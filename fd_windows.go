//go:build windows
// +build windows

package vsock

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	_AF_VSOCK         = 0x28
	_viosock_name     = "\\\\.\\Viosock"
	_SO_RCVTIMEO      = 0x1006
	_SO_SNDTIMEO      = 0x1005
	_FIONBIO          = 0x8004667E
	errSOCKET_ERROR   = uintptr(^uint32(0))
	_IOCTL_GET_CONFIG = 0x08013004
	_IOCTL_GET_AF     = 0x0801300C
	_timeout          = time.Millisecond * 1000
)

var (
	errTimeout    error = syscall.Errno(0x274c)
	errWouldBlock error = syscall.Errno(0x2733)
	errInProgress error = syscall.Errno(0x2734)

	errInvalidHandle  error = syscall.Errno(0xc008)
	errWSAESHUTDOWN   error = syscall.Errno(0x274a)
	errBufferTooSmall error = syscall.Errno(0xC0000023)
)

var (
	ws2_32          = windows.MustLoadDLL("ws2_32.dll")
	procSocket      = ws2_32.MustFindProc("socket")
	procBind        = ws2_32.MustFindProc("bind")
	procAccept      = ws2_32.MustFindProc("accept")
	procConnect     = ws2_32.MustFindProc("connect")
	procSend        = ws2_32.MustFindProc("send")
	procRecv        = ws2_32.MustFindProc("recv")
	procSelect      = ws2_32.MustFindProc("select")
	procGetsockname = ws2_32.MustFindProc("getsockname")
	procGetpeername = ws2_32.MustFindProc("getpeername")
)

type sockaddrVM struct {
	family uint16
	pad    uint16
	port   uint32
	cid    uint32
}

// Base Winsock2 i/o doesn't support canceling blocking i/o,
// so we have enable non-blocking mode, poll the socket,
// and manage the deadline ourselves.
func waitSelectOrTimeout(rfd, wfd syscall.Handle, deadlineFunc func() bool) error {
	for {
		err := ioselect(rfd, wfd, _timeout)
		if deadlineFunc() {
			return os.ErrDeadlineExceeded
		}

		if err != errTimeout {
			return nil
		}
	}
}

func accept(fd syscall.Handle) (handle syscall.Handle, psa sockaddrVM, err error) {
	salen := unsafe.Sizeof(psa)
	r0, _, e1 := syscall.SyscallN(procAccept.Addr(), uintptr(fd), uintptr(unsafe.Pointer(&psa)), uintptr(unsafe.Pointer(&salen)))
	handle = syscall.Handle(r0)
	if handle == syscall.InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return syscall.EINVAL
	case syscall.EWOULDBLOCK, errWouldBlock, errBufferTooSmall, errInProgress:
		return syscall.EAGAIN
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

func socket(af int32, typ int32, protocol int32) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procSocket.Addr(), uintptr(af), uintptr(typ), uintptr(protocol))
	handle = syscall.Handle(r0)
	if handle == syscall.InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

func bind(fd syscall.Handle, sa *sockaddrVM) (err error) {
	r1, _, e1 := syscall.SyscallN(procBind.Addr(), uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
	}
	return
}

func connect(fd syscall.Handle, sa *sockaddrVM) (err error) {
	r1, _, e1 := syscall.SyscallN(procConnect.Addr(), uintptr(fd), uintptr(unsafe.Pointer(sa)), unsafe.Sizeof(*sa))
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
	}
	return
}

func setnonblock(fd syscall.Handle, nonblocking bool) (err error) {
	ret := uint32(0)
	flag := uint32(1)
	if !nonblocking {
		flag = 0
	}
	size := uint32(unsafe.Sizeof(flag))
	err = syscall.WSAIoctl(fd, _FIONBIO, (*byte)(unsafe.Pointer(&flag)), size, nil, 0, &ret, nil, 0)
	if err != nil {
		return err
	}
	return nil
}

func getsockname(fd syscall.Handle) (addr *Addr, err error) {
	sa := &sockaddrVM{}
	saln := unsafe.Sizeof(*sa)
	r1, _, e1 := syscall.SyscallN(procGetsockname.Addr(), uintptr(fd), uintptr(unsafe.Pointer(sa)), uintptr(unsafe.Pointer(&saln)))
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
	}
	addr = &Addr{ContextID: sa.cid, Port: sa.port}
	return
}

func getpeername(fd syscall.Handle) (addr *Addr, err error) {
	sa := &sockaddrVM{}
	saln := unsafe.Sizeof(*sa)
	r1, _, e1 := syscall.SyscallN(procGetpeername.Addr(), uintptr(fd), uintptr(unsafe.Pointer(sa)), uintptr(unsafe.Pointer(&saln)))
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
	}
	addr = &Addr{ContextID: sa.cid, Port: sa.port}
	return
}

func recv(fd syscall.Handle, b []byte) (ln int, err error) {
	r1, _, e1 := syscall.SyscallN(procRecv.Addr(), uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
		r1 = 0
	}
	ln = int(r1)
	return
}

func send(fd syscall.Handle, b []byte) (ln int, err error) {
	if len(b) == 0 {
		return 0, nil
	}
	r1, _, e1 := syscall.SyscallN(procSend.Addr(), uintptr(fd), uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
		r1 = 0
	}
	ln = int(r1)
	return
}

func isErrno(err error, errno int) bool {
	if err == nil {
		return false
	}
	if eno, ok := err.(syscall.Errno); ok {
		return int(eno) == errno
	}
	return false
}

func contextID() (uint32, error) {
	deviceName, err := syscall.UTF16PtrFromString(_viosock_name)
	if err != nil {
		return 0, err
	}
	hdev, err := syscall.CreateFile(
		deviceName,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to open Viosock device: %v", err)
	}
	defer syscall.CloseHandle(hdev)
	config := struct {
		GuestCID uint32
	}{}
	var bytesReturned uint32
	err = syscall.DeviceIoControl(
		hdev,
		_IOCTL_GET_CONFIG,
		nil,
		0,
		(*byte)(unsafe.Pointer(&config)),
		uint32(unsafe.Sizeof(config)),
		&bytesReturned,
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("get config failed: %v", err)
	}
	return config.GuestCID, nil
}
