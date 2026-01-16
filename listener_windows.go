package vsock

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

type listener struct {
	fd     syscall.Handle
	addr   *Addr
	closed atomic.Bool
}

func listen(contextID, port uint32, _ *Config) (*Listener, error) {
	fd, err := socket(_AF_VSOCK, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	addr := &sockaddrVM{
		family: uint16(_AF_VSOCK),
		cid:    contextID,
		port:   port,
	}

	err = bind(fd, addr)
	if err != nil {
		syscall.Closesocket(syscall.Handle(fd))
		return nil, err
	}

	err = syscall.Listen(syscall.Handle(fd), 128)
	if err != nil {
		syscall.Closesocket(syscall.Handle(fd))
		return nil, err
	}

	l := &listener{
		fd:   syscall.Handle(fd),
		addr: &Addr{ContextID: contextID, Port: port},
	}
	return &Listener{l: l}, nil
}

func (l *listener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	afd, peer, err := accept(l.fd)
	if err != nil {
		return nil, err
	}
	ioselect(afd, afd, time.Microsecond)
	setnonblock(afd, true)
	c := &conn{
		fd:  afd,
		ctx: context.Background(),
	}
	return &Conn{
		c:      c,
		local:  l.addr,
		remote: &Addr{ContextID: peer.cid, Port: peer.port},
	}, nil
}

func (l *listener) Addr() net.Addr {
	return l.addr
}

func (l *listener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		syscall.Closesocket(l.fd)
		return nil
	}
	return nil
}

// fileListener is the entry point for FileListener on Linux.
func fileListener(_ *os.File) (*Listener, error) { return nil, errUnimplemented }

func (l *listener) SetDeadline(t time.Time) error {
	// ms := uint32(time.Until(t).Milliseconds())
	// log.Println(syscall.Setsockopt(l.fd, syscall.SOL_SOCKET, _SO_RCVTIMEO, (*byte)(unsafe.Pointer(&ms)), int32(unsafe.Sizeof(ms))))
	// log.Println(syscall.Setsockopt(l.fd, syscall.SOL_SOCKET, _SO_SNDTIMEO, (*byte)(unsafe.Pointer(&ms)), int32(unsafe.Sizeof(ms))))
	return nil
}
