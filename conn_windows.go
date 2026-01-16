package vsock

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func dial(ctx context.Context, contextID, port uint32, _ *Config) (*Conn, error) {
	fd, err := socket(_AF_VSOCK, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket %w", err)
	}
	addr := &sockaddrVM{
		family: _AF_VSOCK,
		cid:    contextID,
		port:   port,
	}
	err = connect(fd, addr)
	if err != nil {
		syscall.Shutdown(fd, syscall.SHUT_RDWR)
		syscall.Closesocket(fd)
		return nil, fmt.Errorf("connect %w", err)
	}
	localAddr, err := getsockname(fd)
	if err != nil {
		syscall.Shutdown(fd, syscall.SHUT_RDWR)
		syscall.Closesocket(fd)
		return nil, fmt.Errorf("getsockname %w", err)
	}
	ioselect(fd, fd, time.Millisecond)
	setnonblock(fd, true)
	c := &conn{
		fd:  fd,
		ctx: ctx,
	}
	return &Conn{
		c:      c,
		local:  localAddr,
		remote: &Addr{ContextID: contextID, Port: port},
	}, nil
}

type conn struct {
	r             sync.Mutex
	w             sync.Mutex
	ctx           context.Context
	fd            syscall.Handle
	closed        atomic.Bool
	flags         atomic.Uint32
	readDeadline  time.Time
	writeDeadline time.Time
}

func (c *conn) deadlineExceeded(write bool) bool {
	var d time.Time
	if write {
		d = c.writeDeadline
	} else {
		d = c.readDeadline
	}

	return !d.IsZero() && time.Now().After(d)
}

func (c *conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		syscall.Shutdown(c.fd, syscall.SHUT_RDWR)
		syscall.Closesocket(c.fd)
		return nil
	}
	return nil
}

func (c *conn) CloseRead() error {
	syscall.Shutdown(c.fd, syscall.SHUT_RD)
	return nil
}

func (c *conn) CloseWrite() error {
	syscall.Shutdown(c.fd, syscall.SHUT_WR)
	return nil
}

func (c *conn) Read(b []byte) (int, error) {
	c.r.Lock()
	defer c.r.Unlock()

	write := false
	for {
		select {
		case <-c.ctx.Done():
			c.Close()
			return 0, context.DeadlineExceeded
		default:
		}
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if c.deadlineExceeded(write) {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := recv(c.fd, b)
		if n == 0 && err == nil {
			return 0, io.EOF
		}
		if isclosed(err) {
			return 0, net.ErrClosed
		}
		if err == syscall.EAGAIN {
			err := waitSelectOrTimeout(c.fd, 0, func() bool { return c.deadlineExceeded(write) })
			if err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func (c *conn) Write(b []byte) (int, error) {
	c.w.Lock()
	defer c.w.Unlock()

	write := true
	offset := 0
	for {
		select {
		case <-c.ctx.Done():
			c.Close()
			return 0, context.DeadlineExceeded
		default:
		}
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if c.deadlineExceeded(write) {
			return 0, os.ErrDeadlineExceeded
		}
		n, err := send(c.fd, b[offset:])
		if isclosed(err) {
			return 0, net.ErrClosed
		}
		offset += n
		if err == syscall.EAGAIN {
			err := waitSelectOrTimeout(0, c.fd, func() bool { return c.deadlineExceeded(write) })
			if err != nil {
				return 0, err
			}
			continue
		}
		if offset < len(b) && err == nil {
			continue
		}
		return offset, err
	}
}

func isclosed(err error) bool {
	return err == errInvalidHandle || err == errWSAESHUTDOWN
}

type fdSet struct {
	fd_count uint32
	fd_array [64]syscall.Handle
}

func ioselect(rhd, whd syscall.Handle, dur time.Duration) (err error) {
	var rptr, wptr, tptr uintptr
	if rhd > 0 {
		fdset := fdSet{
			fd_count: 1,
			fd_array: [64]syscall.Handle{rhd},
		}
		rptr = uintptr(unsafe.Pointer(&fdset))
	}
	if whd > 0 {
		fdset := fdSet{
			fd_count: 1,
			fd_array: [64]syscall.Handle{whd},
		}
		wptr = uintptr(unsafe.Pointer(&fdset))
	}
	if dur > 0 {
		tv := syscall.NsecToTimeval(dur.Nanoseconds())
		tptr = uintptr(unsafe.Pointer(&tv))
	}

	r1, _, e1 := syscall.SyscallN(procSelect.Addr(), 0, rptr, wptr, 0, tptr)
	if r1 == errSOCKET_ERROR {
		err = errnoErr(e1)
	}
	return
}

func (c *conn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

func (c *conn) SyscallConn() (syscall.RawConn, error) {
	return nil, errUnimplemented
}
