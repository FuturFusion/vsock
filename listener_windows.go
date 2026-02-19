package vsock

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type listener struct {
	sync.Mutex
	fd     syscall.Handle
	addr   *Addr
	closed atomic.Bool
	conns  map[int]*conn

	connCount int
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
		fd:    syscall.Handle(fd),
		addr:  &Addr{ContextID: contextID, Port: port},
		conns: map[int]*conn{},
	}
	return &Listener{l: l}, nil
}

func (l *listener) accept(ctx context.Context) (*conn, *sockaddrVM, error) {
	afd, peer, err := accept(l.fd)
	if err != nil {
		return nil, nil, err
	}

	err = setnonblock(afd, true)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to set non-blocking: %w", err)
	}

	l.Lock()
	defer l.Unlock()

	// use a growing ID for each additional connection.
	l.connCount += 1
	c := &conn{
		id:       l.connCount,
		fd:       afd,
		ctx:      ctx,
		listener: l,
	}

	l.conns[c.id] = c

	return c, &peer, nil
}

func (l *listener) deleteConn(id int) {
	l.Lock()
	defer l.Unlock()

	_, ok := l.conns[id]
	if ok {
		delete(l.conns, id)
	}
}

func (l *listener) Accept() (net.Conn, error) {
	if l.closed.Load() {
		return nil, net.ErrClosed
	}
	c, peer, err := l.accept(context.Background())
	if err != nil {
		return nil, err
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
	l.Lock()
	defer l.Unlock()
	if l.closed.CompareAndSwap(false, true) {
		syscall.Closesocket(l.fd)
		for _, c := range l.conns {
			delete(l.conns, c.id)
		}
		return nil
	}
	return nil
}

func fileListener(_ *os.File) (*Listener, error) { return nil, errUnimplemented }

func (l *listener) SetDeadline(t time.Time) error {
	l.Lock()
	defer l.Unlock()
	for _, c := range l.conns {
		c.SetDeadline(t)
	}
	return nil
}
