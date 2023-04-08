package io

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/runtime/v2/shim"
)

type VsockSet struct {
	sockType   string
	sockAddr   string
	stdinPort  int
	stdoutPort int
	stderrPort int
	Terminal   bool
}

func (h *VsockSet) config() cio.Config {
	return cio.Config{
		Terminal: h.Terminal,
		Stdin:    portToStd(h.sockType, h.sockAddr, h.stdinPort),
		Stdout:   portToStd(h.sockType, h.sockAddr, h.stdoutPort),
		Stderr:   portToStd(h.sockType, h.sockAddr, h.stderrPort),
	}
}

func portToStd(socketType, sockAddr string, port int) string {
	if port <= 0 {
		return ""
	} else {
		return fmt.Sprintf("%s://%s:%d", socketType, sockAddr, port)
	}
}

func NewVsock(sockAddr, sockType string, stdinPort, stdoutPort, stderrPort int, tty bool) *VsockSet {
	return &VsockSet{sockType: sockType, sockAddr: sockAddr, stdinPort: stdinPort, stdoutPort: stdoutPort, stderrPort: stderrPort, Terminal: tty}
}

func newStdioVsock(h *VsockSet) (_ *stdios, _ *wgCloser, err error) {
	var ctx, cancel = context.WithCancel(context.Background())
	var p = &stdios{}
	var closers []io.Closer

	defer func() {
		if err != nil {
			for _, f := range closers {
				f.Close()
			}
			cancel()
		}
	}()
	if h.stdinPort > 0 {
		p.stdin = newVsockIo(h.sockType, h.sockAddr, h.stdinPort)
		closers = append(closers, p.stdin)
	}
	if h.stdoutPort > 0 {
		p.stdout = newVsockIo(h.sockType, h.sockAddr, h.stdoutPort)
		closers = append(closers, p.stdout)
	}
	if h.stderrPort > 0 {
		p.stderr = newVsockIo(h.sockType, h.sockAddr, h.stderrPort)
		closers = append(closers, p.stderr)
	}
	return p, &wgCloser{
		wg:     &sync.WaitGroup{},
		set:    closers,
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func newVsockConn(sockType, addr string, port int) (net.Conn, error) {
	var vsockAddr string
	switch sockType {
	case shim.Vsock, shim.HVsock:
		vsockAddr = fmt.Sprintf("%s://%s:%d", sockType, addr, port)
	default:
		return nil, fmt.Errorf("unknow vsock type %s", sockType)
	}
	conn, err := shim.AnonDialer(vsockAddr, 100*time.Second)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func IsHybridVsockIo(config *cio.Config) bool {
	for _, c := range []string{config.Stdin, config.Stdout, config.Stderr} {
		if strings.HasPrefix(c, shim.HVsock) {
			return true
		}
	}
	return false
}

func IsVsockIo(config *cio.Config) bool {
	for _, c := range []string{config.Stdin, config.Stdout, config.Stderr} {
		if strings.HasPrefix(c, shim.Vsock) {
			return true
		}
	}
	return false
}

func newVsockFromConfig(config cio.Config, sockType string) (*VsockSet, error) {
	res := &VsockSet{
		sockType: sockType,
		Terminal: config.Terminal,
	}
	if config.Stdin != "" {
		addr, port, err := parseUrl(config.Stdin, sockType)
		if err != nil {
			return nil, err
		}
		res.sockAddr = addr
		res.stdinPort = port
	}
	if config.Stdout != "" {
		addr, port, err := parseUrl(config.Stdout, sockType)
		if err != nil {
			return nil, err
		}
		res.sockAddr = addr
		res.stdoutPort = port
	}
	if config.Stderr != "" {
		addr, port, err := parseUrl(config.Stderr, sockType)
		if err != nil {
			return nil, err
		}
		res.sockAddr = addr
		res.stderrPort = port
	}
	return res, nil
}

func parseUrl(url, sockType string) (string, int, error) {
	addrPortStr := strings.TrimPrefix(url, sockType+"://")
	addrPort := strings.Split(addrPortStr, ":")
	if len(addrPort) != 2 {
		return "", 0, fmt.Errorf("the vsock url %s format error", url)
	}
	addr := addrPort[0]
	port, err := strconv.Atoi(addrPort[1])
	if err != nil {
		return "", 0, fmt.Errorf("the vsock url %s format error", url)
	}
	return addr, port, nil
}

type VsockIo struct {
	sockType string
	sockAddr string
	port     int
	conn     net.Conn
	conErr   error
	once     sync.Once
}

func newVsockIo(sockType, addr string, port int) *VsockIo {
	return &VsockIo{
		sockType: sockType,
		sockAddr: addr,
		port:     port,
	}
}

func (h *VsockIo) init() {
	h.once.Do(func() {
		if h.conn == nil {
			if conn, err := newVsockConn(h.sockType, h.sockAddr, h.port); err == nil {
				h.conn = conn
			} else {
				h.conErr = err
			}
		}
	})
}

func (h *VsockIo) Write(p []byte) (n int, err error) {
	h.init()
	if h.conn == nil {
		return 0, h.conErr
	}
	return h.conn.Write(p)
}

func (h *VsockIo) Read(p []byte) (n int, err error) {
	h.init()
	if h.conn == nil {
		return 0, h.conErr
	}
	return h.conn.Read(p)
}

func (h *VsockIo) Close() error {
	if h.conn != nil {
		return h.conn.Close()
	}
	return nil
}
