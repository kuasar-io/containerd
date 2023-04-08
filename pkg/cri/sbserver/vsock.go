package sbserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/containerd/pkg/cri/io"
	"github.com/containerd/containerd/pkg/cri/store/sandbox"
	"github.com/containerd/typeurl/v2"
)

type VsockPorts struct {
	Ports []int `json:"ports,omitempty"`
}

func init() {
	typeurl.Register(&VsockPorts{}, "github.com/containerd/cri/pkg", "VsockPorts")
}

// allocateVsockIo allocate vsock port to for io channels,
// TODO we should add a lock here
func (c *criService) allocateVsockIo(ctx context.Context, sb sandbox.Sandbox, vsockType string, stdin bool, tty bool) (*io.VsockSet, error) {
	containerdSandbox, err := c.client.SandboxStore().Get(ctx, sb.ID)
	if err != nil {
		return nil, err
	}
	taskAddress := sb.Status.Get().TaskAddress
	addrPort := strings.TrimPrefix(taskAddress, vsockType+"://")
	address := strings.Split(addrPort, ":")[0]
	var vsockPorts VsockPorts
	if portsAny, ok := containerdSandbox.Extensions["vsock_ports"]; ok {
		if err := typeurl.UnmarshalTo(portsAny, &vsockPorts); err != nil {
			return nil, err
		}
	}
	ports := vsockPorts.Ports
	var stdinPort, stdoutPort, stderrPort int
	if stdin {
		if p := findAvailablePort(ports); p > 0 {
			ports = append(ports, p)
			stdinPort = p
		} else {
			return nil, fmt.Errorf("no available ports for %s io", vsockType)
		}
	}

	if p := findAvailablePort(ports); p > 0 {
		ports = append(ports, p)
		stdoutPort = p
	} else {
		return nil, fmt.Errorf("no available ports for %s io", vsockType)
	}

	if !tty {
		if p := findAvailablePort(ports); p > 0 {
			ports = append(ports, p)
			stderrPort = p
		} else {
			return nil, fmt.Errorf("no available ports for %s io", vsockType)
		}
	}
	newPortsAny, err := typeurl.MarshalAny(&VsockPorts{
		Ports: ports,
	})
	if err != nil {
		return nil, err
	}
	containerdSandbox.Extensions["vsock_ports"] = newPortsAny
	if _, err := c.client.SandboxStore().Update(ctx, containerdSandbox, "extensions"); err != nil {
		return nil, err
	}
	return io.NewVsock(address, vsockType, stdinPort, stdoutPort, stderrPort, tty), nil
}

func findAvailablePort(ports []int) int {
	// find vsock port from 2000

	for i := 2000; i < 65535; i++ {
		var exist bool
		for _, p := range ports {
			if p == i {
				exist = true
			}
		}
		if !exist {
			return i
		}
	}
	return -1
}
