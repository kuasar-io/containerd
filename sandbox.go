/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package containerd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/protobuf/types"
	api "github.com/containerd/containerd/sandbox"
	"github.com/containerd/typeurl/v2"
)

// Sandbox is a high level client to containerd's sandboxes.
type Sandbox interface {
	// ID is a sandbox identifier
	ID() string
	// PID returns sandbox's process PID or error if its not yet started.
	PID(ctx context.Context) (uint32, error)
	// Info returns sandbox metadata
	Info() api.Sandbox
	// Labels returns the labels set on the sandbox
	Labels(ctx context.Context) (map[string]string, error)
	// Start starts new sandbox instance
	Start(ctx context.Context) error
	// Stop sends stop request to the shim instance.
	Stop(ctx context.Context) error
	// Prepare will let the sandbox to prepare the container resources
	// and returns the bundle for the container
	Prepare(ctx context.Context, opts ...api.PrepareOpt) (api.PrepareResult, error)
	// Purge will purge the resources related to the container or exec process in the sandbox.
	Purge(ctx context.Context, containerID string, execID string) error
	// UpdateResources updates the resources that the sandbox is managing
	UpdateResources(ctx context.Context, opts ...api.UpdateResourceOpt) error
	// Status get the sandbox status
	Status(ctx context.Context, verbose bool) (api.ControllerStatus, error)
	// Wait blocks until sandbox process exits.
	Wait(ctx context.Context) (<-chan ExitStatus, error)
	// Shutdown removes sandbox from the metadata store and shutdowns shim instance.
	Shutdown(ctx context.Context) error
}

type sandboxInstance struct {
	client   *Client
	metadata api.Sandbox
}

func sandboxFromRecord(client *Client, s api.Sandbox) *sandboxInstance {
	return &sandboxInstance{
		client:   client,
		metadata: s,
	}
}

func (s *sandboxInstance) ID() string {
	return s.metadata.ID
}

func (s *sandboxInstance) PID(ctx context.Context) (uint32, error) {
	resp, err := s.client.SandboxController(s.metadata.Sandboxer).Status(ctx, s.ID(), false)
	if err != nil {
		return 0, err
	}
	if resp.State != api.StateReady {
		return 0, fmt.Errorf("sandbox not started")
	}
	return resp.Pid, nil
}

func (s *sandboxInstance) Info() api.Sandbox {
	return s.metadata
}

func (s *sandboxInstance) Labels(ctx context.Context) (map[string]string, error) {
	sandbox, err := s.client.SandboxStore().Get(ctx, s.ID())
	if err != nil {
		return nil, err
	}

	return sandbox.Labels, nil
}

func (s *sandboxInstance) Start(ctx context.Context) error {
	_, err := s.client.SandboxController(s.metadata.Sandboxer).Start(ctx, s.ID())
	if err != nil {
		return err
	}

	return nil
}

func (s *sandboxInstance) Wait(ctx context.Context) (<-chan ExitStatus, error) {
	c := make(chan ExitStatus, 1)
	go func() {
		defer close(c)

		exitStatus, err := s.client.SandboxController(s.metadata.Sandboxer).Wait(ctx, s.ID())
		if err != nil {
			c <- ExitStatus{
				code: UnknownExitStatus,
				err:  err,
			}
			return
		}

		c <- ExitStatus{
			code:     exitStatus.ExitStatus,
			exitedAt: exitStatus.ExitedAt,
		}
	}()

	return c, nil
}

func (s *sandboxInstance) Stop(ctx context.Context) error {
	return s.client.SandboxController(s.metadata.Sandboxer).Stop(ctx, s.ID())
}

func (s *sandboxInstance) Status(ctx context.Context, verbose bool) (api.ControllerStatus, error) {
	return s.client.SandboxController(s.metadata.Sandboxer).Status(ctx, s.ID(), verbose)
}

func (s *sandboxInstance) Shutdown(ctx context.Context) error {
	if err := s.client.SandboxController(s.metadata.Sandboxer).Shutdown(ctx, s.ID()); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("failed to shutdown sandbox: %w", err)
	}

	if err := s.client.SandboxStore().Delete(ctx, s.ID()); err != nil {
		return fmt.Errorf("failed to delete sandbox from store: %w", err)
	}

	return nil
}

func (s *sandboxInstance) Prepare(ctx context.Context, opts ...api.PrepareOpt) (api.PrepareResult, error) {
	return s.client.SandboxController(s.metadata.Sandboxer).Prepare(ctx, s.ID(), opts...)
}

func (s *sandboxInstance) Purge(ctx context.Context, containerID string, execID string) error {
	return s.client.SandboxController(s.metadata.Sandboxer).Purge(ctx, s.ID(), containerID, execID)
}

func (s *sandboxInstance) UpdateResources(ctx context.Context, opts ...api.UpdateResourceOpt) error {
	return s.client.SandboxController(s.metadata.Sandboxer).UpdateResources(ctx, s.ID(), opts...)
}

// NewSandbox creates new sandbox client
func (c *Client) NewSandbox(ctx context.Context, sandboxID string, opts ...NewSandboxOpts) (Sandbox, error) {
	if sandboxID == "" {
		return nil, errors.New("sandbox ID must be specified")
	}

	newSandbox := api.Sandbox{
		ID:        sandboxID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	for _, opt := range opts {
		if err := opt(ctx, c, &newSandbox); err != nil {
			return nil, err
		}
	}

	metadata, err := c.SandboxStore().Create(ctx, newSandbox)
	if err != nil {
		return nil, err
	}

	return &sandboxInstance{
		client:   c,
		metadata: metadata,
	}, nil
}

// LoadSandbox laods existing sandbox metadata object using the id
func (c *Client) LoadSandbox(ctx context.Context, id string) (Sandbox, error) {
	sandbox, err := c.SandboxStore().Get(ctx, id)
	if err != nil {
		return nil, err
	}

	return &sandboxInstance{
		client:   c,
		metadata: sandbox,
	}, nil
}

// NewSandboxOpts is a sandbox options and extensions to be provided by client
type NewSandboxOpts func(ctx context.Context, client *Client, sandbox *api.Sandbox) error

// WithSandboxRuntime allows a user to specify the runtime to be used to run a sandbox
func WithSandboxRuntime(name string, options interface{}) NewSandboxOpts {
	return func(ctx context.Context, client *Client, s *api.Sandbox) error {
		if options == nil {
			options = &types.Empty{}
		}

		opts, err := typeurl.MarshalAny(options)
		if err != nil {
			return fmt.Errorf("failed to marshal sandbox runtime options: %w", err)
		}

		s.Runtime = api.RuntimeOpts{
			Name:    name,
			Options: opts,
		}

		return nil
	}
}

// WithSandboxSpec will provide the sandbox runtime spec
func WithSandboxSpec(s *oci.Spec, opts ...oci.SpecOpts) NewSandboxOpts {
	return func(ctx context.Context, client *Client, sandbox *api.Sandbox) error {
		c := &containers.Container{ID: sandbox.ID}

		if err := oci.ApplyOpts(ctx, client, c, s, opts...); err != nil {
			return err
		}

		spec, err := typeurl.MarshalAny(s)
		if err != nil {
			return fmt.Errorf("failed to marshal spec: %w", err)
		}

		sandbox.Spec = spec
		return nil
	}
}

// WithSandboxExtension attaches an extension to sandbox
func WithSandboxExtension(name string, ext interface{}) NewSandboxOpts {
	return func(ctx context.Context, client *Client, s *api.Sandbox) error {
		if s.Extensions == nil {
			s.Extensions = make(map[string]typeurl.Any)
		}

		any, err := typeurl.MarshalAny(ext)
		if err != nil {
			return fmt.Errorf("failed to marshal sandbox extension: %w", err)
		}

		s.Extensions[name] = any
		return err
	}
}

// WithSandboxLabels attaches map of labels to sandbox
func WithSandboxLabels(labels map[string]string) NewSandboxOpts {
	return func(ctx context.Context, client *Client, sandbox *api.Sandbox) error {
		sandbox.Labels = labels
		return nil
	}
}
