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

package io

import (
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/pkg/cri/util"
	cioutil "github.com/containerd/containerd/pkg/ioutil"
	"github.com/sirupsen/logrus"
)

// streamKey generates a key for the stream.
func streamKey(id, name string, stream StreamType) string {
	return strings.Join([]string{id, name, string(stream)}, "-")
}

// ContainerIO holds the container io.
type ContainerIO struct {
	id string

	fifos  *cio.FIFOSet
	vsocks *VsockSet
	*stdios

	stdoutGroup *cioutil.WriterGroup
	stderrGroup *cioutil.WriterGroup

	closer *wgCloser
}

var _ cio.IO = &ContainerIO{}

// ContainerIOOpts sets specific information to newly created ContainerIO.
type ContainerIOOpts func(*ContainerIO) error

// WithFIFOConfig specifies existing io config for the container io.
func WithFIFOConfig(config cio.Config) ContainerIOOpts {
	return func(c *ContainerIO) error {
		fifos := cio.NewFIFOSetByConfig(config)
		return WithFIFOs(fifos)(c)
	}
}

// WithFIFOs specifies existing iosets for the container io.
func WithFIFOs(fifos *cio.FIFOSet) ContainerIOOpts {
	return func(c *ContainerIO) error {
		c.fifos = fifos
		// Create actual fifos.
		stdio, closer, err := newStdioPipes(c.fifos)
		if err != nil {
			return err
		}
		c.stdios = stdio
		c.closer = closer
		return nil
	}
}

// WithNewFIFOs creates new iosets for the container io.
func WithNewFIFOs(root string, tty, stdin bool) ContainerIOOpts {
	return func(c *ContainerIO) error {
		fifos, err := newFifos(root, c.id, tty, stdin)
		if err != nil {
			return err
		}
		return WithFIFOs(fifos)(c)
	}
}

func WithVSocks(vsocks *VsockSet) ContainerIOOpts {
	return func(c *ContainerIO) error {
		c.vsocks = vsocks
		ios, closer, err := newStdioVsock(c.vsocks)
		if err != nil {
			return err
		}
		c.stdios = ios
		c.closer = closer
		return nil
	}
}

func WithVSocksConfig(config cio.Config, sockType string) ContainerIOOpts {
	return func(c *ContainerIO) error {
		vsocks, err := newVsockFromConfig(config, sockType)
		if err != nil {
			return err
		}
		return WithVSocks(vsocks)(c)
	}
}

// WithVSockIo creates new hvsock io for the container io.
func WithVSockIo(vsockIo *VsockSet) ContainerIOOpts {
	return func(c *ContainerIO) error {
		return WithVSocks(vsockIo)(c)
	}
}

func findAvailablePort(ports map[int]struct{}) int {
	// find vsock port from 2000
	for i := 2000; i < 65535; i++ {
		if _, ok := ports[i]; !ok {
			return i
		}
	}
	return -1
}

func convertToPort(std string) int {
	if len(std) > 0 {
		urlParts := strings.Split(std, ":")
		if p, err := strconv.Atoi(urlParts[len(urlParts)-1]); err == nil && p > 0 {
			return p
		}
	}
	return -1
}

// NewContainerIO creates container io.
func NewContainerIO(id string, opts ...ContainerIOOpts) (_ *ContainerIO, err error) {
	c := &ContainerIO{
		id:          id,
		stdoutGroup: cioutil.NewWriterGroup(),
		stderrGroup: cioutil.NewWriterGroup(),
	}
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Config returns io config.
func (c *ContainerIO) Config() cio.Config {
	if c.fifos != nil {
		return c.fifos.Config
	} else {
		return c.vsocks.config()
	}
}

// Pipe creates container iosets and pipe container output
// to output stream.
func (c *ContainerIO) Pipe() error {
	wg := c.closer.wg

	if c.stdout != nil {
		wg.Add(1)
		go func() {
			if _, err := io.Copy(c.stdoutGroup, c.stdout); err != nil {
				logrus.WithError(err).Errorf("Failed to pipe stdout of container %q", c.id)
			}
			c.stdout.Close()
			c.stdoutGroup.Close()
			wg.Done()
			logrus.Debugf("Finish piping stdout of container %q", c.id)
		}()
	}

	if !c.Config().Terminal && c.stderr != nil {
		wg.Add(1)
		go func() {
			if _, err := io.Copy(c.stderrGroup, c.stderr); err != nil {
				logrus.WithError(err).Errorf("Failed to pipe stderr of container %q", c.id)
			}
			c.stderr.Close()
			c.stderrGroup.Close()
			wg.Done()
			logrus.Debugf("Finish piping stderr of container %q", c.id)
		}()
	}
	return nil
}

// Attach attaches container stdio.
// TODO(random-liu): Use pools.Copy in docker to reduce memory usage?
func (c *ContainerIO) Attach(opts AttachOptions) {
	var wg sync.WaitGroup
	key := util.GenerateID()
	stdinKey := streamKey(c.id, "attach-"+key, Stdin)
	stdoutKey := streamKey(c.id, "attach-"+key, Stdout)
	stderrKey := streamKey(c.id, "attach-"+key, Stderr)

	var stdinStreamRC io.ReadCloser
	if c.stdin != nil && opts.Stdin != nil {
		// Create a wrapper of stdin which could be closed. Note that the
		// wrapper doesn't close the actual stdin, it only stops io.Copy.
		// The actual stdin will be closed by stream server.
		stdinStreamRC = cioutil.NewWrapReadCloser(opts.Stdin)
		wg.Add(1)
		go func() {
			if _, err := io.Copy(c.stdin, stdinStreamRC); err != nil {
				logrus.WithError(err).Errorf("Failed to pipe stdin for container attach %q", c.id)
			}
			logrus.Infof("Attach stream %q closed", stdinKey)
			if opts.StdinOnce && !opts.Tty {
				// Due to kubectl requirements and current docker behavior, when (opts.StdinOnce &&
				// opts.Tty) we have to close container stdin and keep stdout and stderr open until
				// container stops.
				c.stdin.Close()
				// Also closes the containerd side.
				if err := opts.CloseStdin(); err != nil {
					logrus.WithError(err).Errorf("Failed to close stdin for container %q", c.id)
				}
			} else {
				if opts.Stdout != nil {
					c.stdoutGroup.Remove(stdoutKey)
				}
				if opts.Stderr != nil {
					c.stderrGroup.Remove(stderrKey)
				}
			}
			wg.Done()
		}()
	}

	attachStream := func(key string, close <-chan struct{}) {
		<-close
		logrus.Infof("Attach stream %q closed", key)
		// Make sure stdin gets closed.
		if stdinStreamRC != nil {
			stdinStreamRC.Close()
		}
		wg.Done()
	}

	if opts.Stdout != nil {
		wg.Add(1)
		wc, close := cioutil.NewWriteCloseInformer(opts.Stdout)
		c.stdoutGroup.Add(stdoutKey, wc)
		go attachStream(stdoutKey, close)
	}
	if !opts.Tty && opts.Stderr != nil {
		wg.Add(1)
		wc, close := cioutil.NewWriteCloseInformer(opts.Stderr)
		c.stderrGroup.Add(stderrKey, wc)
		go attachStream(stderrKey, close)
	}
	wg.Wait()
}

// AddOutput adds new write closers to the container stream, and returns existing
// write closers if there are any.
func (c *ContainerIO) AddOutput(name string, stdout, stderr io.WriteCloser) (io.WriteCloser, io.WriteCloser) {
	var oldStdout, oldStderr io.WriteCloser
	if stdout != nil {
		key := streamKey(c.id, name, Stdout)
		oldStdout = c.stdoutGroup.Get(key)
		c.stdoutGroup.Add(key, stdout)
	}
	if stderr != nil {
		key := streamKey(c.id, name, Stderr)
		oldStderr = c.stderrGroup.Get(key)
		c.stderrGroup.Add(key, stderr)
	}
	return oldStdout, oldStderr
}

// Cancel cancels container io.
func (c *ContainerIO) Cancel() {
	if c.closer != nil {
		c.closer.Cancel()
	}
}

// Wait waits container io to finish.
func (c *ContainerIO) Wait() {
	if c.closer != nil {
		c.closer.Wait()
	}
}

// Close closes all FIFOs.
func (c *ContainerIO) Close() error {
	if c.closer != nil {
		c.closer.Close()
	}
	if c.fifos != nil {
		return c.fifos.Close()
	}
	return nil
}
