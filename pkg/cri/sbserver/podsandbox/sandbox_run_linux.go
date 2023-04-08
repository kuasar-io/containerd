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

package podsandbox

import (
	"fmt"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/plugin"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/selinux/go-selinux"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	"strconv"

	"github.com/containerd/containerd/pkg/cri/annotations"
	customopts "github.com/containerd/containerd/pkg/cri/opts"
	"github.com/containerd/containerd/pkg/userns"
)

func (c *Controller) sandboxContainerSpec(id string, config *runtime.PodSandboxConfig,
	imageConfig *imagespec.ImageConfig, nsPath string, runtimePodAnnotations []string) (_ *runtimespec.Spec, retErr error) {
	// Creates a spec Generator with the default spec.
	// TODO(random-liu): [P1] Compare the default settings with docker and containerd default.
	specOpts := []oci.SpecOpts{
		oci.WithoutRunMount,
		customopts.WithoutDefaultSecuritySettings,
		customopts.WithRelativeRoot(relativeRootfsPath),
		oci.WithEnv(imageConfig.Env),
		oci.WithRootFSReadonly(),
		oci.WithHostname(config.GetHostname()),
	}
	if imageConfig.WorkingDir != "" {
		specOpts = append(specOpts, oci.WithProcessCwd(imageConfig.WorkingDir))
	}

	if len(imageConfig.Entrypoint) == 0 && len(imageConfig.Cmd) == 0 {
		// Pause image must have entrypoint or cmd.
		return nil, fmt.Errorf("invalid empty entrypoint and cmd in image config %+v", imageConfig)
	}
	specOpts = append(specOpts, oci.WithProcessArgs(append(imageConfig.Entrypoint, imageConfig.Cmd...)...))

	// Set cgroups parent.
	if c.config.DisableCgroup {
		specOpts = append(specOpts, customopts.WithDisabledCgroups)
	} else {
		if config.GetLinux().GetCgroupParent() != "" {
			cgroupsPath := getCgroupsPath(config.GetLinux().GetCgroupParent(), id)
			specOpts = append(specOpts, oci.WithCgroup(cgroupsPath))
		}
	}

	// When cgroup parent is not set, containerd-shim will create container in a child cgroup
	// of the cgroup itself is in.
	// TODO(random-liu): [P2] Set default cgroup path if cgroup parent is not specified.

	// Set namespace options.
	var (
		securityContext = config.GetLinux().GetSecurityContext()
		nsOptions       = securityContext.GetNamespaceOptions()
	)
	if nsOptions.GetNetwork() == runtime.NamespaceMode_NODE {
		specOpts = append(specOpts, customopts.WithoutNamespace(runtimespec.NetworkNamespace))
		specOpts = append(specOpts, customopts.WithoutNamespace(runtimespec.UTSNamespace))
	} else {
		specOpts = append(specOpts, oci.WithLinuxNamespace(
			runtimespec.LinuxNamespace{
				Type: runtimespec.NetworkNamespace,
				Path: nsPath,
			}))
	}
	if nsOptions.GetPid() == runtime.NamespaceMode_NODE {
		specOpts = append(specOpts, customopts.WithoutNamespace(runtimespec.PIDNamespace))
	}
	if nsOptions.GetIpc() == runtime.NamespaceMode_NODE {
		specOpts = append(specOpts, customopts.WithoutNamespace(runtimespec.IPCNamespace))
	}

	// It's fine to generate the spec before the sandbox /dev/shm
	// is actually created.
	sandboxDevShm := c.getSandboxDevShm(id)
	if nsOptions.GetIpc() == runtime.NamespaceMode_NODE {
		sandboxDevShm = devShm
	}
	// Remove the default /dev/shm mount from defaultMounts, it is added in oci/mounts.go.
	specOpts = append(specOpts, oci.WithoutMounts(devShm))
	// In future the when user-namespace is enabled, the `nosuid, nodev, noexec` flags are
	// required, otherwise the remount will fail with EPERM. Just use them unconditionally,
	// they are nice to have anyways.
	specOpts = append(specOpts, oci.WithMounts([]runtimespec.Mount{
		{
			Source:      sandboxDevShm,
			Destination: devShm,
			Type:        "bind",
			Options:     []string{"rbind", "ro", "nosuid", "nodev", "noexec"},
		},
		// Add resolv.conf for katacontainers to setup the DNS of pod VM properly.
		{
			Source:      c.getResolvPath(id),
			Destination: resolvConfPath,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		},
	}))

	processLabel, mountLabel, err := initLabelsFromOpt(securityContext.GetSelinuxOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to init selinux options %+v: %w", securityContext.GetSelinuxOptions(), err)
	}
	defer func() {
		if retErr != nil {
			selinux.ReleaseLabel(processLabel)
		}
	}()

	supplementalGroups := securityContext.GetSupplementalGroups()
	specOpts = append(specOpts,
		customopts.WithSelinuxLabels(processLabel, mountLabel),
		customopts.WithSupplementalGroups(supplementalGroups),
	)

	// Add sysctls
	sysctls := config.GetLinux().GetSysctls()
	if sysctls == nil {
		sysctls = make(map[string]string)
	}
	_, ipUnprivilegedPortStart := sysctls["net.ipv4.ip_unprivileged_port_start"]
	_, pingGroupRange := sysctls["net.ipv4.ping_group_range"]
	if nsOptions.GetNetwork() != runtime.NamespaceMode_NODE {
		if c.config.EnableUnprivilegedPorts && !ipUnprivilegedPortStart {
			sysctls["net.ipv4.ip_unprivileged_port_start"] = "0"
		}
		if c.config.EnableUnprivilegedICMP && !pingGroupRange && !userns.RunningInUserNS() {
			sysctls["net.ipv4.ping_group_range"] = "0 2147483647"
		}
	}
	specOpts = append(specOpts, customopts.WithSysctls(sysctls))

	// Note: LinuxSandboxSecurityContext does not currently provide an apparmor profile

	if !c.config.DisableCgroup {
		specOpts = append(specOpts, customopts.WithDefaultSandboxShares)
	}

	if res := config.GetLinux().GetResources(); res != nil {
		specOpts = append(specOpts,
			customopts.WithAnnotation(annotations.SandboxCPUPeriod, strconv.FormatInt(res.CpuPeriod, 10)),
			customopts.WithAnnotation(annotations.SandboxCPUQuota, strconv.FormatInt(res.CpuQuota, 10)),
			customopts.WithAnnotation(annotations.SandboxCPUShares, strconv.FormatInt(res.CpuShares, 10)),
			customopts.WithAnnotation(annotations.SandboxMem, strconv.FormatInt(res.MemoryLimitInBytes, 10)))
	}

	specOpts = append(specOpts, customopts.WithPodOOMScoreAdj(int(defaultSandboxOOMAdj), c.config.RestrictOOMScoreAdj))

	for pKey, pValue := range getPassthroughAnnotations(config.Annotations,
		runtimePodAnnotations) {
		specOpts = append(specOpts, customopts.WithAnnotation(pKey, pValue))
	}

	specOpts = append(specOpts, annotations.DefaultCRIAnnotations(id, "", "", config, true)...)

	return c.runtimeSpec(id, "", specOpts...)
}

// sandboxContainerSpecOpts generates OCI spec options for
// the sandbox container.
func (c *Controller) sandboxContainerSpecOpts(config *runtime.PodSandboxConfig, imageConfig *imagespec.ImageConfig) ([]oci.SpecOpts, error) {
	var (
		securityContext = config.GetLinux().GetSecurityContext()
		specOpts        []oci.SpecOpts
		err             error
	)
	ssp := securityContext.GetSeccomp()
	if ssp == nil {
		ssp, err = generateSeccompSecurityProfile(
			securityContext.GetSeccompProfilePath(), //nolint:staticcheck // Deprecated but we don't want to remove yet
			c.config.UnsetSeccompProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to generate seccomp spec opts: %w", err)
		}
	}
	seccompSpecOpts, err := c.generateSeccompSpecOpts(
		ssp,
		securityContext.GetPrivileged(),
		c.seccompEnabled())
	if err != nil {
		return nil, fmt.Errorf("failed to generate seccomp spec opts: %w", err)
	}
	if seccompSpecOpts != nil {
		specOpts = append(specOpts, seccompSpecOpts)
	}

	userstr, err := generateUserString(
		"",
		securityContext.GetRunAsUser(),
		securityContext.GetRunAsGroup(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user string: %w", err)
	}
	if userstr == "" {
		// Lastly, since no user override was passed via CRI try to set via OCI
		// Image
		userstr = imageConfig.User
	}
	if userstr != "" {
		specOpts = append(specOpts, oci.WithUser(userstr))
	}
	return specOpts, nil
}

// taskOpts generates task options for a (sandbox) container.
func (c *Controller) taskOpts(runtimeType string) []containerd.NewTaskOpts {
	// TODO(random-liu): Remove this after shim v1 is deprecated.
	var taskOpts []containerd.NewTaskOpts

	// c.config.NoPivot is only supported for RuntimeLinuxV1 = "io.containerd.runtime.v1.linux" legacy linux runtime
	// and is not supported for RuntimeRuncV1 = "io.containerd.runc.v1" or  RuntimeRuncV2 = "io.containerd.runc.v2"
	// for RuncV1/2 no pivot is set under the containerd.runtimes.runc.options config see
	// https://github.com/containerd/containerd/blob/v1.3.2/runtime/v2/runc/options/oci.pb.go#L26
	if c.config.NoPivot && runtimeType == plugin.RuntimeLinuxV1 {
		taskOpts = append(taskOpts, containerd.WithNoPivotRoot)
	}

	return taskOpts
}
