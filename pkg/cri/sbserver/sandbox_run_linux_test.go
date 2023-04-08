package sbserver

import (
	"os"
	"path/filepath"
	"testing"

	ostesting "github.com/containerd/containerd/pkg/os/testing"
	"github.com/stretchr/testify/assert"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestSetupSandboxFiles(t *testing.T) {
	const (
		testID       = "test-id"
		realhostname = "test-real-hostname"
	)
	for desc, test := range map[string]struct {
		dnsConfig     *runtime.DNSConfig
		hostname      string
		ipcMode       runtime.NamespaceMode
		expectedCalls []ostesting.CalledDetail
	}{
		"should check host /dev/shm existence when ipc mode is NODE": {
			ipcMode: runtime.NamespaceMode_NODE,
			expectedCalls: []ostesting.CalledDetail{
				{
					Name: "Hostname",
				},
				{
					Name: "WriteFile",
					Arguments: []interface{}{
						filepath.Join(testRootDir, sandboxesDir, testID, "hostname"),
						[]byte(realhostname + "\n"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/hosts",
						filepath.Join(testRootDir, sandboxesDir, testID, "hosts"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/resolv.conf",
						filepath.Join(testRootDir, sandboxesDir, testID, "resolv.conf"),
						os.FileMode(0644),
					},
				},
				{
					Name:      "Stat",
					Arguments: []interface{}{"/dev/shm"},
				},
			},
		},
		"should create new /etc/resolv.conf if DNSOptions is set": {
			dnsConfig: &runtime.DNSConfig{
				Servers:  []string{"8.8.8.8"},
				Searches: []string{"114.114.114.114"},
				Options:  []string{"timeout:1"},
			},
			ipcMode: runtime.NamespaceMode_NODE,
			expectedCalls: []ostesting.CalledDetail{
				{
					Name: "Hostname",
				},
				{
					Name: "WriteFile",
					Arguments: []interface{}{
						filepath.Join(testRootDir, sandboxesDir, testID, "hostname"),
						[]byte(realhostname + "\n"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/hosts",
						filepath.Join(testRootDir, sandboxesDir, testID, "hosts"),
						os.FileMode(0644),
					},
				},
				{
					Name: "WriteFile",
					Arguments: []interface{}{
						filepath.Join(testRootDir, sandboxesDir, testID, "resolv.conf"),
						[]byte(`search 114.114.114.114
nameserver 8.8.8.8
options timeout:1
`), os.FileMode(0644),
					},
				},
				{
					Name:      "Stat",
					Arguments: []interface{}{"/dev/shm"},
				},
			},
		},
		"should create sandbox shm when ipc namespace mode is not NODE": {
			ipcMode: runtime.NamespaceMode_POD,
			expectedCalls: []ostesting.CalledDetail{
				{
					Name: "Hostname",
				},
				{
					Name: "WriteFile",
					Arguments: []interface{}{
						filepath.Join(testRootDir, sandboxesDir, testID, "hostname"),
						[]byte(realhostname + "\n"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/hosts",
						filepath.Join(testRootDir, sandboxesDir, testID, "hosts"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/resolv.conf",
						filepath.Join(testRootDir, sandboxesDir, testID, "resolv.conf"),
						os.FileMode(0644),
					},
				},
				{
					Name: "MkdirAll",
					Arguments: []interface{}{
						filepath.Join(testStateDir, sandboxesDir, testID, "shm"),
						os.FileMode(0700),
					},
				},
				{
					Name: "Mount",
					// Ignore arguments which are too complex to check.
				},
			},
		},
		"should create /etc/hostname when hostname is set": {
			hostname: "test-hostname",
			ipcMode:  runtime.NamespaceMode_NODE,
			expectedCalls: []ostesting.CalledDetail{
				{
					Name: "WriteFile",
					Arguments: []interface{}{
						filepath.Join(testRootDir, sandboxesDir, testID, "hostname"),
						[]byte("test-hostname\n"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/hosts",
						filepath.Join(testRootDir, sandboxesDir, testID, "hosts"),
						os.FileMode(0644),
					},
				},
				{
					Name: "CopyFile",
					Arguments: []interface{}{
						"/etc/resolv.conf",
						filepath.Join(testRootDir, sandboxesDir, testID, "resolv.conf"),
						os.FileMode(0644),
					},
				},
				{
					Name:      "Stat",
					Arguments: []interface{}{"/dev/shm"},
				},
			},
		},
	} {
		t.Run(desc, func(t *testing.T) {
			c := newTestCRIService()
			c.os.(*ostesting.FakeOS).HostnameFn = func() (string, error) {
				return realhostname, nil
			}
			cfg := &runtime.PodSandboxConfig{
				Hostname:  test.hostname,
				DnsConfig: test.dnsConfig,
				Linux: &runtime.LinuxPodSandboxConfig{
					SecurityContext: &runtime.LinuxSandboxSecurityContext{
						NamespaceOptions: &runtime.NamespaceOption{
							Ipc: test.ipcMode,
						},
					},
				},
			}
			c.setupSandboxFiles(testID, cfg)
			calls := c.os.(*ostesting.FakeOS).GetCalls()
			assert.Len(t, calls, len(test.expectedCalls))
			for i, expected := range test.expectedCalls {
				if expected.Arguments == nil {
					// Ignore arguments.
					expected.Arguments = calls[i].Arguments
				}
				assert.Equal(t, expected, calls[i])
			}
		})
	}
}

func TestParseDNSOption(t *testing.T) {
	for desc, test := range map[string]struct {
		servers         []string
		searches        []string
		options         []string
		expectedContent string
		expectErr       bool
	}{
		"empty dns options should return empty content": {},
		"non-empty dns options should return correct content": {
			servers:  []string{"8.8.8.8", "server.google.com"},
			searches: []string{"114.114.114.114"},
			options:  []string{"timeout:1"},
			expectedContent: `search 114.114.114.114
nameserver 8.8.8.8
nameserver server.google.com
options timeout:1
`,
		},
		"expanded dns config should return correct content on modern libc (e.g. glibc 2.26 and above)": {
			servers: []string{"8.8.8.8", "server.google.com"},
			searches: []string{
				"server0.google.com",
				"server1.google.com",
				"server2.google.com",
				"server3.google.com",
				"server4.google.com",
				"server5.google.com",
				"server6.google.com",
			},
			options: []string{"timeout:1"},
			expectedContent: `search server0.google.com server1.google.com server2.google.com server3.google.com server4.google.com server5.google.com server6.google.com
nameserver 8.8.8.8
nameserver server.google.com
options timeout:1
`,
		},
	} {
		t.Run(desc, func(t *testing.T) {
			resolvContent, err := parseDNSOptions(test.servers, test.searches, test.options)
			if test.expectErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, resolvContent, test.expectedContent)
		})
	}
}
