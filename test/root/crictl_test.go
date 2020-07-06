// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package root

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/criutil"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Tests for crictl have to be run as root (rather than in a user namespace)
// because crictl creates named network namespaces in /var/run/netns/.

// SimpleSpec returns a JSON config for a simple container that runs the
// specified command in the specified image.
func SimpleSpec(name, image string, cmd []string, extra map[string]interface{}) string {
	s := map[string]interface{}{
		"metadata": map[string]string{
			"name": name,
		},
		"image": map[string]string{
			"image": testutil.ImageByName(image),
		},
		"log_path": fmt.Sprintf("%s.log", name),
		"stdin":    false,
		"tty":      false,
	}
	if len(cmd) > 0 { // Omit if empty.
		s["command"] = cmd
	}
	for k, v := range extra {
		s[k] = v // Extra settings.
	}
	v, err := json.Marshal(s)
	if err != nil {
		// This shouldn't happen.
		panic(err)
	}
	return string(v)
}

// Sandbox is a default JSON config for a sandbox.
var Sandbox = `{
    "metadata": {
        "name": "default-sandbox",
        "namespace": "default",
        "attempt": 1,
        "uid": "hdishd83djaidwnduwk28bcsb"
    },
    "linux": {
    },
    "log_directory": "/tmp"
}
`

// Httpd is a JSON config for an httpd container.
var Httpd = SimpleSpec("httpd", "basic/httpd", nil, nil)

// TestCrictlSanity refers to b/112433158.
func TestCrictlSanity(t *testing.T) {
	for _, version := range allVersions {
		t.Run(version, func(t *testing.T) {
			// Setup containerd and crictl.
			crictl, cleanup, err := setup(t, version)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()
			podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/httpd", Sandbox, Httpd)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			// Look for the httpd page.
			if err = httpGet(crictl, podID, "index.html"); err != nil {
				t.Fatalf("failed to get page: %v", err)
			}

			// Stop everything.
			if err := crictl.StopPodAndContainer(podID, contID); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

// HttpdMountPaths is a JSON config for an httpd container with additional
// mounts.
var HttpdMountPaths = SimpleSpec("httpd", "basic/httpd", nil, map[string]interface{}{
	"mounts": []map[string]interface{}{
		map[string]interface{}{
			"container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/volumes/kubernetes.io~secret/default-token-2rpfx",
			"readonly":       true,
		},
		map[string]interface{}{
			"container_path": "/etc/hosts",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/etc-hosts",
			"readonly":       false,
		},
		map[string]interface{}{
			"container_path": "/dev/termination-log",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064/containers/httpd/d1709580",
			"readonly":       false,
		},
		map[string]interface{}{
			"container_path": "/usr/local/apache2/htdocs/test",
			"host_path":      "/var/lib/kubelet/pods/82bae206-cdf5-11e8-b245-8cdcd43ac064",
			"readonly":       true,
		},
	},
	"linux": map[string]interface{}{},
})

// TestMountPaths refers to b/117635704.
func TestMountPaths(t *testing.T) {
	for _, version := range allVersions {
		t.Run(version, func(t *testing.T) {
			// Setup containerd and crictl.
			crictl, cleanup, err := setup(t, version)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()
			podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/httpd", Sandbox, HttpdMountPaths)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			// Look for the directory available at /test.
			if err = httpGet(crictl, podID, "test"); err != nil {
				t.Fatalf("failed to get page: %v", err)
			}

			// Stop everything.
			if err := crictl.StopPodAndContainer(podID, contID); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

// TestMountPaths refers to b/118728671.
func TestMountOverSymlinks(t *testing.T) {
	for _, version := range allVersions {
		t.Run(version, func(t *testing.T) {
			// Setup containerd and crictl.
			crictl, cleanup, err := setup(t, version)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()

			spec := SimpleSpec("busybox", "basic/resolv", []string{"sleep", "1000"}, nil)
			podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/resolv", Sandbox, spec)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			out, err := crictl.Exec(contID, "readlink", "/etc/resolv.conf")
			if err != nil {
				t.Fatalf("readlink failed: %v, out: %s", err, out)
			}
			if want := "/tmp/resolv.conf"; !strings.Contains(string(out), want) {
				t.Fatalf("/etc/resolv.conf is not pointing to %q: %q", want, string(out))
			}

			etc, err := crictl.Exec(contID, "cat", "/etc/resolv.conf")
			if err != nil {
				t.Fatalf("cat failed: %v, out: %s", err, etc)
			}
			tmp, err := crictl.Exec(contID, "cat", "/tmp/resolv.conf")
			if err != nil {
				t.Fatalf("cat failed: %v, out: %s", err, out)
			}
			if tmp != etc {
				t.Fatalf("file content doesn't match:\n\t/etc/resolv.conf: %s\n\t/tmp/resolv.conf: %s", string(etc), string(tmp))
			}

			// Stop everything.
			if err := crictl.StopPodAndContainer(podID, contID); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

// TestHomeDir tests that the HOME environment variable is set for
// multi-containers.
func TestHomeDir(t *testing.T) {
	for _, version := range allVersions {
		t.Run(version, func(t *testing.T) {
			// Setup containerd and crictl.
			crictl, cleanup, err := setup(t, version)
			if err != nil {
				t.Fatalf("failed to setup crictl: %v", err)
			}
			defer cleanup()
			contSpec := SimpleSpec("root", "basic/busybox", []string{"sleep", "1000"}, nil)
			podID, contID, err := crictl.StartPodAndContainer(containerdRuntime, "basic/busybox", Sandbox, contSpec)
			if err != nil {
				t.Fatalf("start failed: %v", err)
			}

			t.Run("root container", func(t *testing.T) {
				out, err := crictl.Exec(contID, "sh", "-c", "echo $HOME")
				if err != nil {
					t.Fatalf("exec failed: %v, out: %s", err, out)
				}
				if got, want := strings.TrimSpace(string(out)), "/root"; got != want {
					t.Fatalf("Home directory invalid. Got %q, Want : %q", got, want)
				}
			})

			t.Run("sub-container", func(t *testing.T) {
				// Create a sub container in the same pod.
				subContSpec := SimpleSpec("subcontainer", "basic/busybox", []string{"sleep", "1000"}, nil)
				subContID, err := crictl.StartContainer(podID, "basic/busybox", Sandbox, subContSpec)
				if err != nil {
					t.Fatalf("start failed: %v", err)
				}

				out, err := crictl.Exec(subContID, "sh", "-c", "echo $HOME")
				if err != nil {
					t.Fatalf("exec failed: %v, out: %s", err, out)
				}
				if got, want := strings.TrimSpace(string(out)), "/root"; got != want {
					t.Fatalf("Home directory invalid. Got %q, Want: %q", got, want)
				}

				if err := crictl.StopContainer(subContID); err != nil {
					t.Fatalf("stop failed: %v", err)
				}
			})

			// Stop everything.
			if err := crictl.StopPodAndContainer(podID, contID); err != nil {
				t.Fatalf("stop failed: %v", err)
			}
		})
	}
}

const containerdRuntime = "runsc"

// NOTE: The base path name of runtime_root must be equal to "runsc" in order
// for gvisor-containerd-shim to know that runsc is being evoked.
const v1Template = `
disabled_plugins = ["restart"]
[plugins.linux]
  runtime = "%s"
  runtime_root = "%s/root/runsc"
  shim = "%s"
  shim_debug = true
[plugins.cri.containerd.runtimes.` + containerdRuntime + `]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "%s"
`

const v2Template = `
disabled_plugins = ["restart"]
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.` + containerdRuntime + `]
  runtime_type = "io.containerd.` + containerdRuntime + `.v1"
[plugins.cri.containerd.runtimes.` + containerdRuntime + `.options]
  TypeUrl = "io.containerd.` + containerdRuntime + `.v1.options"
`

const (
	// v1 is the containerd API v1.
	v1 string = "v1"

	// v1 is the containerd API v21.
	v2 string = "v2"
)

// allVersions is the set of known versions.
var allVersions = []string{v1, v2}

// setup sets up before a test. Specifically it:
// * Creates directories and a socket for containerd to utilize.
// * Runs containerd and waits for it to reach a "ready" state for testing.
// * Returns a cleanup function that should be called at the end of the test.
func setup(t *testing.T, version string) (*criutil.Crictl, func(), error) {
	var cleanups []func()
	cleanupFunc := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	cleanup := specutils.MakeCleanup(cleanupFunc)
	defer cleanup.Clean()

	// Create temporary containerd root and state directories, and a socket
	// via which crictl and containerd communicate.
	containerdRoot, err := ioutil.TempDir(testutil.TmpDir(), "containerd-root")
	if err != nil {
		t.Fatalf("failed to create containerd root: %v", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(containerdRoot) })
	t.Logf("Using containerd root: %s", containerdRoot)

	containerdState, err := ioutil.TempDir(testutil.TmpDir(), "containerd-state")
	if err != nil {
		t.Fatalf("failed to create containerd state: %v", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(containerdState) })
	t.Logf("Using containerd state: %s", containerdState)

	sockDir, err := ioutil.TempDir(testutil.TmpDir(), "containerd-sock")
	if err != nil {
		t.Fatalf("failed to create containerd socket directory: %v", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(sockDir) })
	sockAddr := path.Join(sockDir, "test.sock")
	t.Logf("Using containerd socket: %s", sockAddr)

	// Extract the containerd version.
	versionCmd := exec.Command(getContainerd(), "-v")
	out, err := versionCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("error extracting containerd version: %v (%s)", err, string(out))
	}
	r := regexp.MustCompile(" v([0-9]+)\\.([0-9]+)\\.([0-9+])")
	vs := r.FindStringSubmatch(string(out))
	if len(vs) != 4 {
		t.Fatalf("error unexpected version string: %s", string(out))
	}
	major, err := strconv.ParseUint(vs[1], 10, 64)
	if err != nil {
		t.Fatalf("error parsing containerd major version: %v (%s)", err, string(out))
	}
	minor, err := strconv.ParseUint(vs[2], 10, 64)
	if err != nil {
		t.Fatalf("error parsing containerd minor version: %v (%s)", err, string(out))
	}
	t.Logf("Using containerd version: %d.%d", major, minor)

	// We rewrite a configuration. This is based on the current docker
	// configuration for the runtime under test.
	runtime, err := dockerutil.RuntimePath()
	if err != nil {
		t.Fatalf("error discovering runtime path: %v", err)
	}
	t.Logf("Using runtime: %v", runtime)

	// Construct a PATH that includes the runtime directory. This is
	// because the shims will be installed there, and containerd may infer
	// the binary name and search the PATH.
	runtimeDir := path.Dir(runtime)
	modifiedPath := os.Getenv("PATH")
	if modifiedPath != "" {
		modifiedPath = ":" + modifiedPath // We prepend below.
	}
	modifiedPath = path.Dir(getContainerd()) + modifiedPath
	modifiedPath = runtimeDir + ":" + modifiedPath
	t.Logf("Using PATH: %v", modifiedPath)

	var (
		config   string
		runpArgs []string
	)
	switch version {
	case v1:
		// This is only supported less than 1.2.
		if major > 1 || (major == 1 && minor >= 2) {
			// XXX t.Skipf("skipping unsupported containerd (want less than 1.2, got %d.%d)", major, minor)
		}

		// The runtime is required within the configuration, followed
		// by a temporary root directory, followed by the shim,
		// followed by the runtime again. Note that we can safely
		// assume that the shim has been installed in the same
		// directory as the runtime (for test installs and for normal
		// installs). Since this is v1, the binary name will be fixed.
		config = fmt.Sprintf(v1Template, runtime, runtimeDir, path.Join(runtimeDir, "gvisor-containerd-shim"), runtime)
	case v2:
		// This is only supported past 1.2.
		if !(major >= 1 && minor >= 2) {
			t.Skipf("skipping incompatible containerd (want at least 1.2, got %d.%d)", major, minor)
		}

		// The runtime is provided via parameter. Note that the v2 shim
		// binary name is always containerd-shim-* so we don't actually
		// care about the docker runtime name.
		config = v2Template
	default:
		t.Fatalf("unknown version: %d", version)
	}
	t.Logf("Using config: %s", config)

	// Generate the configuration for the test.
	configFile, configCleanup, err := testutil.WriteTmpFile("containerd-config", config)
	if err != nil {
		t.Fatalf("failed to write containerd config")
	}
	cleanups = append(cleanups, configCleanup)

	// Start containerd.
	args := []string{
		getContainerd(),
		"--config", configFile,
		"--log-level", "debug",
		"--root", containerdRoot,
		"--state", containerdState,
		"--address", sockAddr,
	}
	t.Logf("Using args: %s", strings.Join(args, " "))
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "PATH="+modifiedPath)
	startupR, startupW := io.Pipe()
	defer startupR.Close()
	defer startupW.Close()
	stderr := &bytes.Buffer{}
	stdout := &bytes.Buffer{}
	cmd.Stderr = io.MultiWriter(startupW, stderr)
	cmd.Stdout = io.MultiWriter(startupW, stdout)
	cleanups = append(cleanups, func() {
		t.Logf("containerd stdout: %s", stdout.String())
		t.Logf("containerd stderr: %s", stderr.String())
	})

	// Start the process.
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed running containerd: %v", err)
	}

	// Wait for containerd to boot.
	if err := testutil.WaitUntilRead(startupR, "Start streaming server", nil, 10*time.Second); err != nil {
		t.Fatalf("failed to start containerd: %v", err)
	}

	// Create the crictl interface.
	cc := criutil.NewCrictl(t, sockAddr, runpArgs)
	cleanups = append(cleanups, cc.CleanUp)

	// Kill must be the last cleanup (as it will be executed first).
	cleanups = append(cleanups, func() {
		if err := testutil.KillCommand(cmd); err != nil {
			log.Printf("error killing containerd: %v", err)
		}
	})

	cleanup.Release()
	return cc, cleanupFunc, nil
}

// httpGet GETs the contents of a file served from a pod on port 80.
func httpGet(crictl *criutil.Crictl, podID, filePath string) error {
	// Get the IP of the httpd server.
	ip, err := crictl.PodIP(podID)
	if err != nil {
		return fmt.Errorf("failed to get IP from pod %q: %v", podID, err)
	}

	// GET the page. We may be waiting for the server to start, so retry
	// with a timeout.
	var resp *http.Response
	cb := func() error {
		r, err := http.Get(fmt.Sprintf("http://%s", path.Join(ip, filePath)))
		resp = r
		return err
	}
	if err := testutil.Poll(cb, 20*time.Second); err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("bad status returned: %d", resp.StatusCode)
	}
	return nil
}

func getContainerd() string {
	// Use the local path if it exists, otherwise, use the system one.
	if _, err := os.Stat("/usr/local/bin/containerd"); err == nil {
		return "/usr/local/bin/containerd"
	}
	return "/usr/bin/containerd"
}
