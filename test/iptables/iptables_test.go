// Copyright 2019 The gVisor Authors.
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

package iptables

import (
	"context"
	"net"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// singleTest runs a TestCase. Each test follows a pattern:
// - Create a container.
// - Get the container's IP.
// - Send the container our IP.
// - Start a new goroutine running the local action of the test.
// - Wait for both the container and local actions to finish.
//
// Container output is logged to $TEST_UNDECLARED_OUTPUTS_DIR if it exists, or
// to stderr.
func singleTest(t *testing.T, test TestCase) {
	t.Parallel()
	for _, ipv6 := range []bool{false, true} {
		if ipv6 {
			t.Run("IPv6", func(t *testing.T) {
				t.Parallel()
				iptablesTest(t, test, true)
			})
		} else {
			t.Run("IPv4", func(t *testing.T) {
				t.Parallel()
				iptablesTest(t, test, false)
			})
		}
	}
}

func iptablesTest(t *testing.T, test TestCase, ipv6 bool) {
	if _, ok := Tests[test.Name()]; !ok {
		t.Fatalf("no test found with name %q. Has it been registered?", test.Name())
	}

	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// TODO(gvisor.dev/issue/170): Skipping IPv6 gVisor tests.
	if ipv6 && dockerutil.Runtime() != "runc" {
		t.Skip("gVisor ip6tables not yet implemented")
	}

	// Create and start the container.
	opts := dockerutil.RunOpts{
		Image:  "iptables",
		CapAdd: []string{"NET_ADMIN"},
	}
	d.CopyFiles(&opts, "/runner", "test/iptables/runner/runner")
	args := []string{"/runner/runner", "-name", test.Name()}
	if ipv6 {
		args = append(args, "-ipv6")
	}
	if err := d.Spawn(ctx, opts, args...); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Wait for the hello statement.
	if _, err := d.WaitForOutput(ctx, HelloStatement, HelloTimeout); err != nil {
		t.Fatalf("container failed to emit hello statement: %v", err)
	}

	// Get the container IP.
	ip, err := d.FindIP(ctx, ipv6)
	if err != nil {
		if ipv6 {
			// If an ipv4 address is available, skip the test.
			if _, err := d.FindIP(ctx, false); err == nil {
				t.Skip("failed to get container IP: IPv6 unavailable")
			}
		}
		// Fail the test outright.
		t.Fatalf("failed to get container IP: %v", err)
	}

	// Connect to the exchanger, which must be up by Hello.
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   ip,
		Port: IPExchangePort,
	})
	if err != nil {
		t.Fatalf("error connecting to container: %v", err)
	}
	defer conn.Close()
	e := NewExchanger(conn)

	// Run the local action.
	if err := test.LocalAction(e, ipv6); err != nil {
		t.Fatalf("LocalAction failed: %v", err)
	}

	// Wait for the final statement. This structure has the side effect
	// that all container logs will appear within the individual test
	// context.
	if _, err := d.WaitForOutput(ctx, TerminalStatement, TerminalTimeout); err != nil {
		t.Fatalf("test failed: %v", err)
	}
}

func TestIptables(t *testing.T) {
	for name, tc := range Tests {
		t.Run(name, func(t *testing.T) {
			singleTest(t, tc)
		})
	}
}

func TestFilterAddrs(t *testing.T) {
	tcs := []struct {
		ipv6  bool
		addrs []string
		want  []string
	}{
		{
			ipv6:  false,
			addrs: []string{"192.168.0.1", "192.168.0.2/24", "::1", "::2/128"},
			want:  []string{"192.168.0.1", "192.168.0.2"},
		},
		{
			ipv6:  true,
			addrs: []string{"192.168.0.1", "192.168.0.2/24", "::1", "::2/128"},
			want:  []string{"::1", "::2"},
		},
	}

	for _, tc := range tcs {
		if got := filterAddrs(tc.addrs, tc.ipv6); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v with IPv6 %t: got %v, but wanted %v", tc.addrs, tc.ipv6, got, tc.want)
		}
	}
}
