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

// Package main runs iptables tests from within a docker container.
package main

import (
	"flag"
	"log"
	"net"

	"gvisor.dev/gvisor/test/iptables"
)

var (
	name = flag.String("name", "", "name of the test to run")
	ipv6 = flag.Bool("ipv6", false, "whether the test utilizes ip6tables")
)

func main() {
	flag.Parse()

	// Find out which test we're running.
	test, ok := iptables.Tests[*name]
	if !ok {
		log.Fatalf("No test found named %q", *name)
	}
	log.Printf("Running test %q", *name)

	// Bind to the local exchanger port.
	localAddr := net.TCPAddr{
		Port: iptables.IPExchangePort,
	}
	listener, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		log.Fatalf("failed listening for IP: %v", err)
	}
	defer listener.Close()

	// Emit the first line. After this point, the external runner may
	// connect to the exchanger for synchronization.
	log.Printf("%s", iptables.HelloStatement)

	// Accept a connection from the host.
	conn, err := listener.AcceptTCP()
	if err != nil {
		log.Fatalf("failed accepting IP: %v", err)
	}
	defer conn.Close()

	// Create our exchanger.
	e := iptables.NewExchanger(conn)

	// Run the test.
	if err := test.ContainerAction(e, *ipv6); err != nil {
		log.Fatalf("Failed running test %q: %v", *name, err)
	}

	// Emit the final line.
	log.Printf("%s", iptables.TerminalStatement)
}
