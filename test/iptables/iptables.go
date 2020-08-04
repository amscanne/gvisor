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

// Package iptables contains a set of iptables tests implemented as TestCases.
package iptables

import (
	"fmt"
	"time"
)

const (
	// HelloStatement is emitted when the container starts.
	HelloStatement = "Hello!"

	// TerminalStatement is the last statement in the test runner.
	TerminalStatement = "Finished!"
)

const (
	// HelloTimeout is the timeout to come up.
	HelloTimeout = time.Minute

	// TerminalTimeout is the timeout used for completion.
	TerminalTimeout = time.Minute
)

// A TestCase contains one action to run in the container and one to run
// locally. The actions run concurrently and each must succeed for the test
// pass.
type TestCase interface {
	// Name returns the name of the test.
	Name() string

	// ContainerAction runs inside the container. It receives the IP of the
	// local process. Should should be called when the LocalAction can be
	// executed outside the container.
	ContainerAction(e Exchanger, ipv6 bool) error

	// LocalAction runs locally. It receives the IP of the container.
	LocalAction(e Exchanger, ipv6 bool) error
}

// Tests maps test names to TestCase.
//
// New TestCases are added by calling RegisterTestCase in an init function.
var Tests = map[string]TestCase{}

// RegisterTestCase registers tc so it can be run.
func RegisterTestCase(tc TestCase) {
	if _, ok := Tests[tc.Name()]; ok {
		panic(fmt.Sprintf("TestCase %s already registered.", tc.Name()))
	}
	Tests[tc.Name()] = tc
}
