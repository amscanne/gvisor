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
	"errors"
	"fmt"
	"net"
)

func init() {
	RegisterTestCase(FilterInputDropAll{})
	RegisterTestCase(FilterInputDropDifferentUDPPort{})
	RegisterTestCase(FilterInputDropOnlyUDP{})
	RegisterTestCase(FilterInputDropTCPDestPort{})
	RegisterTestCase(FilterInputDropTCPSrcPort{})
	RegisterTestCase(FilterInputDropUDPPort{})
	RegisterTestCase(FilterInputDropUDP{})
	RegisterTestCase(FilterInputCreateUserChain{})
	RegisterTestCase(FilterInputDefaultPolicyAccept{})
	RegisterTestCase(FilterInputDefaultPolicyDrop{})
	RegisterTestCase(FilterInputReturnUnderflow{})
	RegisterTestCase(FilterInputSerializeJump{})
	RegisterTestCase(FilterInputJumpBasic{})
	RegisterTestCase(FilterInputJumpReturn{})
	RegisterTestCase(FilterInputJumpReturnDrop{})
	RegisterTestCase(FilterInputJumpBuiltin{})
	RegisterTestCase(FilterInputJumpTwice{})
	RegisterTestCase(FilterInputDestination{})
	RegisterTestCase(FilterInputInvertDestination{})
	RegisterTestCase(FilterInputSource{})
	RegisterTestCase(FilterInputInvertSource{})
}

// FilterInputDropUDP tests that we can drop UDP traffic.
type FilterInputDropUDP struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDP) Name() string {
	return "FilterInputDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDP) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}
	if err := listenUDP(e); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDP) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputDropOnlyUDP tests that "-p udp -j DROP" only affects UDP traffic.
type FilterInputDropOnlyUDP struct{}

// Name implements TestCase.Name.
func (FilterInputDropOnlyUDP) Name() string {
	return "FilterInputDropOnlyUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropOnlyUDP) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-j", "DROP"); err != nil {
		return err
	}
	if err := listenTCP(e); err != nil {
		return fmt.Errorf("failed to establish a connection %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropOnlyUDP) LocalAction(e Exchanger, ipv6 bool) error {
	return connectTCP(e, false, ipv6) // Should succeed.
}

// FilterInputDropUDPPort tests that we can drop UDP traffic by port.
type FilterInputDropUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropUDPPort) Name() string {
	return "FilterInputDropUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropUDPPort) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := listenUDP(localSend(func(port int) error {
		// Filter the bound port.
		if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", port), "-j", "DROP"); err != nil {
			return err
		}
		// Send along to the receiver.
		return e.Send(port)
	})); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropUDPPort) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputDropDifferentUDPPort tests that dropping traffic for a single UDP port
// doesn't drop packets on other ports.
type FilterInputDropDifferentUDPPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropDifferentUDPPort) Name() string {
	return "FilterInputDropDifferentUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropDifferentUDPPort) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := listenUDP(localSend(func(port int) error {
		// Filter a different port.
		if err := filterTable(ipv6, "-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", fmt.Sprintf("%d", portAlt(port)), "-j", "DROP"); err != nil {
			return err
		}
		// Send along the bound port.
		return e.Send(port)
	})); err != nil {
		return fmt.Errorf("packets should be allowed, but encountered an error: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropDifferentUDPPort) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputDropTCPDestPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPDestPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropTCPDestPort) Name() string {
	return "FilterInputDropTCPDestPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPDestPort) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := listenTCP(localSend(func(port int) error {
		// Filter the port.
		if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "DROP"); err != nil {
			return err
		}
		// Send along.
		return e.Send(port)
	})); err == nil {
		return fmt.Errorf("connection should not be accepted, but got accepted")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPDestPort) LocalAction(e Exchanger, ipv6 bool) error {
	if err := connectTCP(e, false, ipv6); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect")
	}
	return nil
}

// FilterInputDropTCPSrcPort tests that connections are not accepted on specified source ports.
type FilterInputDropTCPSrcPort struct{}

// Name implements TestCase.Name.
func (FilterInputDropTCPSrcPort) Name() string {
	return "FilterInputDropTCPSrcPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropTCPSrcPort) ContainerAction(e Exchanger, ipv6 bool) error {
	// Receive the bound port remotely.
	_, remotePort, err := e.Recv()
	if err != nil {
		return err
	}
	// Drop anything from the given source port.
	if err := filterTable(ipv6, "-A", "INPUT", "-p", "tcp", "-m", "tcp", "--sport", fmt.Sprintf("%d", remotePort), "-j", "DROP"); err != nil {
		return err
	}
	if err := listenTCP(e); err != nil {
		return fmt.Errorf("connection should not be accepted, but was")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropTCPSrcPort) LocalAction(e Exchanger, ipv6 bool) error {
	// Note: the bound port is sent for the container.
	if err := connectTCP(e, true, ipv6); err == nil {
		return fmt.Errorf("expected not to connect, but was able to connect")
	}
	return nil
}

// FilterInputDropAll tests that we can drop all traffic to the INPUT chain.
type FilterInputDropAll struct{}

// Name implements TestCase.Name.
func (FilterInputDropAll) Name() string {
	return "FilterInputDropAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDropAll) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-j", "DROP"); err != nil {
		return err
	}
	if err := listenUDP(e); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDropAll) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputMultiUDPRules verifies that multiple UDP rules are applied
// correctly. This has the added benefit of testing whether we're serializing
// rules correctly -- if we do it incorrectly, the iptables tool will
// misunderstand and save the wrong tables.
type FilterInputMultiUDPRules struct{}

// Name implements TestCase.Name.
func (FilterInputMultiUDPRules) Name() string {
	return "FilterInputMultiUDPRules"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputMultiUDPRules) ContainerAction(e Exchanger, ipv6 bool) error {
	// N.B. These ports are not used for real traffic, so they are invented
	// only for the purposes of this test.
	rules := [][]string{
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", "22", "-j", "DROP"},
		{"-A", "INPUT", "-p", "udp", "-m", "udp", "--destination-port", "23", "-j", "ACCEPT"},
		{"-L"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputMultiUDPRules) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// FilterInputRequireProtocolUDP checks that "-m udp" requires "-p udp" to be
// specified.
type FilterInputRequireProtocolUDP struct{}

// Name implements TestCase.Name.
func (FilterInputRequireProtocolUDP) Name() string {
	return "FilterInputRequireProtocolUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputRequireProtocolUDP) ContainerAction(e Exchanger, ipv6 bool) error {
	// N.B. The port here is invented; we expect failure.
	if err := filterTable(ipv6, "-A", "INPUT", "-m", "udp", "--destination-port", "22", "-j", "DROP"); err == nil {
		return errors.New("expected iptables to fail with out \"-p udp\", but succeeded")
	}
	return nil
}

func (FilterInputRequireProtocolUDP) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// FilterInputCreateUserChain tests chain creation.
type FilterInputCreateUserChain struct{}

// Name implements TestCase.Name.
func (FilterInputCreateUserChain) Name() string {
	return "FilterInputCreateUserChain"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputCreateUserChain) ContainerAction(e Exchanger, ipv6 bool) error {
	rules := [][]string{
		// Create a chain.
		{"-N", chainName},
		// Add a simple rule to the chain.
		{"-A", chainName, "-j", "DROP"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputCreateUserChain) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// FilterInputDefaultPolicyAccept tests the default ACCEPT policy.
type FilterInputDefaultPolicyAccept struct{}

// Name implements TestCase.Name.
func (FilterInputDefaultPolicyAccept) Name() string {
	return "FilterInputDefaultPolicyAccept"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDefaultPolicyAccept) ContainerAction(e Exchanger, ipv6 bool) error {
	// Set the default policy to accept, then receive a packet.
	if err := filterTable(ipv6, "-P", "INPUT", "ACCEPT"); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDefaultPolicyAccept) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputDefaultPolicyDrop tests the default DROP policy.
type FilterInputDefaultPolicyDrop struct{}

// Name implements TestCase.Name.
func (FilterInputDefaultPolicyDrop) Name() string {
	return "FilterInputDefaultPolicyDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDefaultPolicyDrop) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := filterTable(ipv6, "-P", "INPUT", "DROP"); err != nil {
		return err
	}
	if err := listenUDP(e); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDefaultPolicyDrop) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputReturnUnderflow tests that -j RETURN in a built-in chain causes
// the underflow rule (i.e. default policy) to be executed.
type FilterInputReturnUnderflow struct{}

// Name implements TestCase.Name.
func (FilterInputReturnUnderflow) Name() string {
	return "FilterInputReturnUnderflow"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputReturnUnderflow) ContainerAction(e Exchanger, ipv6 bool) error {
	// Add a RETURN rule followed by an unconditional accept, and set the
	// default policy to DROP.
	rules := [][]string{
		{"-A", "INPUT", "-j", "RETURN"},
		{"-A", "INPUT", "-j", "DROP"},
		{"-P", "INPUT", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputReturnUnderflow) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputSerializeJump verifies that we can serialize jumps.
type FilterInputSerializeJump struct{}

// Name implements TestCase.Name.
func (FilterInputSerializeJump) Name() string {
	return "FilterInputSerializeJump"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputSerializeJump) ContainerAction(e Exchanger, ipv6 bool) error {
	// Write a JUMP rule, the serialize it with `-L`.
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-L"},
	}
	return filterTableRules(ipv6, rules)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputSerializeJump) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// FilterInputJumpBasic jumps to a chain and executes a rule there.
type FilterInputJumpBasic struct{}

// Name implements TestCase.Name.
func (FilterInputJumpBasic) Name() string {
	return "FilterInputJumpBasic"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpBasic) ContainerAction(e Exchanger, ipv6 bool) error {
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpBasic) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputJumpReturn jumps, returns, and executes a rule.
type FilterInputJumpReturn struct{}

// Name implements TestCase.Name.
func (FilterInputJumpReturn) Name() string {
	return "FilterInputJumpReturn"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpReturn) ContainerAction(e Exchanger, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-P", "INPUT", "ACCEPT"},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", "RETURN"},
		{"-A", chainName, "-j", "DROP"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpReturn) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputJumpReturnDrop jumps to a chain, returns, and DROPs packets.
type FilterInputJumpReturnDrop struct{}

// Name implements TestCase.Name.
func (FilterInputJumpReturnDrop) Name() string {
	return "FilterInputJumpReturnDrop"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpReturnDrop) ContainerAction(e Exchanger, ipv6 bool) error {
	rules := [][]string{
		{"-N", chainName},
		{"-A", "INPUT", "-j", chainName},
		{"-A", "INPUT", "-j", "DROP"},
		{"-A", chainName, "-j", "RETURN"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	if err := listenUDP(e); err == nil {
		return fmt.Errorf("packets should have been dropped, but got a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("error reading: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpReturnDrop) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputJumpBuiltin verifies that jumping to a top-levl chain is illegal.
type FilterInputJumpBuiltin struct{}

// Name implements TestCase.Name.
func (FilterInputJumpBuiltin) Name() string {
	return "FilterInputJumpBuiltin"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpBuiltin) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := filterTable(ipv6, "-A", "INPUT", "-j", "OUTPUT"); err == nil {
		return fmt.Errorf("iptables should be unable to jump to a built-in chain")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpBuiltin) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// FilterInputJumpTwice jumps twice, then returns twice and executes a rule.
type FilterInputJumpTwice struct{}

// Name implements TestCase.Name.
func (FilterInputJumpTwice) Name() string {
	return "FilterInputJumpTwice"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputJumpTwice) ContainerAction(e Exchanger, ipv6 bool) error {
	const chainName2 = chainName + "2"
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-N", chainName},
		{"-N", chainName2},
		{"-A", "INPUT", "-j", chainName},
		{"-A", chainName, "-j", chainName2},
		{"-A", "INPUT", "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputJumpTwice) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputDestination verifies that we can filter packets via `-d
// <ipaddr>`.
type FilterInputDestination struct{}

// Name implements TestCase.Name.
func (FilterInputDestination) Name() string {
	return "FilterInputDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputDestination) ContainerAction(e Exchanger, ipv6 bool) error {
	addrs, err := localAddrs(ipv6)
	if err != nil {
		return err
	}

	// Make INPUT's default action DROP, then ACCEPT all packets bound for
	// this machine.
	rules := [][]string{{"-P", "INPUT", "DROP"}}
	for _, addr := range addrs {
		rules = append(rules, []string{"-A", "INPUT", "-d", addr, "-j", "ACCEPT"})
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}

	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputDestination) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputInvertDestination verifies that we can filter packets via `! -d
// <ipaddr>`.
type FilterInputInvertDestination struct{}

// Name implements TestCase.Name.
func (FilterInputInvertDestination) Name() string {
	return "FilterInputInvertDestination"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputInvertDestination) ContainerAction(e Exchanger, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-d", localIP(ipv6), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputInvertDestination) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// FilterInputSource verifies that we can filter packets via `-s
// <ipaddr>`.
type FilterInputSource struct{}

// Name implements TestCase.Name.
func (FilterInputSource) Name() string {
	return "FilterInputSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputSource) ContainerAction(e Exchanger, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets from this
	// machine. Note that the Recv here can be done because the first line
	// of the local action is to re-send the local IP and make it
	// accessible here.
	ip, _, err := e.Recv()
	if err != nil {
		return err
	}
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "-s", fmt.Sprintf("%v", ip), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputSource) LocalAction(e Exchanger, ipv6 bool) error {
	// Send blank port for the IP.
	if err := e.Send(0); err != nil {
		return err
	}
	return sendUDP(e)
}

// FilterInputInvertSource verifies that we can filter packets via `! -s
// <ipaddr>`.
type FilterInputInvertSource struct{}

// Name implements TestCase.Name.
func (FilterInputInvertSource) Name() string {
	return "FilterInputInvertSource"
}

// ContainerAction implements TestCase.ContainerAction.
func (FilterInputInvertSource) ContainerAction(e Exchanger, ipv6 bool) error {
	// Make INPUT's default action DROP, then ACCEPT all packets not bound
	// for 127.0.0.1.
	rules := [][]string{
		{"-P", "INPUT", "DROP"},
		{"-A", "INPUT", "!", "-s", localIP(ipv6), "-j", "ACCEPT"},
	}
	if err := filterTableRules(ipv6, rules); err != nil {
		return err
	}
	return listenUDP(e)
}

// LocalAction implements TestCase.LocalAction.
func (FilterInputInvertSource) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}
