// Copyright 2020 The gVisor Authors.
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

/*
import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

func init() {
	RegisterTestCase(NATPreRedirectUDPPort{})
	RegisterTestCase(NATPreRedirectTCPPort{})
	RegisterTestCase(NATPreRedirectTCPOutgoing{})
	RegisterTestCase(NATOutRedirectTCPIncoming{})
	RegisterTestCase(NATOutRedirectUDPPort{})
	RegisterTestCase(NATOutRedirectTCPPort{})
	RegisterTestCase(NATDropUDP{})
	RegisterTestCase(NATAcceptAll{})
	RegisterTestCase(NATPreRedirectIP{})
	RegisterTestCase(NATPreDontRedirectIP{})
	RegisterTestCase(NATPreRedirectInvert{})
	RegisterTestCase(NATOutRedirectIP{})
	RegisterTestCase(NATOutDontRedirectIP{})
	RegisterTestCase(NATOutRedirectInvert{})
	RegisterTestCase(NATRedirectRequiresProtocol{})
	RegisterTestCase(NATLoopbackSkipsPrerouting{})
	RegisterTestCase(NATPreOriginalDst{})
	RegisterTestCase(NATOutOriginalDst{})
}

// NATPreRedirectUDPPort tests that packets are redirected to different port.
type NATPreRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectUDPPort) Name() string {
	return "NATPreRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectUDPPort) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := listenUDP(localSend(func(port int) error {
		// Redirect all traffic to the bound port.
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		// Return the portAlt; not bound, but should redirect.
		return e.Send(portAlt(port))
	})); err != nil {
		return fmt.Errorf("packets should be reidrected, but encountered an error: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectUDPPort) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e) // Should succeed.
}

// NATPreRedirectTCPPort tests that connections are redirected on specified ports.
type NATPreRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPPort) Name() string {
	return "NATPreRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPPort) ContainerAction(e Exchanger, ipv6 bool) error {
	// Listen for TCP packets on redirect port.
	if err := listenTCP(localSend(func(port int) error {
		// Redirect from port to portAlt.
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", portAlt(port)), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		// Return the portAlt; not bound, but should redirect.
		return e.Send(portAlt(port))
	})); err != nil {
		return fmt.Errorf("packets should be redirected, but encountered an error: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPPort) LocalAction(e Exchanger, ipv6 bool) error {
	return connectTCP(e, ipv6) // Should succeed.
}

// NATPreRedirectTCPOutgoing verifies that outgoing TCP connections aren't
// affected by PREROUTING connection tracking.
type NATPreRedirectTCPOutgoing struct{}

// Name implements TestCase.Name.
func (NATPreRedirectTCPOutgoing) Name() string {
	return "NATPreRedirectTCPOutgoing"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectTCPOutgoing) ContainerAction(e Exchanger, ipv6 bool) error {
	// Establish a connection to the host process.
	return connectTCP(localRecv(func() (net.IP, int, error) {
		// Redirect all incoming TCP traffic to a closed port.
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", portAlt(port))); err != nil {
			return net.IP{}, 0, err
		}
		return
	}), ipv6)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectTCPOutgoing) LocalAction(e Exchanger, ipv6 bool) error {
	return listenTCP(e)
}

// NATOutRedirectTCPIncoming verifies that incoming TCP connections aren't
// affected by OUTPUT connection tracking.
type NATOutRedirectTCPIncoming struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPIncoming) Name() string {
	return "NATOutRedirectTCPIncoming"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPIncoming) ContainerAction(e Exchanger, ipv6 bool) error {
	// Redirect all outgoing TCP traffic to a closed port.
	if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", dropPort)); err != nil {
		return err
	}

	// Establish a connection to the host process.
	return listenTCP(e)
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectTCPIncoming) LocalAction(e Exchanger, ipv6 bool) error {
	return connectTCP(e, false)
}

// NATOutRedirectUDPPort tests that packets are redirected to different port.
type NATOutRedirectUDPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectUDPPort) Name() string {
	return "NATOutRedirectUDPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectUDPPort) ContainerAction(_ Exchanger, ipv6 bool) error {
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)), func(boundPort, unboundPort int) []string {
		return []string{
			"-A", "OUTPUT",
			"-p", "udp",
			"-j", "REDIRECT",
			"--to-ports", fmt.Sprintf("%d", boundPort),
		}
	})
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectUDPPort) LocalAction(Exchanger, bool) error {
	return nil
}

// NATDropUDP tests that packets are not received in ports other than redirect
// port.
type NATDropUDP struct{}

// Name implements TestCase.Name.
func (NATDropUDP) Name() string {
	return "NATDropUDP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATDropUDP) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := listenUDP(localSend(func(port int) error {
		// Redirect to the bound port.
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		// Send some other port.
		return e.Send(portAlt(port))
	})); err == nil {
		return fmt.Errorf("packets should have been redirected")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATDropUDP) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// NATAcceptAll tests that all UDP packets are accepted.
type NATAcceptAll struct{}

// Name implements TestCase.Name.
func (NATAcceptAll) Name() string {
	return "NATAcceptAll"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATAcceptAll) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := listenUDP(e); err != nil {
		return fmt.Errorf("packets should be allowed, but encountered an error: %v", err)
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATAcceptAll) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// NATOutRedirectIP uses iptables to select packets based on destination IP and
// redirects them.
type NATOutRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutRedirectIP) Name() string {
	return "NATOutRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectIP) ContainerAction(e Exchanger, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)), func(boundPort, unboundPort int) []string {
		return []string{
			"-A", "OUTPUT",
			"-d", nowhereIP(ipv6),
			"-p", "udp",
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", boundPort),
		}
	})
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectIP) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// NATOutDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATOutDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATOutDontRedirectIP) Name() string {
	return "NATOutDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutDontRedirectIP) ContainerAction(e Exchanger, ipv6 bool) error {
	return sendUDP(localRecv(func() (net.IP, int, error) {
		ip, port, err := e.Recv()
		if err != nil {
			return ip, port, err
		}
		// Redirect outgoing traffic to some other address (won't match).
		if err := natTable(ipv6, "-A", "OUTPUT", "-d", localIP(ipv6), "-p", "udp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", portAlt(port))); err != nil {
			return err
		}
		// Return the original port.
		return ip, port, err
	}))
}

// LocalAction implements TestCase.LocalAction.
func (NATOutDontRedirectIP) LocalAction(e Exchanger, ipv6 bool) error {
	return listenUDP(e)
}

// NATOutRedirectInvert tests that iptables can match with "! -d".
type NATOutRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATOutRedirectInvert) Name() string {
	return "NATOutRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectInvert) ContainerAction(_ Exchanger, ipv6 bool) error {
	// Redirect OUTPUT packets to a listening localhost port.
	dest := "192.0.2.2"
	if ipv6 {
		dest = "2001:db8::2"
	}
	return loopbackTest(ipv6, net.ParseIP(nowhereIP(ipv6)), func(boundPort, unboundPort int) []string {
		return []string{
			"-A", "OUTPUT",
			"!", "-d", dest,
			"-p", "udp",
			"-j", "REDIRECT",
			"--to-port", fmt.Sprintf("%d", boundPort),
		}
	})
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectInvert) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// NATPreRedirectIP tests that we can use iptables to select packets based on
// destination IP and redirect them.
type NATPreRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreRedirectIP) Name() string {
	return "NATPreRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectIP) ContainerAction(e Exchanger, ipv6 bool) error {
	addrs, err := localAddrs(ipv6)
	if err != nil {
		return err
	}
	return listenUDP(localSend(func(port int) error {
		var rules [][]string
		for _, addr := range addrs {
			rules = append(rules, []string{
				"-A", "PREROUTING",
				"-p", "udp",
				"-d", addr,
				"-j", "REDIRECT",
				"--to-ports", fmt.Sprintf("%d", port),
			})
		}
		if err := natTableRules(ipv6, rules); err != nil {
			return err
		}
		return e.Send(port)
	}))
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectIP) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// NATPreDontRedirectIP tests that iptables matching with "-d" does not match
// packets it shouldn't.
type NATPreDontRedirectIP struct{}

// Name implements TestCase.Name.
func (NATPreDontRedirectIP) Name() string {
	return "NATPreDontRedirectIP"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreDontRedirectIP) ContainerAction(e Exchanger, ipv6 bool) error {
	return listenUDP(localSend(func(port int) error {
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		return e.Send(port)
	}))
}

// LocalAction implements TestCase.LocalAction.
func (NATPreDontRedirectIP) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// NATPreRedirectInvert tests that iptables can match with "! -d".
type NATPreRedirectInvert struct{}

// Name implements TestCase.Name.
func (NATPreRedirectInvert) Name() string {
	return "NATPreRedirectInvert"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreRedirectInvert) ContainerAction(e Exchanger, ipv6 bool) error {
	return listenUDP(localSend(func(port int) error {
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "udp", "!", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
	}))
}

// LocalAction implements TestCase.LocalAction.
func (NATPreRedirectInvert) LocalAction(e Exchanger, ipv6 bool) error {
	return sendUDP(e)
}

// NATRedirectRequiresProtocol tests that use of the --to-ports flag requires a
// protocol to be specified with -p.
type NATRedirectRequiresProtocol struct{}

// Name implements TestCase.Name.
func (NATRedirectRequiresProtocol) Name() string {
	return "NATRedirectRequiresProtocol"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATRedirectRequiresProtocol) ContainerAction(e Exchanger, ipv6 bool) error {
	if err := natTable(ipv6, "-A", "PREROUTING", "-d", localIP(ipv6), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", acceptPort)); err == nil {
		return errors.New("expected an error using REDIRECT --to-ports without a protocol")
	}
	return nil
}

// LocalAction implements TestCase.LocalAction.
func (NATRedirectRequiresProtocol) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// NATOutRedirectTCPPort tests that connections are redirected on specified ports.
type NATOutRedirectTCPPort struct{}

// Name implements TestCase.Name.
func (NATOutRedirectTCPPort) Name() string {
	return "NATOutRedirectTCPPort"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutRedirectTCPPort) ContainerAction(_ Exchanger, ipv6 bool) error {
	listenCh := make(chan error)
	localE := makeLocalExchange(ipv6)
	go func() {
		listenCh <- listenTCP(localSend(func(port int) error {
			// Redirect to the bound port.
			if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-m", "tcp", "--dport", fmt.Sprintf("%d", altPort(port)), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", port)); err != nil {
				return err
			}
			// Send the altPort.
			return localE.Send(portAlt(port))
		}))
	}()
	if err := connectTCP(e, false); err != nil {
		return err
	}
	return <-listenCh
}

// LocalAction implements TestCase.LocalAction.
func (NATOutRedirectTCPPort) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// NATLoopbackSkipsPrerouting tests that packets sent via loopback aren't
// affected by PREROUTING rules.
type NATLoopbackSkipsPrerouting struct{}

// Name implements TestCase.Name.
func (NATLoopbackSkipsPrerouting) Name() string {
	return "NATLoopbackSkipsPrerouting"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATLoopbackSkipsPrerouting) ContainerAction(e Exchanger, ipv6 bool) error {
	listenCh := make(chan error)
	localE := makeLocalExchange(ipv6)
	go func() {
		if err := listenTCP(localE); err != nil {
			return err
		}

		// Redirect anything sent to localhost to an unused port.
		dest := []byte{127, 0, 0, 1}
		if err := natTable(ipv6, "-A", "PREROUTING", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", dropPort)); err != nil {
			return err
		}
		<-readyCh // Wait until ready.
		sendCh <- connectTCP(dest, acceptPort, sendloopDuration)
	}()

	return <-sendCh
}

// LocalAction implements TestCase.LocalAction.
func (NATLoopbackSkipsPrerouting) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

// NATPreOriginalDst tests that SO_ORIGINAL_DST returns the pre-NAT destination
// of PREROUTING NATted packets.
type NATPreOriginalDst struct{}

// Name implements TestCase.Name.
func (NATPreOriginalDst) Name() string {
	return "NATPreOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATPreOriginalDst) ContainerAction(e Exchanger, ipv6 bool) error {
	addrs, err := getInterfaceAddrs(ipv6)
	if err != nil {
		return err
	}
	return listenForRedirectedConn(localSend(func(port int) error {
		// Redirect incoming TCP connections from portAlt to port.
		if err := natTable(ipv6, "-A", "PREROUTING",
			"-p", "tcp",
			"--destination-port", fmt.Sprintf("%d", portAlt(port)),
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		// Send portAlt to the other side.
		return e.Send(portAlt(port))
	}), ipv6, addrs)
}

// LocalAction implements TestCase.LocalAction.
func (NATPreOriginalDst) LocalAction(e Exchanger, ipv6 bool) error {
	return connectTCP(e, sendloopDuration)
}

// NATOutOriginalDst tests that SO_ORIGINAL_DST returns the pre-NAT destination
// of OUTBOUND NATted packets.
type NATOutOriginalDst struct{}

// Name implements TestCase.Name.
func (NATOutOriginalDst) Name() string {
	return "NATOutOriginalDst"
}

// ContainerAction implements TestCase.ContainerAction.
func (NATOutOriginalDst) ContainerAction(e Exchanger, ipv6 bool) error {
	localE := makeLocalExchange(ipv6)
	go func() {
		connCh <- connectTCP(localE, sendloopDuration)
	}()
	if err := listenForRedirectedConn(localSend(func(port int) error {
		// Redirect incoming TCP connections.
		if err := natTable(ipv6, "-A", "OUTPUT", "-p", "tcp", "-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", port)); err != nil {
			return err
		}
		// Send the portAlt.
		return localE.Send(portAlt(port))
	}), ipv6, []net.IP{ip}); err != nil {
		return err
	}
	return <-connCh
}

// LocalAction implements TestCase.LocalAction.
func (NATOutOriginalDst) LocalAction(e Exchanger, ipv6 bool) error {
	return nil
}

func listenForRedirectedConn(e Exchanger, ipv6 bool, originalDsts []net.IP) error {
	// Verify that, despite listening on acceptPort, SO_ORIGINAL_DST
	// indicates the packet was sent to originalDst:dropPort.
	sockfd, port, err := rawTCPSocket(ipv6)

	// Stack listening.
	if err := syscall.Listen(sockfd, 1); err != nil {
		return err
	}

	// Send the port.
	if err := e.Send(port); err != nil {
		return err
	}

	// Accept a new connection.
	connfd, _, err := syscall.Accept(sockfd)
	if err != nil {
		return err
	}
	defer syscall.Close(connfd)

	if ipv6 {
		got, err := originalDestination6(connfd)
		if err != nil {
			return err
		}
		// The original destination could be any of our IPs.
		for _, dst := range originalDsts {
			want := syscall.RawSockaddrInet6{
				Family: syscall.AF_INET6,
				Port:   htons(dropPort),
			}
			copy(want.Addr[:], dst.To16())
			if got == want {
				return nil
			}
		}
		return fmt.Errorf("SO_ORIGINAL_DST returned %+v, but wanted one of %+v (note: port numbers are in network byte order)", got, originalDsts)
	} else {
		got, err := originalDestination4(connfd)
		if err != nil {
			return err
		}
		// The original destination could be any of our IPs.
		for _, dst := range originalDsts {
			want := syscall.RawSockaddrInet4{
				Family: syscall.AF_INET,
				Port:   htons(dropPort),
			}
			copy(want.Addr[:], dst.To4())
			if got == want {
				return nil
			}
		}
		return fmt.Errorf("SO_ORIGINAL_DST returned %+v, but wanted one of %+v (note: port numbers are in network byte order)", got, originalDsts)
	}
}

// loopbackTests runs an iptables rule given a bound port.
func loopbackTest(ipv6 bool, dest net.IP, rules func(boundPort, unboundPort int) []string) error {
	listenCh := make(chan error)
	localE := makeLocalExchange(ipv6)
	go func() {
		listenCh <- listenUDP(localSend(func(port int) error {
			// Construct the natTable given the port.
			if err := natTable(ipv6, rules(port, portAlt(port))); err != nil {
				return err
			}
			return localE.Send(port)
		}))
	}()
	if err := sendUDP(localRecv(func() (net.IP, int, error) {
		ip, port, err := localE.Recv()
		if err != nil {
			return ip, port, err
		}
		// Override the destination.
		return dest, port, nil
	})); err != nil {
		return err
	}
	return <-listenCh
}
*/
