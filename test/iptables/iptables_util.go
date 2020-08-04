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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const (
	udpDuration = 3 * time.Second
	tcpDuration = 3 * time.Second
	chainName   = "foochain"
)

// filterTable calls `ip{6}tables -t filter` with the given args.
func filterTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "filter", args)
}

// natTable calls `ip{6}tables -t nat` with the given args.
func natTable(ipv6 bool, args ...string) error {
	return tableCmd(ipv6, "nat", args)
}

func tableCmd(ipv6 bool, table string, args []string) error {
	args = append([]string{"-t", table}, args...)
	binary := "iptables"
	if ipv6 {
		binary = "ip6tables"
	}
	cmd := exec.Command(binary, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error running iptables with args %v\nerror: %v\noutput: %s", args, err, string(out))
	}
	return nil
}

// filterTableRules is like filterTable, but runs multiple iptables commands.
func filterTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "filter", argsList)
}

// natTableRules is like natTable, but runs multiple iptables commands.
func natTableRules(ipv6 bool, argsList [][]string) error {
	return tableRules(ipv6, "nat", argsList)
}

func tableRules(ipv6 bool, table string, argsList [][]string) error {
	for _, args := range argsList {
		if err := tableCmd(ipv6, table, args); err != nil {
			return err
		}
	}
	return nil
}

// listenUDP listens on a UDP port and returns the value of net.Conn.Read() for
// the first read on that port. This means that success is defined as having
// received at least one packet, and failure is defined as having received
// none (or some other error occuring).
//
// The bound port will be Sent on the Exchanger.
func listenUDP(e Exchanger) error {
	localAddr := net.UDPAddr{
		Port: 0,
	}
	conn, err := net.ListenUDP("udp", &localAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send the port to the remote side.
	if err := e.Send(conn.LocalAddr().(*net.UDPAddr).Port); err != nil {
		return err
	}

	// Accept to read at least one packet.
	conn.SetDeadline(time.Now().Add(udpDuration))
	_, err = conn.Read([]byte{0})
	return err
}

// sendUDP sends 1 byte UDP packets repeatedly to the IP and port specified
// over a duration.
//
// The destination is read from the Exchanger.
func sendUDP(e Exchanger) error {
	conn, err := connectUDP(e)
	if err != nil {
		return err
	}
	defer conn.Close()
	loopUDP(conn)
	return nil
}

func connectUDP(e Exchanger) (net.Conn, error) {
	ip, port, err := e.Recv()
	if err != nil {
		return nil, err
	}
	remote := net.UDPAddr{
		IP:   ip,
		Port: port,
	}
	conn, err := net.DialUDP("udp", nil, &remote)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func loopUDP(conn net.Conn) {
	to := time.After(udpDuration)
	for timedOut := false; !timedOut; {
		// This may return an error (connection refused) if the remote
		// hasn't started listening yet or they're dropping our
		// packets. So we ignore Write errors and depend on the remote
		// to report a failure if it doesn't get a packet it needs.
		conn.Write([]byte{0})
		select {
		case <-to:
			timedOut = true
		default:
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// listenTCP listens for connections on a TCP port.
//
// The bound port will be Sent on the Exchanger.
func listenTCP(e Exchanger) error {
	localAddr := net.TCPAddr{
		Port: 0,
	}

	// Starts listening on port.
	lConn, err := net.ListenTCP("tcp", &localAddr)
	if err != nil {
		return err
	}
	defer lConn.Close()

	// Send the port.
	if err := e.Send(lConn.Addr().(*net.TCPAddr).Port); err != nil {
		return err
	}

	// Accept connections on port.
	lConn.SetDeadline(time.Now().Add(tcpDuration))
	conn, err := lConn.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()

	return nil
}

// rawTCPSocket returns a raw FD for a TCP socket, along with it's port.
func rawTCPSocket(ipv6 bool) (sockfd int, port int, err error) {
	// The net package doesn't give guarantee access to the connection's
	// underlying FD, and thus we cannot call getsockopt. We have to use
	// traditional syscalls for SO_ORIGINAL_DST.
	family := syscall.AF_INET
	if ipv6 {
		family = syscall.AF_INET6
	}
	sockfd, err = syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, 0, err
	}
	defer syscall.Close(sockfd)

	var bindAddr syscall.Sockaddr
	if ipv6 {
		bindAddr = &syscall.SockaddrInet6{
			Port: 0,
			Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // IN6ADDR_ANY
		}
	} else {
		bindAddr = &syscall.SockaddrInet4{
			Port: 0,
			Addr: [4]byte{0, 0, 0, 0}, // INADDR_ANY
		}
	}
	if err := syscall.Bind(sockfd, bindAddr); err != nil {
		return 0, 0, err
	}

	// Extract the bound port.
	sa, err := syscall.Getsockname(sockfd)
	if err != nil {
		return 0, 0, err
	}
	switch v := sa.(type) {
	case *syscall.SockaddrInet4:
		port = v.Port
	case *syscall.SockaddrInet6:
		port = v.Port
	default:
		return 0, 0, fmt.Errorf("unknown sockaddr type %T", sa)
	}

	// Success.
	return sockfd, port, nil
}

// connectTCP connects to the given IP and port from an ephemeral local address.
//
// If send is true, then the bound port is sent *before* receiving the port
// from the remote end. This is useful for testing source port-based filtering.
//
// The address is received from the Exchanger.
func connectTCP(e Exchanger, sendPort bool, ipv6 bool) error {
	sockfd, port, err := rawTCPSocket(ipv6)
	if sendPort {
		// Send the port if required.
		if err := e.Send(port); err != nil {
			return err
		}
	}

	// Pull the remote address.
	ip, port, err := e.Recv()
	if err != nil {
		return err
	}

	// Connect to the remote end.
	var connectAddr syscall.Sockaddr
	if ipv6 {
		connectAddr = &syscall.SockaddrInet6{
			Port: port,
		}
		copy(connectAddr.(*syscall.SockaddrInet6).Addr[:], ip)
	} else {
		connectAddr = &syscall.SockaddrInet4{
			Port: port,
		}
		copy(connectAddr.(*syscall.SockaddrInet4).Addr[:], ip)
	}
	if err := syscall.Connect(sockfd, connectAddr); err != nil {
		return err
	}

	// Done.
	return syscall.Close(sockfd)
}

// localAddrs returns a list of local network interface addresses. When ipv6 is
// true, only IPv6 addresses are returned. Otherwise only IPv4 addresses are
// returned.
func localAddrs(ipv6 bool) ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		// Add only IPv4 or only IPv6 addresses.
		parts := strings.Split(addr.String(), "/")
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad interface address: %q", addr.String())
		}
		if isIPv6 := net.ParseIP(parts[0]).To4() == nil; isIPv6 == ipv6 {
			addrStrs = append(addrStrs, addr.String())
		}
	}
	return filterAddrs(addrStrs, ipv6), nil
}

func filterAddrs(addrs []string, ipv6 bool) []string {
	addrStrs := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		// Add only IPv4 or only IPv6 addresses.
		parts := strings.Split(addr, "/")
		if isIPv6 := net.ParseIP(parts[0]).To4() == nil; isIPv6 == ipv6 {
			addrStrs = append(addrStrs, parts[0])
		}
	}
	return addrStrs
}

// getInterfaceName returns the name of the interface other than loopback.
func getInterfaceName() (string, bool) {
	iface, ok := getNonLoopbackInterface()
	if !ok {
		return "", false
	}
	return iface.Name, true
}

func getInterfaceAddrs(ipv6 bool) ([]net.IP, error) {
	iface, ok := getNonLoopbackInterface()
	if !ok {
		return nil, errors.New("no non-loopback interface found")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// Get only IPv4 or IPv6 addresses.
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		parts := strings.Split(addr.String(), "/")
		var ip net.IP
		// To16() returns IPv4 addresses as IPv4-mapped IPv6 addresses.
		// So we check whether To4() returns nil to test whether the
		// address is v4 or v6.
		if v4 := net.ParseIP(parts[0]).To4(); ipv6 && v4 == nil {
			ip = net.ParseIP(parts[0]).To16()
		} else {
			ip = v4
		}
		if ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func getNonLoopbackInterface() (net.Interface, bool) {
	if interfaces, err := net.Interfaces(); err == nil {
		for _, intf := range interfaces {
			if intf.Name != "lo" {
				return intf, true
			}
		}
	}
	return net.Interface{}, false
}

func htons(x uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, x)
	return binary.LittleEndian.Uint16(buf)
}

func localIP(ipv6 bool) string {
	if ipv6 {
		return "::1"
	}
	return "127.0.0.1"
}

func nowhereIP(ipv6 bool) string {
	if ipv6 {
		return "2001:db8::1"
	}
	return "192.0.2.1"
}

// portAlt returns a distinct port from the given one. This is useful for
// redirection rules, or rules where we want to check that an action on a
// different port does not have an effect.
func portAlt(port int) int {
	if port%2 == 1 {
		return port - 1
	}
	return port + 1
}
