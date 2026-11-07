package core

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// sysctlForwardFile persists IPv4 forwarding. It is the only file outside the
// WriteAdminFile roots that GoDeb writes for routing.
const sysctlForwardFile = "/etc/sysctl.d/90-godeb-forward.conf"

// SSHPorts returns the ports sshd listens on (`sshd -T`) plus the server port
// of the current SSH login. Both must stay reachable through the firewall.
func SSHPorts(ctx context.Context) []int {
	ports := ParseSSHDPorts(RunAdmin(ctx, "sshd", "-T").Stdout)
	if p := SSHConnectionPort(os.Getenv("SSH_CONNECTION")); p > 0 && !containsPort(ports, p) {
		ports = append(ports, p)
	}
	return ports
}

// ParseSSHDPorts reads the "port N" lines of `sshd -T`.
func ParseSSHDPorts(out string) []int {
	var ports []int
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "port" {
			continue
		}
		p, err := strconv.Atoi(fields[1])
		if err == nil && p > 0 && p <= 65535 && !containsPort(ports, p) {
			ports = append(ports, p)
		}
	}
	return ports
}

// SSHConnectionPort returns the server port from SSH_CONNECTION
// ("client_ip client_port server_ip server_port"), or 0.
func SSHConnectionPort(env string) int {
	fields := strings.Fields(env)
	if len(fields) != 4 {
		return 0
	}
	p, err := strconv.Atoi(fields[3])
	if err != nil || p <= 0 || p > 65535 {
		return 0
	}
	return p
}

func containsPort(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Route is the interface and source address of the IPv4 default route. On a
// VPS that is the public interface and the public IP.
type Route struct {
	Dev string `json:"dev"`
	Src string `json:"src"`
}

// DefaultRoute asks the kernel which way 1.1.1.1 would leave the host.
func DefaultRoute(ctx context.Context) Route {
	return ParseRouteGet(Run(ctx, "ip", "-4", "route", "get", "1.1.1.1").Stdout)
}

// ParseRouteGet reads `ip -4 route get` output such as
// "1.1.1.1 via 172.31.1.1 dev eth0 src 203.0.113.7 uid 0".
func ParseRouteGet(out string) Route {
	var r Route
	fields := strings.Fields(out)
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			r.Dev = fields[i+1]
		case "src":
			r.Src = fields[i+1]
		}
	}
	return r
}

// IPv4Forwarding reports net.ipv4.ip_forward.
func IPv4Forwarding() bool {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

// EnableIPv4Forwarding turns on routing now and after reboots. Routing alone
// opens nothing: ufw keeps DEFAULT_FORWARD_POLICY=DROP, so only explicit
// `ufw route allow` rules pass.
func EnableIPv4Forwarding(ctx context.Context) error {
	content := "# Managed by GoDeb: WireGuard hub and port forwarding.\nnet.ipv4.ip_forward = 1\n"
	if current, err := os.ReadFile(sysctlForwardFile); err != nil || string(current) != content {
		if err := os.WriteFile(sysctlForwardFile, []byte(content), 0o644); err != nil {
			return err
		}
	}
	if IPv4Forwarding() {
		return nil
	}
	if res := RunAdmin(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); res.Err != nil {
		return &CommandError{Result: res}
	}
	return nil
}

// CommandError wraps a failed command so callers can show its stderr.
type CommandError struct{ Result CommandResult }

func (e *CommandError) Error() string {
	return strings.Join(e.Result.Command, " ") + ": " + e.Result.Detail()
}

// LANAddress is a private IPv4 address of a local interface.
type LANAddress struct {
	Iface   string `json:"iface"`
	Address string `json:"address"`
	Prefix  string `json:"prefix"`
}

// LANAddresses lists private IPv4 addresses on interfaces that are up.
// Loopback and WireGuard (wg*) are excluded: they are not the LAN.
func LANAddresses() []LANAddress {
	out := []LANAddress{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || strings.HasPrefix(ifc.Name, "wg") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok || !ip.Unmap().Is4() || !ip.Unmap().IsPrivate() {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			prefix := netip.PrefixFrom(ip.Unmap(), ones).Masked()
			out = append(out, LANAddress{Iface: ifc.Name, Address: ip.Unmap().String(), Prefix: prefix.String()})
		}
	}
	return out
}
