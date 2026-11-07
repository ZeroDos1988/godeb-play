package wireguard

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var hostName = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`)

// validEndpoint checks host:port from a join code before it lands in wg0.conf.
func validEndpoint(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("Endpoint muss host:port sein")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("Endpoint-Port ist ungültig")
	}
	if _, err := netip.ParseAddr(host); err != nil && !hostName.MatchString(host) {
		return "", fmt.Errorf("Endpoint-Host ist ungültig")
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// hostAddr parses a single address, bare or as a /32 or /128 prefix.
func hostAddr(entry string) (netip.Addr, bool) {
	entry = strings.TrimSpace(entry)
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if prefix.IsSingleIP() {
			return prefix.Addr(), true
		}
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(entry)
	return addr, err == nil
}
