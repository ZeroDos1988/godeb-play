package firstrun

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseUFWRules(t *testing.T) {
	out := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n51820/udp                  ALLOW       Anywhere\n8080/tcp on wg0            ALLOW       Anywhere\n\n"
	rules := ParseUFWRules(out)
	if len(rules) != 3 || rules[2] != "8080/tcp on wg0 ALLOW Anywhere" {
		t.Fatalf("rules = %q", rules)
	}
}

func TestWriteSummaryShowsTunnelURL(t *testing.T) {
	var b bytes.Buffer
	WriteSummary(&b, Summary{
		Hostname: "vps", Version: "0.2.1", PublicIP: "203.0.113.5", Role: "hub", Access: AccessTunnel,
		URLs:     []Link{{Label: "Über den WireGuard-Tunnel", URL: "http://10.8.0.1:8080"}},
		Tunnel:   &TunnelSummary{Interface: "wg0", Address: "10.8.0.1", Network: "10.8.0.0/24", Endpoint: "203.0.113.5:51820", Sites: []SiteLink{{Name: "heim-vm", URL: "http://10.8.0.2:8080"}}},
		SSHPorts: []int{22}, Firewall: "active", Rules: []string{"22/tcp ALLOW Anywhere"},
	})
	out := b.String()
	for _, want := range []string{"http://10.8.0.1:8080", "WireGuard-Hub", "nur über den WireGuard-Tunnel", "203.0.113.5:51820", "heim-vm http://10.8.0.2:8080", "22/tcp ALLOW"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
}
