package ufw

import (
	"reflect"
	"strings"
	"testing"
)

const sampleAdded = `Added user rules (see 'ufw status' for running firewall):
ufw allow 22/tcp comment 'SSH'
ufw allow 51820/udp comment 'GoDeb WireGuard'
ufw route allow in on eth0 out on wg0 to 10.8.0.2 port 15636:15637 proto udp comment 'GoDeb-PF enshrouded-1a2b'
ufw route allow in on wg0 out on wg0 to 10.8.0.2 port 8080 proto tcp comment 'GoDeb-Hub heim-vm'
ufw route allow in on wg0 out on eth0
`

func TestParseAddedRoutes(t *testing.T) {
	got := ParseAddedRoutes(sampleAdded, "GoDeb-PF")
	want := map[string][]string{
		"GoDeb-PF enshrouded-1a2b": {"allow", "in", "on", "eth0", "out", "on", "wg0", "to", "10.8.0.2", "port", "15636:15637", "proto", "udp", "comment", "GoDeb-PF enshrouded-1a2b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	if hub := ParseAddedRoutes(sampleAdded, "GoDeb-Hub"); len(hub) != 1 || hub["GoDeb-Hub heim-vm"] == nil {
		t.Fatalf("hub=%#v", hub)
	}
	if none := ParseAddedRoutes(sampleAdded, "GoDeb"); len(none) != 0 {
		t.Fatalf("tag must match up to the space: %#v", none)
	}
}

func TestRouteRuleValidation(t *testing.T) {
	ok := RouteRule{In: "eth0", Out: "wg0", To: "10.8.0.2", Port: "15636:15637", Proto: "udp", Comment: "GoDeb-PF enshrouded"}
	if err := ok.valid(); err != nil {
		t.Fatal(err)
	}
	all := RouteRule{In: "wg0", Out: "eth0", Comment: "GoDeb-VT internet"}
	if err := all.valid(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(all.args(), " "); got != "in on wg0 out on eth0 comment GoDeb-VT internet" {
		t.Fatalf("args=%q", got)
	}
	for _, bad := range []RouteRule{
		{In: "eth0;x", Out: "wg0", To: "10.8.0.2", Port: "1", Proto: "udp", Comment: "GoDeb-PF a"},
		{In: "eth0", Out: "wg0", To: "10.8.0.2/24", Port: "1", Proto: "udp", Comment: "GoDeb-PF a"},
		{In: "eth0", Out: "wg0", To: "10.8.0.2", Port: "1-2", Proto: "udp", Comment: "GoDeb-PF a"},
		{In: "eth0", Out: "wg0", To: "10.8.0.2", Port: "1", Proto: "icmp", Comment: "GoDeb-PF a"},
		{In: "eth0", Out: "wg0", To: "10.8.0.2", Port: "1", Proto: "udp", Comment: "GoDeb-PF a' b"},
		{In: "wg0", Out: "eth0", To: "10.8.0.2", Comment: "GoDeb-VT internet"}, // partial
	} {
		if bad.valid() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
