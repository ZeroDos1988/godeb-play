package wireguard

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"
)

const testKey = "aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tISE="

func TestParseConfigPeerName(t *testing.T) {
	cfg := ParseConfig(sampleConfig)
	if len(cfg.Peers) != 1 || cfg.Peers[0].Name != "laptop" {
		t.Fatalf("peers = %#v", cfg.Peers)
	}
	if got := interfaceValue(sampleConfig, "privatekey"); got != "not-a-real-key" {
		t.Fatalf("private key = %q", got)
	}
}

func TestParseDumpDropsSecrets(t *testing.T) {
	live := ParseDump(sampleDump)
	if live.PublicKey != "example-server-public-key" || live.ListenPort != "51820" {
		t.Fatalf("interface = %#v", live)
	}
	if len(live.Peers) != 1 {
		t.Fatalf("peers = %#v", live.Peers)
	}
	p := live.Peers[0]
	if p.RxBytes != 1482734 || p.TxBytes != 20941823 || p.LatestHandshake != 1760380000 {
		t.Fatalf("peer = %#v", p)
	}
	if p.AllowedIPs[0] != "10.8.0.2/32" || p.Endpoint != "203.0.113.10:51820" {
		t.Fatalf("peer = %#v", p)
	}
}

func TestMergePeers(t *testing.T) {
	conf := []Peer{{Name: "laptop", PublicKey: "a", AllowedIPs: []string{"10.8.0.2/32"}}}
	live := []LivePeer{{PublicKey: "a", RxBytes: 10, TxBytes: 20}, {PublicKey: "b", AllowedIPs: []string{"10.8.0.3/32"}}}
	got := MergePeers(conf, live)
	if len(got) != 2 {
		t.Fatalf("got %#v", got)
	}
	if got[0].Name != "laptop" || !got[0].Live || !got[0].InConfig || got[0].RxBytes != 10 {
		t.Fatalf("first = %#v", got[0])
	}
	if got[1].PublicKey != "b" || got[1].InConfig || got[1].AllowedIPs[0] != "10.8.0.3/32" {
		t.Fatalf("second = %#v", got[1])
	}
}

func TestValidators(t *testing.T) {
	if got, err := validEndpoint("vpn.example.org:51820"); err != nil || got != "vpn.example.org:51820" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := validEndpoint("[2001:db8::1]:51820"); err != nil || got != "[2001:db8::1]:51820" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"vpn.example.org", "host:0", "evil\nhost:1", "a b:1", "-x:1"} {
		if _, err := validEndpoint(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if !validKey(testKey) || validKey("short") {
		t.Fatal("validKey")
	}
}

func TestGenerateKeypair(t *testing.T) {
	if _, err := exec.LookPath("wg"); err != nil {
		t.Skip("wg nicht installiert")
	}
	keys, err := GenerateKeypair(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !validKey(keys.Private) || !validKey(keys.Public) || keys.Private == keys.Public {
		t.Fatalf("keys = %#v", keys)
	}
	again, err := PublicKey(context.Background(), keys.Private)
	if err != nil || again != keys.Public {
		t.Fatalf("pubkey = %q, %v", again, err)
	}
}

func TestHubFromConfig(t *testing.T) {
	cfg := ParseConfig("[Interface]\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = x\nAllowedIPs = 192.168.50.0/24, 10.8.0.0/24\nEndpoint = vps.example.org:51820\n")
	hub, ok := hubFromConfig(cfg, netip.MustParseAddr("10.8.0.2"))
	if !ok || hub.String() != "10.8.0.1" {
		t.Fatalf("hub = %v %v", hub, ok)
	}
	full := ParseConfig("[Peer]\nAllowedIPs = 0.0.0.0/0\n")
	if _, ok := hubFromConfig(full, netip.MustParseAddr("10.8.0.2")); ok {
		t.Fatal("a full tunnel says nothing about the hub address")
	}
}
