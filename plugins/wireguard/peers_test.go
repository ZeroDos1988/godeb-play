package wireguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"
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

func TestNextFreeIP(t *testing.T) {
	got, err := NextFreeIP([]string{"10.8.0.1/24"}, []string{"10.8.0.2/32", "10.8.0.3", "0.0.0.0/0"})
	if err != nil || got.String() != "10.8.0.4" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := NextFreeIP([]string{"10.9.0.1/30"}, []string{"10.9.0.2/32"}); err == nil {
		t.Fatal("expected full subnet")
	}
	if _, err := NextFreeIP([]string{"fd00::1/64"}, nil); err == nil {
		t.Fatal("expected missing IPv4 subnet")
	}
	if _, err := checkAddress("10.8.0.2", []string{"10.8.0.1/24"}, []string{"10.8.0.2/32"}); err == nil {
		t.Fatal("expected taken address")
	}
	if _, err := checkAddress("10.9.0.2", []string{"10.8.0.1/24"}, nil); err == nil {
		t.Fatal("expected address outside subnet")
	}
}

func TestRenderAndParseClient(t *testing.T) {
	spec := ClientSpec{
		Name:         "phone",
		Keys:         Keypair{Private: "client-private", Public: "client-public"},
		PresharedKey: "psk",
		Address:      netip.MustParseAddr("10.8.0.5"),
		DNS:          []string{"1.1.1.1"},
		ServerKey:    "server-public",
		Endpoint:     "vpn.example.org:51820",
		AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
		Keepalive:    25,
		Created:      time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
	}
	conf := RenderClient(spec)
	for _, want := range []string{"PrivateKey = client-private", "Address = 10.8.0.5/32", "PresharedKey = psk", "PersistentKeepalive = 25"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("missing %q in\n%s", want, conf)
		}
	}
	c := ParseClient("phone", conf)
	if c.PublicKey != "client-public" || c.Created != "2026-10-13T12:00:00Z" || c.Endpoint != "vpn.example.org:51820" {
		t.Fatalf("client = %#v", c)
	}
	if len(c.Addresses) != 1 || c.Addresses[0] != "10.8.0.5/32" || len(c.AllowedIPs) != 2 {
		t.Fatalf("client = %#v", c)
	}

	block := RenderServerPeer("phone", "client-public", "psk", spec.Address)
	cfg := ParseConfig(sampleConfig + block)
	if len(cfg.Peers) != 2 || cfg.Peers[1].Name != "phone" || cfg.Peers[1].AllowedIPs[0] != "10.8.0.5/32" {
		t.Fatalf("peers = %#v", cfg.Peers)
	}
}

func TestMergePeers(t *testing.T) {
	conf := []Peer{{Name: "laptop", PublicKey: "a", AllowedIPs: []string{"10.8.0.2/32"}}}
	live := []LivePeer{{PublicKey: "a", RxBytes: 10, TxBytes: 20}, {PublicKey: "b", AllowedIPs: []string{"10.8.0.3/32"}}}
	clients := []Client{{Name: "laptop", PublicKey: "a"}, {Name: "orphan", PublicKey: "c", Addresses: []string{"10.8.0.9/32"}}}
	got := MergePeers(conf, live, clients)
	if len(got) != 3 {
		t.Fatalf("got %#v", got)
	}
	if got[0].ID != "laptop" || !got[0].Live || !got[0].InConfig || got[0].RxBytes != 10 {
		t.Fatalf("first = %#v", got[0])
	}
	if got[1].PublicKey != "b" || got[1].InConfig || got[1].HasClient {
		t.Fatalf("second = %#v", got[1])
	}
	if got[2].ID != "orphan" || got[2].AllowedIPs[0] != "10.8.0.9/32" {
		t.Fatalf("third = %#v", got[2])
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
	if _, err := validDNS("1.1.1.1, nope"); err == nil {
		t.Fatal("accepted bad dns")
	}
	if _, err := validAllowedIPs("0.0.0.0/0\nPostUp = id"); err == nil {
		t.Fatal("accepted injected allowed ips")
	}
	if !validKey(testKey) || validKey("short") {
		t.Fatal("validKey")
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	for _, body := range []string{
		`{"name":"../etc","endpoint":"vpn.example.org:51820"}`,
		`{"name":"phone","endpoint":"vpn.example.org"}`,
		`{"name":"phone","endpoint":"vpn.example.org:51820","dns":"x"}`,
		`{"name":"phone","endpoint":"vpn.example.org:51820","keepalive":-1}`,
		`{"name":"phone","endpoint":"vpn.example.org:51820","publicKey":"not-a-key"}`,
		`{"name":"phone","endpoint":"vpn.example.org:51820","site":true,"publicKey":"aGVsbG8taGVsbG8taGVsbG8taGVsbG8taGVsbG8tISE="}`,
		`{"name":"phone","endpoint":"vpn.example.org:51820","extra":true}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/wireguard/peers", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d body = %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestClientRoutesRejectBadID(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	for _, path := range []string{"/api/plugins/wireguard/peers/..%2Fwg0/config", "/api/plugins/wireguard/peers/a.b/qr"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d body = %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestSendEmailValidatesBeforeReading(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	send := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/plugins/wireguard/peers/godeb-test-missing/send-email", strings.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, body := range []string{
		`{"to":"anna@example.org, bob@example.org"}`,
		`{"to":"anna@example.org\r\nBcc: x@y.z"}`,
		`{"to":"nope"}`,
	} {
		if code := send(body); code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d", body, code)
		}
	}
	if code := send(`{"to":"anna@example.org"}`); code == http.StatusOK || code == http.StatusBadRequest {
		t.Fatalf("missing client: status = %d", code)
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

func TestRenderQRForGeneratedClient(t *testing.T) {
	for _, tool := range []string{"wg", "qrencode"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " nicht installiert")
		}
	}
	ctx := context.Background()
	client, err := GenerateKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server, err := GenerateKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	psk, err := GeneratePresharedKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conf := RenderClient(ClientSpec{
		Name:         "phone",
		Keys:         client,
		PresharedKey: psk,
		Address:      netip.MustParseAddr("10.8.0.2"),
		DNS:          []string{"1.1.1.1"},
		ServerKey:    server.Public,
		Endpoint:     "vpn.example.org:51820",
		AllowedIPs:   []string{"0.0.0.0/0", "::/0"},
		Keepalive:    25,
		Created:      time.Now(),
	})
	png, err := RenderQR(ctx, []byte(conf))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(png), "\x89PNG\r\n\x1a\n") || len(png) < 500 {
		t.Fatalf("no PNG: %d bytes", len(png))
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
