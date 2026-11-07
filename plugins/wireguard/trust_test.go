package wireguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testTrustKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyB64(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func TestTrustHandlerSignsNonce(t *testing.T) {
	key, pub := testTrustKey(t)
	_, other := testTrustKey(t)
	h := trustHandler(keySource{key})
	nonce := "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/godeb-trust?nonce="+nonce, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		V     int    `json:"v"`
		Nonce string `json:"nonce"`
		Sig   string `json:"sig"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.V != 1 || resp.Nonce != nonce {
		t.Fatalf("resp=%+v", resp)
	}
	if !verifyTrust(pub, nonce, resp.Sig) {
		t.Fatal("signature does not verify with the endpoint key")
	}
	if verifyTrust(other, nonce, resp.Sig) {
		t.Fatal("signature verifies with a foreign key")
	}
	if verifyTrust(pub, nonce+"x", resp.Sig) {
		t.Fatal("signature verifies for another nonce (replay)")
	}
}

func TestTrustHandlerRejects(t *testing.T) {
	key, _ := testTrustKey(t)
	h := trustHandler(keySource{key})
	for _, target := range []string{
		"/godeb-trust",
		"/godeb-trust?nonce=short",
		"/godeb-trust?nonce=" + strings.Repeat("a", 129),
		"/godeb-trust?nonce=abc%20def%20ghi%20jklmnop",
		"/api/plugins/wireguard/peers",
		"/",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s answered 200", target)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/godeb-trust?nonce=Zm9vYmFyYmF6cXV4MTIzNDU2", nil))
	if rec.Code == http.StatusOK {
		t.Error("POST answered 200")
	}
}

func TestTrustInfoValidation(t *testing.T) {
	_, pub := testTrustKey(t)
	ok := TrustInfo{Enabled: true, URL: "http://192.168.1.50:8787/godeb-trust", Key: pub}
	if !ok.valid() {
		t.Fatal("valid info rejected")
	}
	for name, bad := range map[string]TrustInfo{
		"disabled":   {URL: ok.URL, Key: pub},
		"public ip":  {Enabled: true, URL: "http://203.0.113.7:8787/godeb-trust", Key: pub},
		"https path": {Enabled: true, URL: "http://192.168.1.2:8787/evil", Key: pub},
		"hostname":   {Enabled: true, URL: "http://evil.example:8787/godeb-trust", Key: pub},
		"comment":    {Enabled: true, URL: "http://192.168.1.2:8787/godeb-trust\n[Interface]", Key: pub},
		"bad key":    {Enabled: true, URL: ok.URL, Key: "bm9wZQ=="},
		"key inject": {Enabled: true, URL: ok.URL, Key: pub + "\nPostUp = id"},
	} {
		if bad.valid() {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestClientFileCarriesTrust(t *testing.T) {
	_, pub := testTrustKey(t)
	trust := []TrustInfo{{Enabled: true, URL: "http://192.168.1.50:8787/godeb-trust", Key: pub}}
	conf := RenderClient(ClientSpec{
		Name: "phone", Keys: Keypair{Private: testPriv, Public: testPub}, Address: mustAddr("10.8.0.10"),
		ServerKey: testPub, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"10.8.0.0/24"},
		Created: time.Unix(0, 0), Trust: trust,
	})
	want := "# GoDeb-Trusted-Endpoint: http://192.168.1.50:8787/godeb-trust\n# GoDeb-Trusted-Key: " + pub + "\n[Interface]"
	if !strings.Contains(conf, want) {
		t.Fatalf("client file:\n%s", conf)
	}
	// wg-quick and the WireGuard parser ignore comment lines.
	if cfg := ParseConfig(conf); len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint != "203.0.113.7:51820" {
		t.Fatalf("parsed %+v", cfg)
	}
	// Re-syncing with a new key replaces, never duplicates, the lines.
	_, pub2 := testTrustKey(t)
	next := replaceTrustComments(conf, []TrustInfo{{Enabled: true, URL: trust[0].URL, Key: pub2}})
	if strings.Count(next, "GoDeb-Trusted-Key") != 1 || !strings.Contains(next, pub2) || strings.Contains(next, pub) {
		t.Fatalf("resynced:\n%s", next)
	}
	if cleared := replaceTrustComments(next, nil); strings.Contains(cleared, "GoDeb-Trusted") {
		t.Fatalf("cleared:\n%s", cleared)
	}
}

// keySource signs with a fixed key, like the agent does for the web process.
type keySource struct{ key *ecdsa.PrivateKey }

func (k keySource) Config(context.Context) (TrustConfig, error) { return TrustConfig{}, nil }

func (k keySource) Sign(_ context.Context, nonce string) (string, error) {
	return signTrust(k.key, nonce)
}
