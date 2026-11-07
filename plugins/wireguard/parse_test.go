package wireguard

import "testing"

func TestParseConfigRedactsSecrets(t *testing.T) {
	cfg := ParseConfig(sampleConfig + "\nPresharedKey = also-not-real\n")
	if cfg.Interface.ListenPort != "51820" || len(cfg.Interface.Addresses) != 1 {
		t.Fatalf("interface = %#v", cfg.Interface)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].PublicKey != "example-peer-public-key" {
		t.Fatalf("peers = %#v", cfg.Peers)
	}
	if cfg.Peers[0].Endpoint != "203.0.113.10:51820" {
		t.Fatalf("endpoint = %#v", cfg.Peers[0])
	}
	if len(cfg.Redacted) != 2 || cfg.Redacted[0] != "PrivateKey" || cfg.Redacted[1] != "PresharedKey" {
		t.Fatalf("redacted = %#v", cfg.Redacted)
	}
}
