package wireguard

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRenderServer(t *testing.T) {
	conf := RenderServer(ServerSpec{Address: netip.MustParsePrefix("10.8.0.1/24"), ListenPort: 51820}, testKey)
	cfg := ParseConfig(conf)
	if len(cfg.Interface.Addresses) != 1 || cfg.Interface.Addresses[0] != "10.8.0.1/24" || cfg.Interface.ListenPort != "51820" {
		t.Fatalf("cfg = %+v", cfg.Interface)
	}
	if interfaceValue(conf, "PrivateKey") != testKey || strings.Contains(conf, "PostUp") {
		t.Fatalf("conf = %s", conf)
	}
	next, err := NextFreeIP(cfg.Interface.Addresses, nil)
	if err != nil || next.String() != "10.8.0.2" {
		t.Fatalf("next = %v, %v", next, err)
	}
}
