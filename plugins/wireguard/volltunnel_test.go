package wireguard

import (
	"strings"
	"testing"
)

func TestRenderVolltunnelNft(t *testing.T) {
	out := renderVolltunnelNft("eth0", true)
	for _, want := range []string{
		"table ip godeb_volltunnel\ndelete table ip godeb_volltunnel\n",
		"type nat hook postrouting priority srcnat; policy accept;",
		`iifname "wg0" oifname "eth0" masquerade`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	off := renderVolltunnelNft("eth0", false)
	if strings.Contains(off, "masquerade") || strings.Contains(off, "chain") {
		t.Errorf("disabled must only remove the table:\n%s", off)
	}
}
