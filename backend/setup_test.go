package main

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"godebplay/plugins/wireguard"
)

const joinTestConf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.7:51820
AllowedIPs = 10.8.0.0/24
PersistentKeepalive = 25
`

func joinFrom(t *testing.T, input string) string {
	t.Helper()
	s := &setup{opt: setupOptions{Join: "-"}, in: bufio.NewReader(strings.NewReader(input)), out: io.Discard}
	got, err := s.joinInput()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestJoinInputFromStdin(t *testing.T) {
	code := wireguard.JoinCode(joinTestConf)
	// One pasted line plus Enter: stops without waiting for EOF; the rest
	// of stdin stays for later questions.
	s := &setup{opt: setupOptions{Join: "-"}, in: bufio.NewReader(strings.NewReader(code + "\nnext answer\n")), out: io.Discard}
	got, err := s.joinInput()
	if err != nil || strings.TrimSpace(got) != code {
		t.Fatalf("code line: %q %v", got, err)
	}
	if rest, _ := s.in.ReadString('\n'); rest != "next answer\n" {
		t.Fatalf("read too far, left %q", rest)
	}
	// Wrapped across lines.
	if got := joinFrom(t, code[:50]+"\n"+code[50:]+"\n"); !wireguard.CompleteJoinCode(got) {
		t.Fatalf("wrapped code: %q", got)
	}
	// A pasted file keeps its empty line between the sections up to EOF.
	if got := joinFrom(t, joinTestConf); got != joinTestConf {
		t.Fatalf("file: %q", got)
	}
}
