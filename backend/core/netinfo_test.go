package core

import (
	"reflect"
	"testing"
)

func TestParseSSHDPorts(t *testing.T) {
	out := "port 22\naddressfamily any\nport 2222\nport 22\npermitrootlogin without-password\nport 99999\n"
	if got := ParseSSHDPorts(out); !reflect.DeepEqual(got, []int{22, 2222}) {
		t.Fatalf("ports=%v", got)
	}
	if got := ParseSSHDPorts(""); len(got) != 0 {
		t.Fatalf("empty output gave %v", got)
	}
}

func TestSSHConnectionPort(t *testing.T) {
	cases := map[string]int{
		"203.0.113.7 51234 198.51.100.2 22":  22,
		"2001:db8::1 51234 2001:db8::2 2222": 2222,
		"":                                   0,
		"203.0.113.7 51234 198.51.100.2":     0,
		"a b c port":                         0,
	}
	for env, want := range cases {
		if got := SSHConnectionPort(env); got != want {
			t.Errorf("%q: got %d want %d", env, got, want)
		}
	}
}

func TestParseRouteGet(t *testing.T) {
	got := ParseRouteGet("1.1.1.1 via 172.31.1.1 dev eth0 src 203.0.113.7 uid 0 \n    cache \n")
	if got != (Route{Dev: "eth0", Src: "203.0.113.7"}) {
		t.Fatalf("route=%+v", got)
	}
	if got := ParseRouteGet(""); got != (Route{}) {
		t.Fatalf("empty=%+v", got)
	}
}
