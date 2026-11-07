package main

import "testing"

func TestParseListen(t *testing.T) {
	specs, err := parseListen("127.0.0.1:8080, wg0:8080,[::1]:9000")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 3 || specs[0].Addr != "127.0.0.1:8080" || specs[1].Iface != "wg0" || specs[1].Port != "8080" || specs[2].Addr != "[::1]:9000" {
		t.Fatalf("specs = %+v", specs)
	}
	for _, bad := range []string{"", "8080", "wg0;rm:8080", "Bad Iface:1"} {
		if _, err := parseListen(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if addr, err := (listenSpec{Iface: "lo", Port: "1"}).resolve(); err != nil || addr != "127.0.0.1:1" {
		t.Fatalf("lo = %q, %v", addr, err)
	}
}
