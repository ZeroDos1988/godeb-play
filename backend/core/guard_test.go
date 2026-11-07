package core

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPIgnoresForwardingHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.8:4711"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if got := ClientIP(r); got != "192.0.2.8" {
		t.Fatalf("ip = %q", got)
	}
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := ClientIP(r); got != "2001:db8::1" {
		t.Fatalf("ipv6 = %q", got)
	}
	r.RemoteAddr = "garbage"
	if got := ClientIP(r); got != "" {
		t.Fatalf("garbage = %q", got)
	}
}

func TestReadAdminFileRejectsOtherPaths(t *testing.T) {
	if _, err := ReadAdminFile("/etc/passwd"); err == nil {
		t.Fatal("expected rejection")
	}
	if _, err := ReadAdminFile("/etc/wireguard/../../etc/shadow"); err == nil {
		t.Fatal("expected cleaned path to be rejected")
	}
	for _, path := range []string{"/etc/letsencrypt/live/x.pem", "/etc/wireguard", "/etc/godeb-play/../passwd", "/tmp/x"} {
		if err := WriteAdminFile(path, []byte("x"), 0o600); err == nil {
			t.Fatalf("write to %s accepted", path)
		}
	}
	if _, err := ListAdminDir("/root"); err == nil {
		t.Fatal("expected list rejection")
	}
}
