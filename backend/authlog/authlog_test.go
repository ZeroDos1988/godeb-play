package authlog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// failregex mirrors scripts/setup-fail2ban.sh with <HOST> replaced by an IP group.
var failregex = regexp.MustCompile(`^.* FAILED_LOGIN ip=(\S+).*$`)

func TestFailedLoginFormatAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "godeb", "auth.log")
	t.Setenv("GODEB_AUTH_LOG", path)
	l := New()
	l.now = func() time.Time { return time.Date(2026, 10, 13, 22, 30, 5, 0, time.Local) }

	l.FailedLogin("192.0.2.7", "admin")
	l.FailedLogin("2001:db8::1", "x ip=203.0.113.1\n[2026-01-01 00:00:00] FAILED_LOGIN ip=198.51.100.1")
	l.FailedLogin("not-an-ip", "admin")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if lines[0] != "[2026-10-13 22:30:05] FAILED_LOGIN ip=192.0.2.7 user=admin" {
		t.Fatalf("line0 = %q", lines[0])
	}
	for i, want := range []string{"192.0.2.7", "2001:db8::1"} {
		m := failregex.FindStringSubmatch(lines[i])
		if m == nil || m[1] != want {
			t.Fatalf("line %d %q matched %v", i, lines[i], m)
		}
	}
	if strings.Contains(lines[1], "ip=203.0.113.1") || strings.Contains(lines[1], "ip=198.51.100.1") {
		t.Fatalf("injection survived: %q", lines[1])
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
}
