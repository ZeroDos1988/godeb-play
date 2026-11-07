package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"godebplay/backend/auth"
)

func TestHealthIsPublicAndAPIRequiresSession(t *testing.T) {
	t.Setenv("GODEB_AUTH_DIR", t.TempDir())
	handler, err := newHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, remote := range []string{"192.0.2.10:1234", "127.0.0.1:1234"} {
		health := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		health.RemoteAddr = remote
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, health)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
			t.Fatalf("health %s status=%d body=%s", remote, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatalf("security headers missing: %v", rec.Header())
		}

		plugins := httptest.NewRequest(http.MethodGet, "/api/plugins", nil)
		plugins.RemoteAddr = remote
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, plugins)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("plugins %s status=%d", remote, rec.Code)
		}
	}
}

func TestCLIPasswdAndReset(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_AUTH_DIR", dir)
	t.Setenv("GODEB_DB", filepath.Join(dir, "godeb.db"))

	var out, errOut bytes.Buffer
	if code := runCLI([]string{"user", "passwd", "admin"}, strings.NewReader("correct horse battery\n"), &out, &errOut); code != 0 {
		t.Fatalf("passwd exit=%d err=%s", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "godeb.db")); err != nil {
		t.Fatal(err)
	}

	if _, err := auth.Generate2FASecret("admin"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := runCLI([]string{"2fa", "reset", "admin"}, nil, &out, &errOut); code != 0 {
		t.Fatalf("reset exit=%d err=%s", code, errOut.String())
	}
	enrolled, err := auth.Enrolled("admin")
	if err != nil || enrolled {
		t.Fatalf("enrolled after reset = %v err=%v", enrolled, err)
	}
	if !strings.Contains(out.String(), "zurückgesetzt") {
		t.Fatalf("out = %q", out.String())
	}

	if code := runCLI([]string{"2fa", "reset", "../etc"}, nil, &out, &errOut); code != 1 {
		t.Fatalf("traversal exit=%d", code)
	}
	if code := runCLI([]string{"bogus"}, nil, &out, &errOut); code != 2 {
		t.Fatalf("usage exit=%d", code)
	}
}
