package firstrun

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupEnv(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("GODEB_ETC", filepath.Join(root, "etc"))
	t.Setenv("GODEB_AUTH_DIR", filepath.Join(root, "auth"))
	t.Setenv("GODEB_DB", filepath.Join(root, "godeb.db"))
	t.Setenv("GODEB_MASTER_KEY", filepath.Join(root, "master.key"))
	return root
}

func post(mux http.Handler, path, token string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	if token != "" {
		req.Header.Set(TokenHeader, token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestAdminNeedsTokenAndOnlyOnce(t *testing.T) {
	setupEnv(t)
	mux := http.NewServeMux()
	Mount(mux)
	if !Required() {
		t.Fatal("fresh install must require setup")
	}
	tok, err := EnsureToken()
	if err != nil || len(tok) < 30 {
		t.Fatalf("token %q %v", tok, err)
	}
	if again, _ := EnsureToken(); again != tok {
		t.Fatal("token changed on second call")
	}
	if info, err := os.Stat(tokenPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode: %v %v", info, err)
	}
	admin := adminRequest{Username: "admin", Password: "ein-langes-passwort-123"}
	for _, bad := range []string{"", "wrong", tok + "x"} {
		if rec := post(mux, "/api/setup/admin", bad, admin); rec.Code != http.StatusForbidden {
			t.Fatalf("token %q: %d %s", bad, rec.Code, rec.Body)
		}
	}
	if rec := post(mux, "/api/setup/admin", tok, admin); rec.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", rec.Code, rec.Body)
	}
	if rec := post(mux, "/api/setup/admin", tok, adminRequest{Username: "evil", Password: "ein-langes-passwort-456"}); rec.Code != http.StatusConflict {
		t.Fatalf("second admin: %d %s", rec.Code, rec.Body)
	}
	if !Load().Started || !Required() {
		t.Fatalf("state after admin: %+v", Load())
	}
	// A restart in the middle of the wizard must not mark it done.
	Migrate()
	if !Required() {
		t.Fatal("Migrate closed a running wizard")
	}
}

func TestDoneClosesEverything(t *testing.T) {
	setupEnv(t)
	mux := http.NewServeMux()
	Mount(mux)
	tok, _ := EnsureToken()
	if err := MarkDone("peer", AccessTunnel); err != nil {
		t.Fatal(err)
	}
	if Required() {
		t.Fatal("still required")
	}
	if _, err := os.Stat(tokenPath()); !os.IsNotExist(err) {
		t.Fatal("token survived the setup")
	}
	for _, path := range []string{"/api/setup/admin", "/api/setup/join", "/api/setup/finish"} {
		if rec := post(mux, path, tok, map[string]any{}); rec.Code != http.StatusGone {
			t.Errorf("%s after setup: %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/setup/status", nil))
	if !strings.Contains(rec.Body.String(), `"required":false`) {
		t.Fatalf("status %s", rec.Body)
	}
}

func TestMigrateMarksExistingInstall(t *testing.T) {
	setupEnv(t)
	if err := CreateAdmin("admin", "ein-langes-passwort-123"); err != nil {
		t.Fatal(err)
	}
	// Simulate an install from before the wizard: account exists, no
	// setup.json written by the wizard.
	if err := os.Remove(statePath()); err != nil {
		t.Fatal(err)
	}
	Migrate()
	if s := Load(); !s.Done || !s.Legacy {
		t.Fatalf("legacy install not marked: %+v", s)
	}
}

func TestResolveAccess(t *testing.T) {
	setupEnv(t)
	for _, mode := range []string{AccessTunnel, AccessLocal} {
		if c, err := ResolveAccess(mode, "", 0); err != nil || c.Addr() != "" {
			t.Errorf("%s: %+v %v", mode, c, err)
		}
	}
	for name, c := range map[string][3]any{
		"public ip": {AccessLAN, "203.0.113.7", 8443},
		"port 8080": {AccessLAN, "192.168.1.2", 8080},
		"low port":  {AccessLAN, "192.168.1.2", 443},
		"bogus":     {"world", "", 0},
	} {
		if _, err := ResolveAccess(c[0].(string), c[1].(string), c[2].(int)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if LoadAccess().Mode != AccessTunnel {
		t.Fatal("default access must be tunnel-only")
	}
}

func TestFirewallPlanSSHFirst(t *testing.T) {
	p := FirewallPlan{SSHPorts: []int{2222}, WireGuard: 51820, UIPort: 8080, LANIface: "eth0", LANAddress: "192.168.1.2", LANPrefix: "192.168.1.0/24", LANPort: 8443}
	rules := p.Rules()
	if len(rules) != 4 || strings.Join(rules[0], " ") != "allow 2222/tcp comment SSH" {
		t.Fatalf("rules %v", rules)
	}
	if got := strings.Join(rules[3], " "); got != "allow in on eth0 from 192.168.1.0/24 to 192.168.1.2 port 8443 proto tcp comment GoDeb UI im Heimnetz" {
		t.Fatalf("lan rule %s", got)
	}
	peer := FirewallPlan{SSHPorts: []int{22}, UIPort: 8080}
	for _, r := range peer.Rules() {
		if strings.Contains(strings.Join(r, " "), "udp") {
			t.Fatal("a peer must not open a WireGuard port")
		}
	}
}

func TestCertificate(t *testing.T) {
	setupEnv(t)
	cert, fp, err := EnsureCert()
	if err != nil || len(cert.Certificate) == 0 || strings.Count(fp, ":") != 31 {
		t.Fatalf("cert %v fp %q", err, fp)
	}
	if _, fp2, _ := EnsureCert(); fp2 != fp {
		t.Fatal("certificate regenerated")
	}
	if info, _ := os.Stat(keyPath()); info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode())
	}
}
