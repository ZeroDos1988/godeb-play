package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"godebplay/backend/db"
	"godebplay/backend/security"
)

// enrolled sets up user with a confirmed 2FA and returns the secret.
func enrolled(t *testing.T, user string) string {
	t.Helper()
	enr, err := Generate2FASecret(user)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Confirm2FA(user, code(t, enr.Secret)); err != nil || !ok {
		t.Fatalf("confirm: %v %v", ok, err)
	}
	advance(totpPeriod * time.Second)
	return enr.Secret
}

func gateRequest(g *AgentGuard, method, path, user, session, totp string) *httptest.ResponseRecorder {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("X-User", user)
	req.Header.Set("X-Session", session)
	if totp != "" {
		req.Header.Set(StepUpHeader, totp)
	}
	rec := httptest.NewRecorder()
	g.Gate("X-User", "X-Session", next).ServeHTTP(rec, req)
	return rec
}

func TestAgentGateNeedsItsOwnCode(t *testing.T) {
	setup(t)
	secret := enrolled(t, "admin")
	g := NewAgentGuard()

	// Reads pass, changes need a code even though the web process vouches
	// for the session.
	if rec := gateRequest(g, "GET", "/api/plugins/ufw/status", "admin", "s1", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("read: %d", rec.Code)
	}
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "admin", "s1", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("change without code: %d", rec.Code)
	}
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no identity: %d", rec.Code)
	}

	current := code(t, secret)
	rec := gateRequest(g, "POST", "/api/plugins/ufw/rules", "admin", "s1", current)
	if rec.Code != http.StatusNoContent || rec.Header().Get(ElevatedHeader) == "" {
		t.Fatalf("critical with code: %d %v", rec.Code, rec.Header())
	}
	// Replay of the same code is refused, the window covers ordinary actions
	// of this session only.
	if rec := gateRequest(g, "POST", "/api/plugins/ufw/rules", "admin", "s1", current); rec.Code != http.StatusForbidden {
		t.Fatalf("replay: %d", rec.Code)
	}
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "admin", "s1", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("window: %d", rec.Code)
	}
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "admin", "s2", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("window leaked to another session: %d", rec.Code)
	}
	advance(elevationTTL + time.Second)
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "admin", "s1", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("expired window: %d", rec.Code)
	}
}

func TestAgentGateFailuresAndLockout(t *testing.T) {
	setup(t)
	enrolled(t, "admin")
	g := NewAgentGuard()
	var last *httptest.ResponseRecorder
	for i := 0; i < maxCodeAttempts; i++ {
		last = gateRequest(g, "POST", "/api/plugins/ufw/rules", "admin", "s1", "000000")
	}
	if last.Code != http.StatusUnauthorized || last.Header().Get(EndSessionHeader) == "" {
		t.Fatalf("last failure: %d %v", last.Code, last.Header())
	}
	// Brute force across many sessions hits the per-user lock.
	for i := 0; i < userFailureLimit; i++ {
		gateRequest(g, "POST", "/api/plugins/ufw/rules", "admin", "x"+string(rune('a'+i)), "000000")
	}
	if _, _, _, err := g.Check("admin", "s9", "123456"); !errors.Is(err, ErrCodesLocked) {
		t.Fatalf("lock: %v", err)
	}
	advance(userFailureWindow + time.Second)
	if _, _, _, err := g.Check("admin", "s9", "123456"); err != nil {
		t.Fatalf("lock not lifted: %v", err)
	}
}

func TestAgentLoginTicket(t *testing.T) {
	setup(t)
	secret := enrolled(t, "admin")
	g := NewAgentGuard()
	ok, _, _, err := g.Check("admin", "", code(t, secret))
	if err != nil || !ok {
		t.Fatalf("login code: %v %v", ok, err)
	}
	ticket := g.Ticket("admin")
	if g.Bind("other", ticket, "s1") {
		t.Fatal("ticket bound for another user")
	}
	ticket = g.Ticket("admin")
	if !g.Bind("admin", ticket, "s1") || g.Bind("admin", ticket, "s2") {
		t.Fatal("ticket must bind exactly once")
	}
	if rec := gateRequest(g, "POST", "/api/plugins/fail2ban/unban", "admin", "s1", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("window after login: %d", rec.Code)
	}
	stale := g.Ticket("admin")
	advance(ticketTTL + time.Second)
	if g.Bind("admin", stale, "s3") {
		t.Fatal("expired ticket bound")
	}
}

func TestEnrollAllowed(t *testing.T) {
	setup(t)
	// Fresh install: the first account may enroll.
	if ok, err := EnrollAllowed("admin"); err != nil || !ok {
		t.Fatalf("first account: %v %v", ok, err)
	}
	enrolled(t, "admin")
	// Afterwards nobody else without root's grant.
	if ok, _ := EnrollAllowed("mallory"); ok {
		t.Fatal("ungranted enrollment allowed")
	}
	if err := GrantEnrollment("bob"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := EnrollAllowed("bob"); !ok {
		t.Fatal("granted enrollment refused")
	}
	enr, err := Generate2FASecret("bob")
	if err != nil {
		t.Fatal(err)
	}
	// A started enrollment may be continued, and confirming uses up the grant.
	if ok, _ := EnrollAllowed("bob"); !ok {
		t.Fatal("pending enrollment refused")
	}
	if ok, err := Confirm2FA("bob", code(t, enr.Secret)); err != nil || !ok {
		t.Fatalf("confirm bob: %v %v", ok, err)
	}
	conn, _ := twoFactorConn()
	var grants int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM twofa_grants`).Scan(&grants)
	if grants != 0 {
		t.Fatalf("grant left after enrollment: %d", grants)
	}
	// Reset by root grants a new enrollment.
	if err := Reset2FA("bob"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := EnrollAllowed("bob"); !ok {
		t.Fatal("reset must allow a new enrollment")
	}
}

// fakeRemote answers like the agent for an enrollment it holds.
type fakeRemote struct{ fp string }

func (f fakeRemote) Status(string) (bool, string, error)           { return true, f.fp, nil }
func (f fakeRemote) Generate(string) (Enrollment, error)           { return Enrollment{}, nil }
func (f fakeRemote) Confirm(string, string) (bool, error)          { return false, nil }
func (f fakeRemote) Validate(string, string, string) (bool, error) { return false, nil }

func TestScrubLocalSecrets(t *testing.T) {
	setup(t)
	secret := enrolled(t, "admin")
	// One file for web and agent: never scrub.
	if kept, err := ScrubLocalSecrets(fakeRemote{fp: fingerprintOf(secret)}); err != nil || kept != nil {
		t.Fatalf("shared file: kept=%v err=%v", kept, err)
	}
	if ok, _ := Enrolled("admin"); !ok {
		t.Fatal("shared file was scrubbed")
	}
	// Separate files from here on; both hold the enrollment, as after the
	// upgrade copy.
	web := filepath.Join(t.TempDir(), "web.db")
	raw, err := os.ReadFile(db.AgentPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(web, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	key := security.KeyPath() // the upgrade copies the key along
	t.Setenv("GODEB_MASTER_KEY", key)
	t.Setenv("GODEB_AGENT_MASTER_KEY", key)
	t.Setenv("GODEB_AGENT_DB", db.AgentPath())
	t.Setenv("GODEB_DB", web)
	// Wrong fingerprint: the agent does not hold this enrollment, keep it.
	if kept, err := ScrubLocalSecrets(fakeRemote{fp: "other"}); err == nil || len(kept) != 1 {
		t.Fatalf("kept=%v err=%v", kept, err)
	}
	if kept, err := ScrubLocalSecrets(fakeRemote{fp: fingerprintOf(secret)}); err != nil || len(kept) != 0 {
		t.Fatalf("kept=%v err=%v", kept, err)
	}
	conn, _ := ready()
	var left int
	_ = conn.QueryRow(`SELECT COUNT(*) FROM users WHERE totp_secret <> ''`).Scan(&left)
	if left != 0 {
		t.Fatalf("secrets left: %d", left)
	}
	if ok, _ := Enrolled("admin"); !ok {
		t.Fatal("agent database lost the enrollment")
	}
}
