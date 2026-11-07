package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func setup(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "auth")
	t.Setenv("GODEB_AUTH_DIR", dir)
	t.Setenv("GODEB_DB", filepath.Join(root, "godeb.db"))
	clock := time.Unix(1_800_000_000, 0)
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = time.Now })
	return dir
}

func advance(d time.Duration) {
	t := now().Add(d)
	now = func() time.Time { return t }
}

func code(t *testing.T, secret string) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, now(), totpOpts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestImportsLegacyPasswordFile(t *testing.T) {
	dir := setup(t)
	const hash = "$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012"
	raw := []byte("{\n  \"users\": {\n    \"admin\": \"" + hash + "\"\n  }\n}\n")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := passwordHash("admin")
	if err != nil {
		t.Fatal(err)
	}
	if got != hash {
		t.Fatalf("imported hash = %q", got)
	}
}

func TestThemeSettingsRoundTrip(t *testing.T) {
	setup(t)
	if err := SetPassword("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	got, err := loadSettings("admin")
	if err != nil || got.ThemeMode != "system" {
		t.Fatalf("default = %+v err=%v", got, err)
	}
	want := ThemeSettings{ThemeMode: "custom", ColorPrimary: "#112233", ColorBg: "#abcdef", ColorAccent: "#445566", ColorText: "#010203"}
	if err := storeSettings("admin", want); err != nil {
		t.Fatal(err)
	}
	got, err = loadSettings("admin")
	if err != nil || got != want {
		t.Fatalf("stored = %+v err=%v", got, err)
	}

	mux := http.NewServeMux()
	Mount(mux, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/user/settings", strings.NewReader(`{"themeMode":"nope","colorPrimary":"#112233","colorBg":"#abcdef","colorAccent":"#445566","colorText":"#010203"}`))
	rec := httptest.NewRecorder()
	RequireSession(mux).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous settings status = %d", rec.Code)
	}
}

func TestEnrollmentFileModeAndContent(t *testing.T) {
	dir := setup(t)
	enr, err := Generate2FASecret("admin")
	if err != nil {
		t.Fatal(err)
	}
	if len(enr.BackupCodes) != 8 || !strings.HasPrefix(enr.QRCode, "data:image/png;base64,") || enr.Secret == "" {
		t.Fatalf("enrollment = %+v", enr)
	}
	if !strings.HasPrefix(enr.OTPAuthURL, "otpauth://totp/GoDeb:admin") {
		t.Fatalf("url = %s", enr.OTPAuthURL)
	}

	if _, err := os.Stat(filepath.Join(dir, "2fa_admin.json")); !os.IsNotExist(err) {
		t.Fatalf("legacy 2fa file = %v", err)
	}
	info, err := os.Stat(os.Getenv("GODEB_DB"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %v", info.Mode().Perm())
	}
	raw, err := os.ReadFile(os.Getenv("GODEB_DB"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range enr.BackupCodes {
		if strings.Contains(string(raw), c) || strings.Contains(string(raw), strings.ReplaceAll(c, "-", "")) {
			t.Fatal("backup code stored in plain text")
		}
	}
}

func TestConfirmValidateReplayAndBackup(t *testing.T) {
	setup(t)
	enr, err := Generate2FASecret("admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateTOTP("admin", code(t, enr.Secret)); err != ErrNotEnrolled {
		t.Fatalf("unconfirmed validate err = %v", err)
	}
	if ok, err := Confirm2FA("admin", "000000"); ok || err != nil {
		t.Fatalf("wrong confirm ok=%v err=%v", ok, err)
	}
	if ok, err := Confirm2FA("admin", code(t, enr.Secret)); !ok || err != nil {
		t.Fatalf("confirm ok=%v err=%v", ok, err)
	}
	if _, err := Generate2FASecret("admin"); err != ErrAlreadyEnrolled {
		t.Fatalf("re-enroll err = %v", err)
	}

	if ok, _ := ValidateTOTP("admin", code(t, enr.Secret)); ok {
		t.Fatal("same time step accepted twice")
	}
	advance(30 * time.Second)
	if ok, err := ValidateTOTP("admin", code(t, enr.Secret)); !ok || err != nil {
		t.Fatalf("next step ok=%v err=%v", ok, err)
	}

	backup := strings.ToLower(enr.BackupCodes[3])
	if ok, err := ValidateTOTP("admin", backup); !ok || err != nil {
		t.Fatalf("backup ok=%v err=%v", ok, err)
	}
	if ok, _ := ValidateTOTP("admin", backup); ok {
		t.Fatal("backup code reused")
	}
	if ok, _ := ValidateTOTP("admin", "AAAAA-AAAAA"); ok {
		t.Fatal("unknown backup accepted")
	}

	if err := Reset2FA("admin"); err != nil {
		t.Fatal(err)
	}
	if enrolled, _ := Enrolled("admin"); enrolled {
		t.Fatal("still enrolled after reset")
	}
	if err := Reset2FA("admin"); err != ErrNotEnrolled {
		t.Fatalf("second reset err = %v", err)
	}
}

func TestRejectsTraversalUsernames(t *testing.T) {
	setup(t)
	for _, name := range []string{"../x", "Admin", "a/b", "", strings.Repeat("a", 40)} {
		if _, err := Generate2FASecret(name); err != ErrInvalidUsername {
			t.Fatalf("%q err = %v", name, err)
		}
	}
}

type client struct {
	t       *testing.T
	handler http.Handler
	cookies map[string]*http.Cookie
}

func (c *client) do(method, path, body string) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.50:5555"
	for _, cookie := range c.cookies {
		if strings.HasPrefix(path, cookie.Path) {
			req.AddCookie(cookie)
		}
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(c.cookies, cookie.Name)
			continue
		}
		c.cookies[cookie.Name] = cookie
	}
	return rec
}

func TestLoginFlowRequires2FA(t *testing.T) {
	setup(t)
	if err := SetPassword("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	var failures []string
	mux := http.NewServeMux()
	Mount(mux, func(r *http.Request, username string) { failures = append(failures, username) })
	mux.HandleFunc("GET /api/plugins", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	c := &client{t: t, handler: RequireSession(mux), cookies: map[string]*http.Cookie{}}

	if rec := c.do("POST", "/api/auth/login", `{"username":"admin","password":"wrong password!"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad password status = %d", rec.Code)
	}
	if len(failures) != 1 || failures[0] != "admin" {
		t.Fatalf("failures = %v", failures)
	}

	rec := c.do("POST", "/api/auth/login", `{"username":"admin","password":"correct horse battery"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"2fa_required":true`) || !strings.Contains(rec.Body.String(), `"enrollment_required":true`) {
		t.Fatalf("login status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, ok := c.cookies[SessionCookie]; ok {
		t.Fatal("session issued before 2FA")
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("pending cookie opened API: %d", rec.Code)
	}

	rec = c.do("POST", "/api/auth/2fa/enroll", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll status=%d body=%s", rec.Code, rec.Body.String())
	}
	var enr Enrollment
	if err := json.Unmarshal(rec.Body.Bytes(), &enr); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("POST", "/api/auth/2fa/verify", `{"code":"`+code(t, enr.Secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("session did not open API: %d", rec.Code)
	}

	c.do("POST", "/api/auth/logout", "")
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("logout kept access: %d", rec.Code)
	}

	advance(time.Minute)
	rec = c.do("POST", "/api/auth/login", `{"username":"admin","password":"correct horse battery"}`)
	if !strings.Contains(rec.Body.String(), `"enrollment_required":false`) {
		t.Fatalf("second login body=%s", rec.Body.String())
	}
	if rec := c.do("POST", "/api/auth/2fa/enroll", ""); rec.Code != http.StatusConflict {
		t.Fatalf("re-enroll status=%d", rec.Code)
	}
	if rec := c.do("POST", "/api/auth/2fa/authenticate", `{"code":"123456"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code status=%d", rec.Code)
	}
	if len(failures) != 2 {
		t.Fatalf("failures = %v", failures)
	}
	if rec := c.do("POST", "/api/auth/2fa/authenticate", `{"code":"`+code(t, enr.Secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("authenticate status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := c.do("GET", "/api/auth/me", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("me status=%d body=%s", rec.Code, rec.Body.String())
	}

	if err := Reset2FA("admin"); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived 2FA reset: %d", rec.Code)
	}
}

func TestRequireSessionPathsAndOrigin(t *testing.T) {
	setup(t)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := RequireSession(next)
	cases := map[string]int{
		"/":                                  http.StatusNoContent,
		"/assets/app.js":                     http.StatusNoContent,
		"/api/health":                        http.StatusNoContent,
		"/api/trusted":                       http.StatusUnauthorized,
		"/api/plugins/wireguard/trust/info":  http.StatusNoContent,
		"/api/plugins/monitor/site":          http.StatusNoContent,
		"/api/plugins/monitor/sites":         http.StatusUnauthorized,
		"/api/plugins/monitor/summary":       http.StatusUnauthorized,
		"/api/plugins/wireguard/trust":       http.StatusUnauthorized,
		"/api/plugins/wireguard/android":     http.StatusNoContent,
		"/api/plugins/wireguard/android/apk": http.StatusNoContent,
		"/api/auth/login":                    http.StatusNoContent,
		"/api/auth/2fa/verify":               http.StatusNoContent,
		"/api/auth/oidc/providers":           http.StatusNoContent,
		"/api/auth/oidc/google/start":        http.StatusNoContent,
		"/api/auth/oidc/microsoft/callback":  http.StatusNoContent,
		"/api/auth/oidc/config":              http.StatusUnauthorized,
		"/api/system":                        http.StatusUnauthorized,
		"/api/auth/me":                       http.StatusUnauthorized,
		"/api/auth/2fa/../../plugins":        http.StatusUnauthorized,
		"/api/plugins/ufw/status":            http.StatusUnauthorized,
	}
	for path, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = path
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s status=%d want=%d", path, rec.Code, want)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "http://godeb.local/api/auth/login", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status=%d", rec.Code)
	}
}

func TestIdentifySameAnswerCountsUnknown(t *testing.T) {
	setup(t)
	identifyDelay = 0
	t.Cleanup(func() { identifyDelay = 300 * time.Millisecond })
	if err := SetPassword("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	var failures []string
	mux := http.NewServeMux()
	Mount(mux, func(r *http.Request, username string) { failures = append(failures, username) })
	c := &client{t: t, handler: RequireSession(mux), cookies: map[string]*http.Cookie{}}

	known := c.do("POST", "/api/auth/identify", `{"username":"admin"}`)
	unknown := c.do("POST", "/api/auth/identify", `{"username":"root"}`)
	invalid := c.do("POST", "/api/auth/identify", `{"username":"a b;c"}`)
	for _, rec := range []*httptest.ResponseRecorder{known, unknown, invalid} {
		if rec.Code != http.StatusOK || rec.Body.String() != known.Body.String() {
			t.Fatalf("answers differ: %d %q vs %q", rec.Code, rec.Body.String(), known.Body.String())
		}
	}
	if len(failures) != 2 || failures[0] != "root" {
		t.Fatalf("unknown names must count as failures, got %v", failures)
	}
	if len(c.cookies) != 0 {
		t.Fatalf("identify must not start a session: %v", c.cookies)
	}
}

func TestIdentifyTakesFixedTime(t *testing.T) {
	setup(t)
	identifyDelay = 50 * time.Millisecond
	t.Cleanup(func() { identifyDelay = 300 * time.Millisecond })
	mux := http.NewServeMux()
	Mount(mux, func(*http.Request, string) {})
	c := &client{t: t, handler: RequireSession(mux), cookies: map[string]*http.Cookie{}}
	start := time.Now()
	c.do("POST", "/api/auth/identify", `{"username":"nobody"}`)
	if d := time.Since(start); d < 50*time.Millisecond {
		t.Fatalf("identify answered after %s, want at least 50ms", d)
	}
}
