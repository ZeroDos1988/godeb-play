package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func (c *client) doCode(method, path, body, code string) *httptest.ResponseRecorder {
	return c.doAuth(method, path, body, code, "")
}

func (c *client) doAuth(method, path, body, code, password string) *httptest.ResponseRecorder {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.50:5555"
	if code != "" {
		req.Header.Set(StepUpHeader, code)
	}
	if password != "" {
		req.Header.Set(PasswordHeader, password)
	}
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

const testPassword = "correct horse battery"

// signedIn returns a client with a full session and the user's TOTP secret.
func signedIn(t *testing.T, failures *[]string) (*client, string) {
	t.Helper()
	if err := SetPassword("admin", testPassword); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	Mount(mux, func(r *http.Request, username string) { *failures = append(*failures, username) })
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mux.HandleFunc("GET /api/plugins", ok)
	mux.HandleFunc("POST /api/plugins/fail2ban/unban", ok)
	mux.HandleFunc("POST /api/plugins/ufw/rules", ok)
	mux.HandleFunc("GET /api/plugins/wireguard/peers/{id}/config", ok)
	c := &client{t: t, handler: RequireSession(mux), cookies: map[string]*http.Cookie{}}
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)
	var enr Enrollment
	if err := json.Unmarshal(c.do("POST", "/api/auth/2fa/enroll", "").Body.Bytes(), &enr); err != nil {
		t.Fatal(err)
	}
	if rec := c.do("POST", "/api/auth/2fa/verify", `{"code":"`+code(t, enr.Secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", rec.Code, rec.Body.String())
	}
	return c, enr.Secret
}

func TestStepUpLevels(t *testing.T) {
	cases := []struct {
		method, path string
		want         stepUpLevel
	}{
		{"GET", "/api/plugins/ufw/status", stepUpNone},
		{"GET", "/api/plugins/wireguard/peers/laptop/config", stepUpWindow},
		{"GET", "/api/plugins/wireguard/peers/laptop/qr", stepUpWindow},
		{"GET", "/api/plugins/wireguard/peers/heim-vm/code", stepUpWindow},
		{"POST", "/api/plugins/apt/upgrade", stepUpFresh},
		{"POST", "/api/plugins/domains/token", stepUpFresh},
		{"POST", "/api/plugins/domains/domains/example.com/apply", stepUpFresh},
		{"POST", "/api/plugins/domains/domains", stepUpWindow},
		{"POST", "/api/plugins/apt/security", stepUpWindow},
		{"POST", "/api/plugins/apt/settings", stepUpWindow},
		{"POST", "/api/user/settings", stepUpNone},
		{"POST", "/api/plugin-manager/scan", stepUpNone},
		{"POST", "/api/plugins/fail2ban/unban", stepUpWindow},
		{"POST", "/api/plugins/new-plugin/anything", stepUpWindow},
		{"POST", "/api/auth/sessions/revoke-others", stepUpWindow},
		{"POST", "/api/plugin-manager/apt/install", stepUpFresh},
		{"POST", "/api/plugins/ufw/rules", stepUpFresh},
		{"POST", "/api/plugins/ufw/remote", stepUpFresh},
		{"POST", "/api/plugins/ufw/remote/close", stepUpNone},
		{"POST", "/api/plugins/ufw/remote/close/../../remote", stepUpFresh},
		{"POST", "/api/plugins/systemd/reboot/cancel", stepUpNone},
		{"POST", "/api/plugins/systemd/reboot", stepUpFresh},
		{"POST", "/api/plugins/systemd/reboot/settings", stepUpFresh},
		{"POST", "/api/plugins/apphttps/enable", stepUpFresh},
		{"POST", "/api/plugins/apphttps/renew", stepUpWindow},
		{"POST", "/api/plugins/systemd/action", stepUpFresh},
		{"PUT", "/api/auth/oidc/providers/google", stepUpFresh},
		{"POST", "/api/plugins/wireguard/peers", stepUpFresh},
		{"POST", "/api/plugins/wireguard/peers/laptop/send-email", stepUpWindow},
		{"POST", "/api/plugins/x/../ufw/rules", stepUpFresh},
		{"DELETE", "/api/plugins/ufw/rules/3", stepUpFresh},
		{"POST", "/api/plugins/wireguard/join", stepUpFresh},
		{"POST", "/api/plugins/wireguard/trust", stepUpFresh},
		{"POST", "/api/plugins/wireguard/trust/sync", stepUpWindow},
		{"POST", "/api/plugins/portforward/rules", stepUpFresh},
		{"POST", "/api/plugins/cron/jobs", stepUpFresh},
		{"POST", "/api/plugins/cron/jobs/x/delete", stepUpFresh},
		{"POST", "/api/plugins/websites/sites", stepUpFresh},
		{"POST", "/api/plugins/websites/sites/blog/certificate", stepUpFresh},
		{"POST", "/api/plugins/postgres/databases", stepUpWindow},
		{"POST", "/api/plugins/postgres/databases/app/delete", stepUpFresh},
		{"POST", "/api/plugins/postgres/roles/app/delete", stepUpFresh},
		{"GET", "/api/plugins/postgres/databases/app/tables/users", stepUpWindow},
		{"GET", "/api/plugins/postgres/status", stepUpNone},
		{"POST", "/api/plugins/portforward/rules/enshrouded/delete", stepUpFresh},
		{"GET", "/api/plugins/portforward/status", stepUpNone},
	}
	for _, tc := range cases {
		if got := stepUpFor(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s = %d want %d", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestStepUpWindowAndFreshCodes(t *testing.T) {
	setup(t)
	var failures []string
	c, secret := signedIn(t, &failures)

	// The login code opens the window, so ordinary actions work right away.
	if rec := c.do("POST", "/api/plugins/fail2ban/unban", "{}"); rec.Code != http.StatusNoContent {
		t.Fatalf("window after login: %d %s", rec.Code, rec.Body.String())
	}
	// Critical actions never ride on the window and need the password.
	rec := c.do("POST", "/api/plugins/ufw/rules", "{}")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"step_up_required":true`) ||
		!strings.Contains(rec.Body.String(), `"critical":true`) || !strings.Contains(rec.Body.String(), `"password_required":true`) {
		t.Fatalf("critical without password: %d %s", rec.Code, rec.Body.String())
	}

	advance(elevationTTL + time.Second)
	rec = c.do("POST", "/api/plugins/fail2ban/unban", "{}")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"critical":false`) ||
		strings.Contains(rec.Body.String(), `"password_required":true`) {
		t.Fatalf("expired window: %d %s", rec.Code, rec.Body.String())
	}
	if rec := c.do("GET", "/api/plugins/wireguard/peers/laptop/config", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("key download without code: %d", rec.Code)
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("plain read blocked: %d", rec.Code)
	}

	current := code(t, secret)
	if rec := c.doAuth("POST", "/api/plugins/ufw/rules", "{}", current, testPassword); rec.Code != http.StatusNoContent {
		t.Fatalf("critical with password and code: %d %s", rec.Code, rec.Body.String())
	}
	// The same code cannot confirm a second critical action.
	if rec := c.doAuth("POST", "/api/plugins/ufw/rules", "{}", current, testPassword); rec.Code != http.StatusForbidden {
		t.Fatalf("replayed code accepted: %d", rec.Code)
	}
	// But the code opened the window for ordinary actions (no password).
	if rec := c.do("POST", "/api/plugins/fail2ban/unban", "{}"); rec.Code != http.StatusNoContent {
		t.Fatalf("window after step-up: %d", rec.Code)
	}
	if len(failures) != 1 {
		t.Fatalf("failures = %v", failures)
	}
}

func TestStepUpCriticalPassword(t *testing.T) {
	setup(t)
	var failures []string
	c, secret := signedIn(t, &failures)
	// Move past the login code so the next TOTP is unused.
	advance(time.Minute)
	current := code(t, secret)

	// Code alone is not enough for critical actions.
	rec := c.doCode("POST", "/api/plugins/ufw/rules", "{}", current)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"password_required":true`) {
		t.Fatalf("code without password: %d %s", rec.Code, rec.Body.String())
	}

	// A wrong password counts as a failure and must not consume the code.
	rec = c.doAuth("POST", "/api/plugins/ufw/rules", "{}", current, "wrong password!!")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "Passwort falsch") ||
		!strings.Contains(rec.Body.String(), `"password_required":true`) || !strings.Contains(rec.Body.String(), `"remaining":`) {
		t.Fatalf("wrong password: %d %s", rec.Code, rec.Body.String())
	}
	if len(failures) != 1 {
		t.Fatalf("failures after wrong password = %v", failures)
	}
	if rec := c.doAuth("POST", "/api/plugins/ufw/rules", "{}", current, testPassword); rec.Code != http.StatusNoContent {
		t.Fatalf("same code after wrong password: %d %s", rec.Code, rec.Body.String())
	}

	// Window actions still need no password.
	if rec := c.do("POST", "/api/plugins/fail2ban/unban", "{}"); rec.Code != http.StatusNoContent {
		t.Fatalf("window without password: %d %s", rec.Code, rec.Body.String())
	}
}

func TestStepUpFailuresEndSession(t *testing.T) {
	setup(t)
	var failures []string
	c, _ := signedIn(t, &failures)
	for i := 1; i < maxCodeAttempts; i++ {
		rec := c.doAuth("POST", "/api/plugins/ufw/rules", "{}", "000000", testPassword)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"remaining":`) {
			t.Fatalf("attempt %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if rec := c.doAuth("POST", "/api/plugins/ufw/rules", "{}", "000000", testPassword); rec.Code != http.StatusUnauthorized {
		t.Fatalf("last attempt: %d", rec.Code)
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived brute force: %d", rec.Code)
	}
	if len(failures) != maxCodeAttempts {
		t.Fatalf("failures = %d", len(failures))
	}
}

func TestPendingLoginAttemptLimit(t *testing.T) {
	setup(t)
	var failures []string
	_, _ = signedIn(t, &failures)
	mux := http.NewServeMux()
	Mount(mux, nil)
	c := &client{t: t, handler: RequireSession(mux), cookies: map[string]*http.Cookie{}}
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)
	for i := 1; i < maxCodeAttempts; i++ {
		if rec := c.do("POST", "/api/auth/2fa/authenticate", `{"code":"000000"}`); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	if rec := c.do("POST", "/api/auth/2fa/authenticate", `{"code":"000000"}`); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("last attempt: %d", rec.Code)
	}
	if rec := c.do("POST", "/api/auth/2fa/authenticate", `{"code":"000000"}`); rec.Code != http.StatusUnauthorized ||
		!strings.Contains(rec.Body.String(), "Passwort") {
		t.Fatalf("pending login survived: %d %s", rec.Code, rec.Body.String())
	}
}

func TestSessionsRevocable(t *testing.T) {
	setup(t)
	var failures []string
	c, secret := signedIn(t, &failures)

	// A copied cookie stops working once the session is logged out.
	stolen := *c.cookies[SessionCookie]
	c.do("POST", "/api/auth/logout", "")
	thief := &client{t: t, handler: c.handler, cookies: map[string]*http.Cookie{SessionCookie: &stolen}}
	if rec := thief.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out cookie still valid: %d", rec.Code)
	}

	// Two fresh sessions; "end all others" keeps only the caller.
	advance(time.Minute)
	c.do("POST", "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)
	c.do("POST", "/api/auth/2fa/authenticate", `{"code":"`+code(t, secret)+`"}`)
	other := &client{t: t, handler: c.handler, cookies: map[string]*http.Cookie{}}
	advance(time.Minute)
	other.do("POST", "/api/auth/login", `{"username":"admin","password":"`+testPassword+`"}`)
	if rec := other.do("POST", "/api/auth/2fa/authenticate", `{"code":"`+code(t, secret)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("second login: %d %s", rec.Code, rec.Body.String())
	}

	var list struct {
		Sessions []SessionInfo `json:"sessions"`
	}
	if err := json.Unmarshal(c.do("GET", "/api/auth/sessions", "").Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions = %+v", list.Sessions)
	}
	if rec := c.do("POST", "/api/auth/sessions/revoke-others", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"revoked":1`) {
		t.Fatalf("revoke-others: %d %s", rec.Code, rec.Body.String())
	}
	if rec := other.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session still valid: %d", rec.Code)
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("own session revoked: %d", rec.Code)
	}

	if n, err := RevokeSessions("admin", ""); err != nil || n != 1 {
		t.Fatalf("cli revoke n=%d err=%v", n, err)
	}
	if rec := c.do("GET", "/api/plugins", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session survived cli revoke: %d", rec.Code)
	}
}
