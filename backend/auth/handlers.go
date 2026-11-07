package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"godebplay/backend/core"
)

// FailureFunc records a failed password or 2FA attempt.
type FailureFunc func(r *http.Request, username string)

type handlers struct {
	fail FailureFunc
}

// onFailure is the FailureFunc of the last Mount; RequireSession uses it for
// wrong step-up codes.
var onFailure FailureFunc = func(r *http.Request, username string) {
	slog.Warn("Anmeldung fehlgeschlagen", "benutzer", username, "ip", core.ClientIP(r))
}

// Mount registers the /api/auth routes. fail is called for every rejected
// password, TOTP or backup code.
func Mount(mux *http.ServeMux, fail FailureFunc) {
	if fail != nil {
		onFailure = fail
	}
	h := handlers{fail: onFailure}
	mux.HandleFunc("POST /api/auth/identify", h.identify)
	mux.HandleFunc("POST /api/auth/login", h.login)
	mux.HandleFunc("POST /api/auth/2fa/enroll", h.enroll)
	mux.HandleFunc("POST /api/auth/2fa/verify", h.verify)
	mux.HandleFunc("POST /api/auth/2fa/authenticate", h.authenticate)
	mux.HandleFunc("POST /api/auth/logout", h.logout)
	mux.HandleFunc("GET /api/auth/me", h.me)
	mux.HandleFunc("GET /api/auth/sessions", h.listSessions)
	mux.HandleFunc("POST /api/auth/sessions/{id}/revoke", h.revokeSession)
	mux.HandleFunc("POST /api/auth/sessions/revoke-others", h.revokeOthers)
	mux.HandleFunc("GET /api/auth/oidc/providers", h.listOIDCProviders)
	mux.HandleFunc("GET /api/auth/oidc/config", h.getOIDCConfig)
	mux.HandleFunc("PUT /api/auth/oidc/providers/{id}", h.saveOIDCConfig)
	mux.HandleFunc("GET /api/auth/oidc/{id}/start", h.startOIDC)
	mux.HandleFunc("GET /api/auth/oidc/{id}/callback", h.callbackOIDC)
	mux.HandleFunc("GET /api/auth/oidc/resume", h.resumeOIDC)
	mux.HandleFunc("GET /api/user/settings", h.getSettings)
	mux.HandleFunc("POST /api/user/settings", h.saveSettings)
}

var sessionIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type codeRequest struct {
	Code string `json:"code"`
}

// identifyDelay is the least time /api/auth/identify takes. An unknown name
// also writes to auth.log; the fixed duration keeps that from telling
// known and unknown names apart. Tests set it to 0.
var identifyDelay = 300 * time.Millisecond

// identify is the first of the three login steps (name, password, code).
// An unknown name counts as a failed login for fail2ban right away, but the
// answer is the same for every name: telling "no such user" would let
// anyone collect the valid names and then only guess passwords.
func (h handlers) identify(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	start := time.Now()
	var req struct {
		Username string `json:"username"`
	}
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	exists, err := UserExists(username)
	if err != nil && !errors.Is(err, ErrInvalidUsername) {
		core.WriteError(w, http.StatusInternalServerError, "Benutzerdaten nicht lesbar")
		return
	}
	if !exists {
		h.fail(r, username)
	}
	if wait := identifyDelay - time.Since(start); wait > 0 {
		select {
		case <-time.After(wait):
		case <-r.Context().Done():
			return
		}
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h handlers) login(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	var req loginRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	username := strings.TrimSpace(req.Username)
	hash, ok := CheckPassword(username, req.Password)
	if !ok {
		h.fail(r, username)
		core.WriteError(w, http.StatusUnauthorized, "Benutzername oder Passwort falsch")
		return
	}
	enrolled, _, err := secondFactor.Status(username)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "2FA-Status nicht lesbar")
		return
	}
	token, err := startSession(r, username, stagePending, version(hash, ""), pendingTTL)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzung konnte nicht erstellt werden")
		return
	}
	setCookie(w, r, PendingCookie, token, pendingPath, pendingTTL)
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"2fa_required":        true,
		"enrollment_required": !enrolled,
	})
}

func (h handlers) enroll(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pending, err := pendingSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Bitte zuerst mit Passwort anmelden")
		return
	}
	enrollment, err := secondFactor.Generate(pending.Username)
	if errors.Is(err, ErrAlreadyEnrolled) {
		core.WriteError(w, http.StatusConflict, "2FA ist bereits eingerichtet")
		return
	}
	if errors.Is(err, ErrEnrollForbidden) {
		core.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "2FA konnte nicht eingerichtet werden")
		return
	}
	core.WriteJSON(w, http.StatusOK, enrollment)
}

func (h handlers) verify(w http.ResponseWriter, r *http.Request) {
	h.finish(w, r, secondFactor.Confirm)
}

func (h handlers) authenticate(w http.ResponseWriter, r *http.Request) {
	h.finish(w, r, func(username, code string) (bool, error) {
		return secondFactor.Validate(username, code, "")
	})
}

// finish checks the second factor and swaps the pending cookie for a session.
func (h handlers) finish(w http.ResponseWriter, r *http.Request, check func(username, code string) (bool, error)) {
	noStore(w)
	pending, err := pendingSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Bitte zuerst mit Passwort anmelden")
		return
	}
	username := pending.Username
	var req codeRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	ok, err := check(username, req.Code)
	switch {
	case errors.Is(err, ErrNotEnrolled):
		core.WriteError(w, http.StatusConflict, "2FA ist noch nicht eingerichtet")
		return
	case errors.Is(err, ErrAlreadyEnrolled):
		core.WriteError(w, http.StatusConflict, "2FA ist bereits eingerichtet")
		return
	case errors.Is(err, ErrCodesLocked):
		core.WriteError(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		core.WriteError(w, http.StatusInternalServerError, "2FA-Daten nicht lesbar")
		return
	case !ok:
		h.fail(r, username)
		left, err := recordFailure(pending.ID)
		if errors.Is(err, errTooManyAttempts) {
			clearCookie(w, r, PendingCookie, pendingPath)
			core.WriteError(w, http.StatusTooManyRequests, "Zu viele falsche Codes. Bitte erneut mit Passwort anmelden.")
			return
		}
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, "Sitzung nicht lesbar")
			return
		}
		core.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "Code ungültig", "remaining": left})
		return
	}

	hash, err := passwordHash(username)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Benutzer existiert nicht mehr")
		return
	}
	_, fp, err := secondFactor.Status(username)
	if err != nil || fp == "" {
		core.WriteError(w, http.StatusInternalServerError, "2FA-Daten nicht lesbar")
		return
	}
	token, err := startSession(r, username, stageFull, version(hash, fp), sessionTTL)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzung konnte nicht erstellt werden")
		return
	}
	// The login itself just checked a code, so the step-up window starts open.
	if c, err := parse(token, stageFull); err == nil {
		_ = elevate(sessionKey(c.ID), now().Add(elevationTTL))
		if b, ok := secondFactor.(LoginBinder); ok {
			b.BindLogin(username, sessionKey(c.ID))
		}
	}
	_ = deleteSession(pending.ID)
	clearCookie(w, r, PendingCookie, pendingPath)
	setCookie(w, r, SessionCookie, token, "/", sessionTTL)
	slog.Info("Anmeldung erfolgreich", "benutzer", username, "ip", core.ClientIP(r))
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "username": username})
}

func (h handlers) logout(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if s, err := currentSession(r); err == nil {
		_ = deleteSession(s.ID)
		slog.Info("Abmeldung", "benutzer", s.Username, "ip", core.ClientIP(r))
	}
	if s, err := pendingSession(r); err == nil {
		_ = deleteSession(s.ID)
	}
	clearCookie(w, r, PendingCookie, pendingPath)
	clearCookie(w, r, SessionCookie, "/")
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h handlers) me(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s, err := currentSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	res := map[string]any{"username": s.Username}
	if now().Before(s.ElevatedUntil) {
		res["elevated_until"] = s.ElevatedUntil
	}
	core.WriteJSON(w, http.StatusOK, res)
}

func (h handlers) listSessions(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s, err := currentSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	list, err := ListSessions(s.Username, s.ID)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzungen nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (h handlers) revokeSession(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s, err := currentSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	id := r.PathValue("id")
	if !sessionIDPattern.MatchString(id) {
		core.WriteError(w, http.StatusBadRequest, "Ungültige Sitzungs-ID")
		return
	}
	found, err := RevokeSession(s.Username, id)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzung nicht beendet")
		return
	}
	if !found {
		core.WriteError(w, http.StatusNotFound, "Sitzung nicht gefunden")
		return
	}
	if id == s.ID {
		clearCookie(w, r, SessionCookie, "/")
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h handlers) revokeOthers(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s, err := currentSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	n, err := RevokeSessions(s.Username, s.ID)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzungen nicht beendet")
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": n})
}

// RequireSession rejects /api requests without a full 2FA session. The SPA,
// the health check and the login steps stay reachable. State-changing
// requests from a foreign Origin are refused. Admin actions additionally need
// a recent or fresh 2FA code (see stepUpFor).
func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !sameOrigin(r) {
			core.WriteError(w, http.StatusForbidden, "Fremde Herkunft abgelehnt")
			return
		}
		if !protected(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		s, err := currentSession(r)
		if err != nil {
			core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
			return
		}
		level := stepUpFor(r.Method, r.URL.Path)
		if stepUpElsewhere(r.URL.Path) {
			// The agent checks the TOTP itself. Passwords live in the web
			// database, so critical actions still need the password here;
			// checkCriticalPassword strips the header before the proxy.
			if !checkCriticalPassword(w, r, s, level) {
				return
			}
		} else if !checkStepUp(w, r, s, level) {
			return
		}
		touchSession(s)
		next.ServeHTTP(w, r)
	})
}

func protected(raw string) bool {
	p := path.Clean("/" + raw)
	if p != "/api" && !strings.HasPrefix(p, "/api/") {
		return false
	}
	switch p {
	// setup/status tells the UI whether to show the wizard; setup/admin needs
	// the one-time token and only works until the first account exists.
	case "/api/setup/status", "/api/setup/admin":
		return false
	case "/api/health",
		// identify: first login step, same answer for every name (see identify).
		"/api/auth/identify", "/api/auth/login", "/api/auth/logout", "/api/auth/oidc/providers", "/api/auth/oidc/resume":
		return false
	}
	// monitor/site: health summary of a site for its hub. The agent answers
	// only requests from the hub's tunnel address (WireGuard binds that
	// address to the hub's key) and only on a peer; everyone else gets 404.
	if p == "/api/plugins/monitor/site" {
		return false
	}
	if strings.HasPrefix(p, "/api/auth/oidc/") && (strings.HasSuffix(p, "/start") || strings.HasSuffix(p, "/callback")) {
		return false
	}
	return !strings.HasPrefix(p, pendingPath+"/")
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}
