package auth

import (
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/logging"
)

// StepUpHeader carries a TOTP or backup code that confirms one request.
const StepUpHeader = "X-GoDeb-TOTP"

// PasswordHeader carries the account password for critical (stepUpFresh)
// actions. The web process checks it against the web database and strips
// it before forwarding to the agent; the agent never sees it.
const PasswordHeader = "X-GoDeb-Password"

// elevationTTL is how long a confirmed code covers ordinary admin actions.
const elevationTTL = 5 * time.Minute

type stepUpLevel int

const (
	// stepUpNone: reading, or a change that cannot affect the host.
	stepUpNone stepUpLevel = iota
	// stepUpWindow: a code confirmed within elevationTTL is enough.
	stepUpWindow
	// stepUpFresh: every request needs its own code. Used where one request
	// can open access to the host or install software.
	stepUpFresh
)

// criticalPrefixes always need a fresh code.
var criticalPrefixes = []string{
	"/api/plugin-manager/",      // install, enable and disable plugins (APT, systemd)
	"/api/auth/oidc/providers/", // who may sign in
	"/api/plugins/ufw/",         // firewall rules
	"/api/plugins/systemd/",     // stop/restart any allowed unit, sshd and wg-quick included
	"/api/plugins/portforward/", // exposes ports of a tunnel peer to the internet
	"/api/plugins/mailgateway/setup",
	"/api/plugins/mail/install",     // installs packages, opens ports, rewrites Postfix and Dovecot
	"/api/plugins/mail/clamav",      // installs or removes packages
	"/api/plugins/mail/certificate", // opens port 80 for certbot
	"/api/plugins/cron/",            // scheduled jobs run as root
	"/api/plugins/websites/",        // nginx and PHP, opens ports 80/443
}

// criticalExact always needs a fresh code.
var criticalExact = map[string]bool{
	"/api/plugins/wireguard/peers":      true, // a new peer is a new way into the network
	"/api/plugins/wireguard/join":       true, // replaces how this host reaches the tunnel
	"/api/plugins/wireguard/trust":      true, // decides where phones switch their tunnel off
	"/api/plugins/wireguard/volltunnel": true, // NAT: client internet egress through the hub
	"/api/plugins/apt/upgrade":          true, // installs every pending update, GoDeb included
	"/api/plugins/domains/token":        true, // Cloud-API token that can change every DNS zone
	"/api/plugins/apphttps/enable":      true, // public DNS record and a firewall port on wg0
}

// noStepUp lists state-changing routes that skip the second factor.
var noStepUp = map[string]bool{
	"/api/user/settings":       true, // theme and language of the own account only
	"/api/plugin-manager/scan": true, // re-reads plugin.json files, changes nothing
	// Closing the temporary remote access only takes access away; it must
	// work in one click from the overview, also when no code is at hand.
	"/api/plugins/ufw/remote/close": true,
	// Cancelling a scheduled reboot only stops one; the minute until the
	// reboot is too short to look up a code.
	"/api/plugins/systemd/reboot/cancel": true,
}

// stepUpFor decides how fresh the second factor must be. Every state-changing
// /api request needs at least the window unless it is listed in noStepUp, so
// new plugin routes are covered without opting in. Reads are free except for
// downloads that contain private keys.
func stepUpFor(method, raw string) stepUpLevel {
	p := path.Clean("/" + raw)
	if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions {
		if strings.HasPrefix(p, "/api/plugins/wireguard/peers/") && (strings.HasSuffix(p, "/config") || strings.HasSuffix(p, "/qr") || strings.HasSuffix(p, "/code")) {
			return stepUpWindow
		}
		// The table viewer reads application data (often credentials) as
		// the PostgreSQL superuser.
		if strings.HasPrefix(p, "/api/plugins/postgres/databases/") {
			return stepUpWindow
		}
		return stepUpNone
	}
	if noStepUp[p] {
		return stepUpNone
	}
	if criticalExact[p] {
		return stepUpFresh
	}
	// Dropping a database or role cannot be undone.
	if strings.HasPrefix(p, "/api/plugins/postgres/") && strings.HasSuffix(p, "/delete") {
		return stepUpFresh
	}
	// Publishing DNS through the provider rewrites public records.
	if strings.HasPrefix(p, "/api/plugins/domains/") && strings.HasSuffix(p, "/apply") {
		return stepUpFresh
	}
	for _, prefix := range criticalPrefixes {
		if p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix) {
			return stepUpFresh
		}
	}
	return stepUpWindow
}

type stepUpResponse struct {
	Error            string `json:"error"`
	StepUpRequired   bool   `json:"step_up_required"`
	Critical         bool   `json:"critical"`
	PasswordRequired bool   `json:"password_required,omitempty"`
	Remaining        int    `json:"remaining,omitempty"`
}

// checkCriticalPassword requires the account password for stepUpFresh. It
// runs in the web process (password hashes live in the web database) even
// when the agent checks the TOTP itself. The password is never logged; the
// caller must strip PasswordHeader before forwarding to the agent.
func checkCriticalPassword(w http.ResponseWriter, r *http.Request, s session, level stepUpLevel) bool {
	if level != stepUpFresh {
		return true
	}
	password := r.Header.Get(PasswordHeader)
	if password == "" {
		noStore(w)
		logging.Annotate(r.Context(), slog.String("2fa", "passwort_verlangt"))
		logging.Expected(r.Context())
		core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
			Error:            "Bestätigung mit Passwort und 2FA-Code erforderlich",
			StepUpRequired:   true,
			Critical:         true,
			PasswordRequired: true,
		})
		return false
	}
	if _, ok := CheckPassword(s.Username, password); !ok {
		noStore(w)
		logging.Annotate(r.Context(), slog.String("2fa", "passwort_falsch"))
		onFailure(r, s.Username)
		left, err := recordFailure(s.ID)
		if errors.Is(err, errTooManyAttempts) {
			clearCookie(w, r, SessionCookie, "/")
			core.WriteError(w, http.StatusUnauthorized, "Zu viele Fehlversuche. Die Sitzung wurde beendet.")
			return false
		}
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, "Sitzung nicht lesbar")
			return false
		}
		core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
			Error:            "Passwort falsch",
			StepUpRequired:   true,
			Critical:         true,
			PasswordRequired: true,
			Remaining:        left,
		})
		return false
	}
	// Drop the secret before any downstream handler (agent proxy included).
	r.Header.Del(PasswordHeader)
	return true
}

// checkStepUp enforces the level for s. It writes the response and returns
// false when the request must not proceed. Wrong codes and wrong passwords
// count against the session; the last allowed failure ends it. Critical
// actions need the password first so a wrong password never consumes a code.
func checkStepUp(w http.ResponseWriter, r *http.Request, s session, level stepUpLevel) bool {
	if level == stepUpNone {
		return true
	}
	if !checkCriticalPassword(w, r, s, level) {
		return false
	}
	code := strings.TrimSpace(r.Header.Get(StepUpHeader))
	critical := level == stepUpFresh
	if code == "" {
		if !critical && now().Before(s.ElevatedUntil) {
			return true
		}
		noStore(w)
		logging.Annotate(r.Context(), slog.String("2fa", "verlangt"))
		logging.Expected(r.Context())
		core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
			Error:            "Bestätigung mit 2FA-Code erforderlich",
			StepUpRequired:   true,
			Critical:         critical,
			PasswordRequired: critical,
		})
		return false
	}
	noStore(w)
	ok, err := secondFactor.Validate(s.Username, code, s.ID)
	if errors.Is(err, ErrCodesLocked) {
		logging.Annotate(r.Context(), slog.String("2fa", "gesperrt"))
		core.WriteError(w, http.StatusTooManyRequests, err.Error())
		return false
	}
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "2FA-Daten nicht lesbar")
		return false
	}
	if !ok {
		logging.Annotate(r.Context(), slog.String("2fa", "falsch"))
		onFailure(r, s.Username)
		left, err := recordFailure(s.ID)
		if errors.Is(err, errTooManyAttempts) {
			clearCookie(w, r, SessionCookie, "/")
			core.WriteError(w, http.StatusUnauthorized, "Zu viele falsche Codes. Die Sitzung wurde beendet.")
			return false
		}
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, "Sitzung nicht lesbar")
			return false
		}
		core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
			Error:            "Code ungültig oder bereits verwendet",
			StepUpRequired:   true,
			Critical:         critical,
			PasswordRequired: critical,
			Remaining:        left,
		})
		return false
	}
	logging.Annotate(r.Context(), slog.String("2fa", "bestätigt"))
	if err := elevate(s.ID, now().Add(elevationTTL)); err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Sitzung nicht gespeichert")
		return false
	}
	return true
}
