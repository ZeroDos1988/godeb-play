package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/logging"
)

// Headers the agent answers with; the web process applies them to its own
// session and removes them before the browser sees the response.
const (
	ElevatedHeader   = "X-GoDeb-Elevated-Until" // unix seconds
	EndSessionHeader = "X-GoDeb-End-Session"
)

const (
	// userFailureLimit wrong codes per user within userFailureWindow lock
	// the user's codes in the agent, whatever the web process claims.
	userFailureLimit  = 10
	userFailureWindow = 15 * time.Minute
)

// ErrCodesLocked is returned while a user is locked after too many wrong codes.
var ErrCodesLocked = errors.New("Zu viele falsche Codes. Bitte in einigen Minuten erneut versuchen.")

// AgentGuard is the agent's own second-factor check. The web process only
// passes user, a session id hash and the code; secrets, step-up windows and
// failure counts live here, so a compromised web process cannot change the
// system without a valid code from the admin.
type AgentGuard struct {
	mu        sync.Mutex
	windows   map[string]time.Time   // session hash -> end of step-up window
	failures  map[string]int         // session hash -> wrong codes in a row
	userFails map[string][]time.Time // user -> recent wrong codes
	tickets   map[string]loginTicket // one-time login tickets
}

// loginTicket proves that a login code was just checked here; the web
// process trades it for the step-up window of the session it then creates.
type loginTicket struct {
	user string
	exp  time.Time
}

const ticketTTL = 30 * time.Second

// NewAgentGuard returns an empty guard.
func NewAgentGuard() *AgentGuard {
	return &AgentGuard{windows: map[string]time.Time{}, failures: map[string]int{}, userFails: map[string][]time.Time{}, tickets: map[string]loginTicket{}}
}

func (g *AgentGuard) locked(user string) bool {
	cut := now().Add(-userFailureWindow)
	recent := g.userFails[user][:0]
	for _, t := range g.userFails[user] {
		if t.After(cut) {
			recent = append(recent, t)
		}
	}
	g.userFails[user] = recent
	return len(recent) >= userFailureLimit
}

// Check validates code for user. On success the step-up window of session
// opens; on failure the counters grow. left is the number of attempts the
// session has before it is ended (0 = end it).
func (g *AgentGuard) Check(user, session, code string) (ok bool, left int, until time.Time, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.locked(user) {
		return false, maxCodeAttempts, time.Time{}, ErrCodesLocked
	}
	ok, err = ValidateTOTP(user, code)
	if err != nil {
		return false, maxCodeAttempts, time.Time{}, err
	}
	if !ok {
		g.userFails[user] = append(g.userFails[user], now())
		if session == "" {
			return false, maxCodeAttempts, time.Time{}, nil
		}
		g.failures[session]++
		left = maxCodeAttempts - g.failures[session]
		if left <= 0 {
			delete(g.failures, session)
			delete(g.windows, session)
			left = 0
		}
		return false, left, time.Time{}, nil
	}
	if session != "" {
		until = now().Add(elevationTTL)
		g.windows[session] = until
		delete(g.failures, session)
	}
	return true, 0, until, nil
}

// Ticket issues a one-time login ticket for user after a code was accepted
// without a session (login or enrollment).
func (g *AgentGuard) Ticket(user string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	for t, v := range g.tickets {
		if now().After(v.exp) {
			delete(g.tickets, t)
		}
	}
	t := randomHex(16)
	g.tickets[t] = loginTicket{user: user, exp: now().Add(ticketTTL)}
	return t
}

// Bind trades a login ticket for the step-up window of session.
func (g *AgentGuard) Bind(user, ticket, session string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.tickets[ticket]
	delete(g.tickets, ticket)
	if !ok || v.user != user || now().After(v.exp) || session == "" {
		return false
	}
	g.windows[session] = now().Add(elevationTTL)
	return true
}

func (g *AgentGuard) elevated(session string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.windows[session]
	if ok && !now().Before(until) {
		delete(g.windows, session)
		return false
	}
	return ok
}

// Gate enforces stepUpFor on requests forwarded by the web process.
// userHeader and sessionHeader name the identity headers the web process
// sets (see package agent).
func (g *AgentGuard) Gate(userHeader, sessionHeader string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		level := stepUpFor(r.Method, r.URL.Path)
		if level == stepUpNone {
			next.ServeHTTP(w, r)
			return
		}
		user, session := r.Header.Get(userHeader), r.Header.Get(sessionHeader)
		if user == "" || session == "" {
			core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
			return
		}
		critical := level == stepUpFresh
		code := strings.TrimSpace(r.Header.Get(StepUpHeader))
		if code == "" {
			if !critical && g.elevated(session) {
				next.ServeHTTP(w, r)
				return
			}
			logging.Annotate(r.Context(), slog.String("2fa", "verlangt"))
			logging.Expected(r.Context())
			noStore(w)
			core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
				Error: "Bestätigung mit 2FA-Code erforderlich", StepUpRequired: true, Critical: critical,
			})
			return
		}
		noStore(w)
		ok, left, until, err := g.Check(user, session, code)
		switch {
		case errors.Is(err, ErrCodesLocked):
			logging.Annotate(r.Context(), slog.String("2fa", "gesperrt"))
			core.WriteError(w, http.StatusTooManyRequests, err.Error())
			return
		case err != nil:
			core.WriteError(w, http.StatusInternalServerError, "2FA-Daten nicht lesbar")
			return
		case !ok && left == 0:
			logging.Annotate(r.Context(), slog.String("2fa", "falsch"), slog.String("sitzung", "beendet"))
			w.Header().Set(EndSessionHeader, "1")
			core.WriteError(w, http.StatusUnauthorized, "Zu viele falsche Codes. Die Sitzung wurde beendet.")
			return
		case !ok:
			logging.Annotate(r.Context(), slog.String("2fa", "falsch"), slog.Int("versuche_übrig", left))
			core.WriteJSON(w, http.StatusForbidden, stepUpResponse{
				Error: "Code ungültig oder bereits verwendet", StepUpRequired: true, Critical: critical, Remaining: left,
			})
			return
		}
		logging.Annotate(r.Context(), slog.String("2fa", "bestätigt"))
		w.Header().Set(ElevatedHeader, strconv.FormatInt(until.Unix(), 10))
		next.ServeHTTP(w, r)
	})
}

// ApplyAgentVerdict mirrors the agent's answer onto the web session: an
// opened step-up window or the end of the session after too many codes.
func ApplyAgentVerdict(sessionID string, h http.Header) {
	if sessionID == "" {
		return
	}
	if h.Get(EndSessionHeader) != "" {
		_ = deleteSession(sessionID)
	} else if v := h.Get(ElevatedHeader); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			until := time.Unix(sec, 0)
			if max := now().Add(elevationTTL); until.After(max) {
				until = max
			}
			_ = elevate(sessionID, until)
		}
	}
	h.Del(EndSessionHeader)
	h.Del(ElevatedHeader)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// LoginBinder is implemented by a SecondFactor that keeps its own step-up
// windows (the agent): after a login the new session gets one there too.
type LoginBinder interface {
	BindLogin(username, sessionID string)
}
