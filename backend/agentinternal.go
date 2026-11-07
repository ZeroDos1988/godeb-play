package main

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/auth"
	"godebplay/backend/core"
	"godebplay/backend/pluginmgr"
	"godebplay/plugins/wireguard"
)

// mountAgentInternal registers the routes only the web process calls on
// the socket: what it would otherwise read from root-only files.
func mountAgentInternal(mux *http.ServeMux) {
	// Read-only host diagnosis for the overview; never changes the system.
	mux.HandleFunc("GET /internal/doctor", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		core.WriteJSON(w, http.StatusOK, runDoctorReport(r.Context()))
	})
	mux.HandleFunc("GET /internal/plugins/disabled", func(w http.ResponseWriter, r *http.Request) {
		ids, err := pluginmgr.DisabledIDs()
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		core.WriteJSON(w, http.StatusOK, map[string]any{"disabled": ids})
	})
	mux.HandleFunc("GET /internal/trust/config", func(w http.ResponseWriter, r *http.Request) {
		cfg, err := wireguard.TrustSettings()
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		core.WriteJSON(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("POST /internal/trust/sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Nonce string `json:"nonce"`
		}
		if !core.DecodeJSON(w, r, &req) {
			return
		}
		sig, err := wireguard.TrustSign(req.Nonce)
		if err != nil {
			core.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		core.WriteJSON(w, http.StatusOK, map[string]string{"sig": sig})
	})
}

// agentTrust is the web process's view of the trusted endpoint: config and
// signatures come from the agent, the key stays root-only.
type agentTrust struct{ c *agent.Client }

func (a agentTrust) Config(ctx context.Context) (wireguard.TrustConfig, error) {
	var cfg wireguard.TrustConfig
	err := a.c.Call(ctx, http.MethodGet, "/internal/trust/config", nil, &cfg)
	return cfg, err
}

func (a agentTrust) Sign(ctx context.Context, nonce string) (string, error) {
	var resp struct {
		Sig string `json:"sig"`
	}
	err := a.c.Call(ctx, http.MethodPost, "/internal/trust/sign", map[string]string{"nonce": nonce}, &resp)
	return resp.Sig, err
}

// useAgentState points the web process at the agent for data it may not
// read itself.
func useAgentState(c *agent.Client) {
	pluginmgr.SetDisabledSource(func() (map[string]bool, error) {
		var resp struct {
			Disabled map[string]bool `json:"disabled"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := c.Call(ctx, http.MethodGet, "/internal/plugins/disabled", nil, &resp)
		return resp.Disabled, err
	})
}

// mountAgent2FA registers the second-factor routes. There is deliberately
// no reset route: resetting 2FA stays with root on the command line.
func mountAgent2FA(mux *http.ServeMux, guard *auth.AgentGuard) {
	type req struct {
		User    string `json:"user"`
		Code    string `json:"code"`
		Session string `json:"session"`
	}
	decode := func(w http.ResponseWriter, r *http.Request) (req, bool) {
		var q req
		if !core.DecodeJSON(w, r, &q) {
			return q, false
		}
		if !auth.ValidUsername(q.User) {
			core.WriteError(w, http.StatusBadRequest, auth.ErrInvalidUsername.Error())
			return q, false
		}
		return q, true
	}
	mux.HandleFunc("GET /internal/2fa/status", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if !auth.ValidUsername(user) {
			core.WriteError(w, http.StatusBadRequest, auth.ErrInvalidUsername.Error())
			return
		}
		enrolled, fp, err := auth.LocalSecondFactor().Status(user)
		if err != nil {
			writeAgent2FAError(w, err)
			return
		}
		core.WriteJSON(w, http.StatusOK, map[string]any{"enrolled": enrolled, "fingerprint": fp})
	})
	mux.HandleFunc("POST /internal/2fa/enroll", func(w http.ResponseWriter, r *http.Request) {
		q, ok := decode(w, r)
		if !ok {
			return
		}
		allowed, err := auth.EnrollAllowed(q.User)
		if err == nil && !allowed {
			err = auth.ErrEnrollForbidden
		}
		var e auth.Enrollment
		if err == nil {
			e, err = auth.LocalSecondFactor().Generate(q.User)
		}
		if err != nil {
			writeAgent2FAError(w, err)
			return
		}
		core.WriteJSON(w, http.StatusOK, e)
	})
	mux.HandleFunc("POST /internal/2fa/confirm", func(w http.ResponseWriter, r *http.Request) {
		q, ok := decode(w, r)
		if !ok {
			return
		}
		valid, err := auth.LocalSecondFactor().Confirm(q.User, q.Code)
		if err != nil {
			writeAgent2FAError(w, err)
			return
		}
		resp := map[string]any{"ok": valid}
		if valid {
			resp["ticket"] = guard.Ticket(q.User)
		}
		core.WriteJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /internal/2fa/validate", func(w http.ResponseWriter, r *http.Request) {
		q, ok := decode(w, r)
		if !ok {
			return
		}
		valid, _, _, err := guard.Check(q.User, q.Session, q.Code)
		if err != nil {
			writeAgent2FAError(w, err)
			return
		}
		resp := map[string]any{"ok": valid}
		if valid && q.Session == "" {
			resp["ticket"] = guard.Ticket(q.User)
		}
		core.WriteJSON(w, http.StatusOK, resp)
	})
	mux.HandleFunc("POST /internal/2fa/bind", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			User    string `json:"user"`
			Ticket  string `json:"ticket"`
			Session string `json:"session"`
		}
		if !core.DecodeJSON(w, r, &q) {
			return
		}
		core.WriteJSON(w, http.StatusOK, map[string]bool{"ok": guard.Bind(q.User, q.Ticket, q.Session)})
	})
}

// agent2FAErrors map errors to codes so the web process can tell them apart.
var agent2FAErrors = map[string]error{
	"not_enrolled":     auth.ErrNotEnrolled,
	"already_enrolled": auth.ErrAlreadyEnrolled,
	"enroll_forbidden": auth.ErrEnrollForbidden,
	"locked":           auth.ErrCodesLocked,
}

func writeAgent2FAError(w http.ResponseWriter, err error) {
	for code, known := range agent2FAErrors {
		if errors.Is(err, known) {
			core.WriteJSON(w, http.StatusConflict, map[string]string{"error": known.Error(), "code": code})
			return
		}
	}
	core.WriteError(w, http.StatusInternalServerError, err.Error())
}

// agentSecondFactor is the web process's 2FA: every question goes to the
// agent, which holds the secrets. Status is asked on every request (session
// binding) and cached briefly.
type agentSecondFactor struct {
	c       *agent.Client
	mu      sync.Mutex
	cache   map[string]statusEntry
	tickets map[string]string // user -> login ticket from the last code
}

type statusEntry struct {
	enrolled bool
	fp       string
	at       time.Time
}

const statusTTL = 5 * time.Second

func newAgentSecondFactor(c *agent.Client) *agentSecondFactor {
	return &agentSecondFactor{c: c, cache: map[string]statusEntry{}, tickets: map[string]string{}}
}

func (a *agentSecondFactor) call(method, path string, body, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := a.c.Call(ctx, method, path, body, out)
	if err != nil {
		for _, known := range agent2FAErrors {
			if err.Error() == known.Error() {
				return known
			}
		}
	}
	return err
}

func (a *agentSecondFactor) forget(user string) {
	a.mu.Lock()
	delete(a.cache, user)
	a.mu.Unlock()
}

func (a *agentSecondFactor) Status(user string) (bool, string, error) {
	a.mu.Lock()
	e, ok := a.cache[user]
	a.mu.Unlock()
	if ok && time.Since(e.at) < statusTTL {
		return e.enrolled, e.fp, nil
	}
	var resp struct {
		Enrolled    bool   `json:"enrolled"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := a.call(http.MethodGet, "/internal/2fa/status?user="+url.QueryEscape(user), nil, &resp); err != nil {
		return false, "", err
	}
	a.mu.Lock()
	a.cache[user] = statusEntry{enrolled: resp.Enrolled, fp: resp.Fingerprint, at: time.Now()}
	a.mu.Unlock()
	return resp.Enrolled, resp.Fingerprint, nil
}

func (a *agentSecondFactor) Generate(user string) (auth.Enrollment, error) {
	var e auth.Enrollment
	err := a.call(http.MethodPost, "/internal/2fa/enroll", map[string]string{"user": user}, &e)
	return e, err
}

type codeResult struct {
	OK     bool   `json:"ok"`
	Ticket string `json:"ticket"`
}

func (a *agentSecondFactor) keepTicket(user string, resp codeResult) {
	if resp.Ticket != "" {
		a.mu.Lock()
		a.tickets[user] = resp.Ticket
		a.mu.Unlock()
	}
}

func (a *agentSecondFactor) Confirm(user, code string) (bool, error) {
	defer a.forget(user)
	var resp codeResult
	err := a.call(http.MethodPost, "/internal/2fa/confirm", map[string]string{"user": user, "code": code}, &resp)
	a.keepTicket(user, resp)
	return resp.OK, err
}

func (a *agentSecondFactor) Validate(user, code, session string) (bool, error) {
	var resp codeResult
	err := a.call(http.MethodPost, "/internal/2fa/validate",
		map[string]string{"user": user, "code": code, "session": agent.SessionID(session)}, &resp)
	a.keepTicket(user, resp)
	return resp.OK, err
}

// BindLogin opens the agent's step-up window for the session a login just
// created, with the ticket the agent issued for the login code.
func (a *agentSecondFactor) BindLogin(user, sessionID string) {
	a.mu.Lock()
	ticket := a.tickets[user]
	delete(a.tickets, user)
	a.mu.Unlock()
	if ticket == "" {
		return
	}
	_ = a.call(http.MethodPost, "/internal/2fa/bind",
		map[string]string{"user": user, "ticket": ticket, "session": agent.SessionID(sessionID)}, nil)
}
