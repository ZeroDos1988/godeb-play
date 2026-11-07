package apt

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/core"
	"godebplay/backend/pluginmgr"
)

func init() {
	core.Register("apt", Mount)
	core.RegisterService("apt", runScheduler)
}

// Mount registers the APT routes.
func Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/apt/upgradable", handleStatus)
	mux.HandleFunc("POST /api/plugins/apt/check", handleStart(ActionCheck))
	mux.HandleFunc("POST /api/plugins/apt/security", handleStart(ActionSecurity))
	mux.HandleFunc("POST /api/plugins/apt/upgrade", handleStart(ActionUpgrade))
	mux.HandleFunc("POST /api/plugins/apt/settings", handleSettings)
}

type jobView struct {
	Status
	Running bool     `json:"running"`
	Log     []string `json:"log"`
}

type statusResponse struct {
	core.CommandEnvelope
	Packages  []Package `json:"packages"`
	Security  int       `json:"security"`
	Settings  Settings  `json:"settings"`
	Job       *jobView  `json:"job,omitempty"`
	LastCheck string    `json:"lastCheck,omitempty"`
	NextCheck string    `json:"nextCheck,omitempty"`
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	stdout, env := core.ReadCommand(r.Context(), sampleUpgradable, "apt", "list", "--upgradable")
	resp := statusResponse{CommandEnvelope: env, Packages: ParseUpgradable(stdout)}
	for _, p := range resp.Packages {
		if p.Security {
			resp.Security++
		}
	}
	var err error
	if resp.Settings, err = loadSettings(); err != nil {
		resp.Detail = err.Error()
	}
	if st, ok := readStatus(); ok {
		job := &jobView{Status: st, Running: unitActive(r.Context()), Log: readLog(200)}
		if !job.Running && st.Finished == "" {
			job.Error = "Abgebrochen (Dienst godeb-play-apt beendet ohne Ergebnis)"
		}
		resp.Job = job
	}
	sched.mu.Lock()
	if !sched.lastCheck.IsZero() {
		resp.LastCheck = sched.lastCheck.UTC().Format(time.RFC3339)
		if resp.Settings.AutoCheck {
			resp.NextCheck = sched.lastCheck.Add(time.Duration(resp.Settings.Interval) * time.Minute).UTC().Format(time.RFC3339)
		}
	}
	sched.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, resp)
}

// triggerName is the user written into the status; anything unexpected
// becomes "web".
var triggerName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func handleStart(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trigger := agent.User(r)
		if !triggerName.MatchString(trigger) {
			trigger = "web"
		}
		if action == ActionCheck {
			// With automatic security updates on, a manual check behaves
			// like the scheduled one.
			if s, err := loadSettings(); err == nil && s.AutoCheck && s.AutoSecurity {
				action = ActionSecurity
			}
		}
		if err := startUnit(r.Context(), action, trigger); err != nil {
			core.WriteError(w, http.StatusConflict, err.Error())
			return
		}
		if action == ActionCheck || action == ActionSecurity {
			sched.checked(time.Now())
		}
		core.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true, "action": action})
	}
}

func handleSettings(w http.ResponseWriter, r *http.Request) {
	var s Settings
	if !core.DecodeJSON(w, r, &s) {
		return
	}
	s, err := validSettings(s)
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := saveSettings(s); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	slog.InfoContext(r.Context(), "APT-Automatik geändert", "pruefen", s.AutoCheck, "intervall_min", s.Interval, "sicherheitsupdates", s.AutoSecurity)
	core.WriteJSON(w, http.StatusOK, s)
}

// scheduler remembers when the last check started.
type scheduler struct {
	mu        sync.Mutex
	lastCheck time.Time
}

var sched scheduler

func (s *scheduler) checked(t time.Time) {
	s.mu.Lock()
	s.lastCheck = t
	s.mu.Unlock()
}

// due reports whether the next scheduled check is due.
func (s *scheduler) due(now time.Time, interval time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCheck.IsZero() || now.Sub(s.lastCheck) >= interval
}

// schedTick is how often the scheduler looks at the clock.
const schedTick = time.Minute

// runScheduler checks for updates every Interval minutes and installs
// security updates on its own when AutoSecurity is on. It runs in the
// agent; the work itself runs in godeb-play-apt.service.
func runScheduler(ctx context.Context) {
	// Continue the rhythm across agent restarts (e.g. after a self-update)
	// instead of checking again right away.
	if st, ok := readStatus(); ok {
		if t, err := time.Parse(time.RFC3339, st.Started); err == nil && st.Trigger == "auto" {
			sched.checked(t)
		}
	}
	t := time.NewTicker(schedTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if pluginmgr.IsDisabled("apt") {
			// Switched off in the plugin manager: no automatic installs.
			continue
		}
		s, err := loadSettings()
		if err != nil {
			slog.Warn("APT-Automatik: Einstellungen nicht lesbar", "fehler", err)
			continue
		}
		if !s.AutoCheck || !sched.due(time.Now(), time.Duration(s.Interval)*time.Minute) || unitActive(ctx) {
			continue
		}
		action := ActionCheck
		if s.AutoSecurity {
			action = ActionSecurity
		}
		sched.checked(time.Now())
		if err := startUnit(ctx, action, "auto"); err != nil {
			slog.Warn("APT-Automatik: Prüfung nicht gestartet", "fehler", err)
		}
	}
}
