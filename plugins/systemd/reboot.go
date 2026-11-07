package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/core"
	"godebplay/backend/doctor"
	"godebplay/backend/pluginmgr"
)

// Reboot from the UI: `shutdown -r +1` with a broadcast, so there is a
// minute to cancel. No power-off: a VPS only comes back through the
// provider's console after that.

const (
	rebootRequiredFile = "/run/reboot-required"
	rebootSettingsPath = "/etc/godeb-play/reboot.json"
	// aptUnit is the transient unit of plugins/apt; never reboot under it.
	aptUnit = "godeb-play-apt.service"
	// autoWindow is how long after the chosen time an automatic reboot may
	// still start (e.g. when an APT run blocked the first minutes).
	autoWindow = time.Hour
	// minUptime keeps a host whose reboot does not clear the flag from
	// rebooting in a loop.
	minUptime = 2 * time.Hour
)

// RebootSettings is reboot.json. It decides when the agent reboots on its
// own, so it lives in /etc/godeb-play (root).
type RebootSettings struct {
	Auto bool   `json:"auto"`
	Time string `json:"time"` // local HH:MM
}

var clockPattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func defaultRebootSettings() RebootSettings {
	return RebootSettings{Auto: false, Time: "04:00"}
}

func loadRebootSettings() (RebootSettings, error) {
	s := defaultRebootSettings()
	data, err := core.ReadAdminFile(rebootSettingsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return defaultRebootSettings(), fmt.Errorf("%s: %w", rebootSettingsPath, err)
	}
	if !clockPattern.MatchString(s.Time) {
		return defaultRebootSettings(), fmt.Errorf("%s: Uhrzeit %q ungültig", rebootSettingsPath, s.Time)
	}
	return s, nil
}

type rebootStatus struct {
	Required  bool           `json:"required"`
	Packages  []string       `json:"packages,omitempty"`
	Scheduled string         `json:"scheduled,omitempty"` // RFC 3339
	Mode      string         `json:"mode,omitempty"`      // reboot, poweroff, …
	Settings  RebootSettings `json:"settings"`
	Detail    string         `json:"detail,omitempty"`
}

func handleRebootStatus(w http.ResponseWriter, r *http.Request) {
	st := rebootStatus{}
	if _, err := os.Stat(rebootRequiredFile); err == nil {
		st.Required = true
		if raw, err := os.ReadFile(rebootRequiredFile + ".pkgs"); err == nil {
			st.Packages = dedupe(strings.Fields(string(raw)))
		}
	}
	if mode, at, ok := doctor.ScheduledShutdown(r.Context(), core.RunQuiet); ok {
		st.Mode = mode
		st.Scheduled = at.UTC().Format(time.RFC3339)
	}
	var err error
	if st.Settings, err = loadRebootSettings(); err != nil {
		st.Detail = err.Error()
	}
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, st)
}

// userName is the account written into the broadcast; anything unexpected
// is left out.
var userName = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func handleReboot(w http.ResponseWriter, r *http.Request) {
	who := agent.User(r)
	if !userName.MatchString(who) {
		who = ""
	}
	if err := scheduleReboot(r.Context(), who); err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	slog.InfoContext(r.Context(), "Neustart geplant", "benutzer", who, "in_min", 1)
	core.WriteJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func handleRebootCancel(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := doctor.ScheduledShutdown(r.Context(), core.RunQuiet); !ok {
		core.WriteError(w, http.StatusConflict, "Es ist kein Neustart geplant")
		return
	}
	if res := core.RunAdmin(r.Context(), "shutdown", "-c", "GoDeb: Neustart abgebrochen"); res.Err != nil {
		core.WriteError(w, http.StatusBadGateway, "shutdown -c: "+res.Detail())
		return
	}
	slog.InfoContext(r.Context(), "Neustart abgebrochen", "benutzer", agent.User(r))
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRebootSettings(w http.ResponseWriter, r *http.Request) {
	var s RebootSettings
	if !core.DecodeJSON(w, r, &s) {
		return
	}
	if !clockPattern.MatchString(s.Time) {
		core.WriteError(w, http.StatusBadRequest, "Uhrzeit im Format HH:MM angeben")
		return
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := core.WriteAdminFile(rebootSettingsPath, append(data, '\n'), 0o600); err != nil {
		core.WriteError(w, http.StatusBadGateway, err.Error())
		return
	}
	slog.InfoContext(r.Context(), "Automatischer Neustart geändert", "an", s.Auto, "uhrzeit", s.Time)
	core.WriteJSON(w, http.StatusOK, s)
}

// scheduleReboot runs `shutdown -r +1`. It refuses while an APT run is
// active: a reboot in the middle of dpkg leaves half-configured packages.
func scheduleReboot(ctx context.Context, who string) error {
	if core.RunQuiet(ctx, "systemctl", "is-active", "--quiet", aptUnit).Err == nil {
		return errors.New("Es läuft gerade eine APT-Aktion. Neustart danach erneut anfordern.")
	}
	msg := "GoDeb: Neustart in einer Minute"
	if who != "" {
		msg += " (angefordert von " + who + ")"
	}
	if res := core.RunAdmin(ctx, "shutdown", "-r", "+1", msg); res.Err != nil {
		return errors.New("shutdown: " + res.Detail())
	}
	return nil
}

// autoRebootDue decides whether the automatic reboot starts now: the option
// is on, the host asks for a reboot, nothing is scheduled yet, the clock is
// within autoWindow after the chosen time, no automatic reboot was scheduled
// in this window before (last; a cancelled one stays cancelled) and the host
// has been up long enough.
func autoRebootDue(s RebootSettings, now, last time.Time, required, scheduled bool, uptime time.Duration) bool {
	if !s.Auto || !required || scheduled || uptime < minUptime {
		return false
	}
	h, m, ok := parseClock(s.Time)
	if !ok {
		return false
	}
	start := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if now.Before(start) {
		// A window that started yesterday may still run past midnight.
		start = start.AddDate(0, 0, -1)
	}
	return now.Sub(start) < autoWindow && last.Before(start)
}

func parseClock(s string) (h, m int, ok bool) {
	if !clockPattern.MatchString(s) {
		return 0, 0, false
	}
	h, _ = strconv.Atoi(s[:2])
	m, _ = strconv.Atoi(s[3:])
	return h, m, true
}

// uptime reads /proc/uptime; on error it reports zero, which blocks the
// automatic reboot.
func uptime() time.Duration {
	raw, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	sec, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0
	}
	return time.Duration(sec * float64(time.Second))
}

// runAutoReboot checks once a minute whether the nightly reboot is due. It
// runs in the agent.
func runAutoReboot(ctx context.Context) {
	// last is when this agent last scheduled an automatic reboot. After the
	// reboot the agent starts fresh, and minUptime covers that case.
	var last time.Time
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if pluginmgr.IsDisabled("systemd") {
			continue
		}
		s, err := loadRebootSettings()
		if err != nil || !s.Auto {
			continue
		}
		_, statErr := os.Stat(rebootRequiredFile)
		_, _, scheduled := doctor.ScheduledShutdown(ctx, core.RunQuiet)
		now := time.Now()
		if !autoRebootDue(s, now, last, statErr == nil, scheduled, uptime()) {
			continue
		}
		if err := scheduleReboot(ctx, "auto"); err != nil {
			slog.Warn("Automatischer Neustart verschoben", "fehler", err)
			continue
		}
		last = now
		slog.Info("Automatischer Neustart geplant", "uhrzeit", s.Time)
	}
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
