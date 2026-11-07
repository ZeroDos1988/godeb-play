package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"godebplay/backend/core"
	"godebplay/backend/mail"
	"godebplay/backend/metrics"
)

// Alerts tell the admin about new and resolved findings by mail (the SMTP
// account of /etc/godeb-play/smtp.json) and/or a push message to an ntfy topic.
// The settings live in /etc/godeb-play (root): they decide where the agent sends
// data, so the web process must not be able to change them.
const alertsPath = "/etc/godeb-play/monitor-alerts.json"

const (
	alertFlush  = 30 * time.Second
	alertRepeat = 6 * time.Hour
)

// AlertSettings is monitor-alerts.json.
type AlertSettings struct {
	Enabled  bool   `json:"enabled"`
	Email    string `json:"email"`
	Ntfy     string `json:"ntfy"`  // https://ntfy.sh/<topic> or an own server
	Level    string `json:"level"` // warning or critical
	Resolved bool   `json:"resolved"`
}

func init() {
	extraRoutes = append(extraRoutes, func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/monitor/alerts", handleGetAlerts)
		mux.HandleFunc("POST /api/plugins/monitor/alerts", handleSaveAlerts)
		mux.HandleFunc("POST /api/plugins/monitor/alerts/test", handleTestAlert)
	})
	extraServices = append(extraServices, runAlerts)
	findingHook = queueAlert
}

func loadAlerts() (AlertSettings, error) {
	s := AlertSettings{Level: "warning", Resolved: true}
	data, err := core.ReadAdminFile(alertsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("%s: %w", alertsPath, err)
	}
	return s, nil
}

// ValidateAlerts normalises and checks settings from a request.
func ValidateAlerts(s AlertSettings) (AlertSettings, error) {
	s.Email = strings.TrimSpace(s.Email)
	s.Ntfy = strings.TrimSpace(s.Ntfy)
	if s.Level != "critical" {
		s.Level = "warning"
	}
	if s.Email != "" {
		addr, err := mail.ParseRecipient(s.Email)
		if err != nil {
			return s, err
		}
		s.Email = addr
	}
	if s.Ntfy != "" {
		if err := validNtfy(s.Ntfy); err != nil {
			return s, err
		}
	}
	if s.Enabled && s.Email == "" && s.Ntfy == "" {
		return s, errors.New("Für Alarme eine Mailadresse oder eine ntfy-Adresse angeben")
	}
	return s, nil
}

// validNtfy accepts https URLs with a topic path, without credentials,
// query or fragment.
func validNtfy(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 300 {
		return errors.New("ntfy-Adresse ist ungültig")
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("ntfy-Adresse muss https://server/thema sein, ohne Zugangsdaten")
	}
	topic := strings.Trim(u.Path, "/")
	if topic == "" || strings.ContainsAny(topic, " \t") {
		return errors.New("ntfy-Adresse braucht ein Thema, z. B. https://ntfy.sh/mein-geheimes-thema")
	}
	return nil
}

type alertView struct {
	AlertSettings
	MailReady bool   `json:"mailReady"`
	MailError string `json:"mailError,omitempty"`
}

func handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	s, err := loadAlerts()
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	v := alertView{AlertSettings: s, MailReady: true}
	if _, err := mail.LoadConfig(); err != nil {
		v.MailReady, v.MailError = false, err.Error()
	}
	core.WriteJSON(w, http.StatusOK, v)
}

func handleSaveAlerts(w http.ResponseWriter, r *http.Request) {
	var req AlertSettings
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	s, err := ValidateAlerts(req)
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, _ := json.MarshalIndent(s, "", "  ")
	if err := core.WriteAdminFile(alertsPath, append(raw, '\n'), 0o600); err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	handleGetAlerts(w, r)
}

func handleTestAlert(w http.ResponseWriter, r *http.Request) {
	s, err := loadAlerts()
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Email == "" && s.Ntfy == "" {
		core.WriteError(w, http.StatusBadRequest, "Erst eine Mailadresse oder ntfy-Adresse speichern")
		return
	}
	host, _ := os.Hostname()
	errs := deliver(r.Context(), s, "Testnachricht von GoDeb", "Diese Nachricht kommt von der Überwachung auf "+host+". Alarme kommen auf demselben Weg.", metrics.StatusInfo)
	if len(errs) > 0 {
		core.WriteError(w, http.StatusBadGateway, strings.Join(errs, "; "))
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type alertChange struct {
	old, new *metrics.Finding
}

var (
	alertMu    sync.Mutex
	alertQueue []alertChange
	alertSent  = map[string]alertRecord{}
)

type alertRecord struct {
	status metrics.Status
	at     time.Time
}

func queueAlert(old, new *metrics.Finding) {
	alertMu.Lock()
	defer alertMu.Unlock()
	if len(alertQueue) < 200 {
		alertQueue = append(alertQueue, alertChange{old, new})
	}
}

func runAlerts(ctx context.Context, _ *metrics.Collector, _ *metrics.Store) {
	t := time.NewTicker(alertFlush)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			flushAlerts(ctx)
		}
	}
}

func levelReached(st metrics.Status, level string) bool {
	if level == "critical" {
		return st == metrics.StatusCritical
	}
	return st == metrics.StatusWarning || st == metrics.StatusCritical
}

// PlanAlerts picks the changes worth a message: findings at or above the
// level (again only after alertRepeat or when they got worse) and, if
// wanted, findings that were alarmed and are gone now.
func PlanAlerts(changes []alertChange, s AlertSettings, sent map[string]alertRecord, now time.Time) (problems, resolved []metrics.Finding) {
	for _, c := range changes {
		switch {
		case c.new != nil && levelReached(c.new.Status, s.Level):
			last, ok := sent[c.new.ID]
			if ok && !metrics.Worse(c.new.Status, last.status) && now.Sub(last.at) < alertRepeat {
				continue
			}
			sent[c.new.ID] = alertRecord{c.new.Status, now}
			problems = append(problems, *c.new)
		case c.old != nil && (c.new == nil || !levelReached(c.new.Status, s.Level)):
			if _, ok := sent[c.old.ID]; !ok {
				continue
			}
			delete(sent, c.old.ID)
			if s.Resolved {
				resolved = append(resolved, *c.old)
			}
		}
	}
	return problems, resolved
}

func flushAlerts(ctx context.Context) {
	alertMu.Lock()
	changes := alertQueue
	alertQueue = nil
	alertMu.Unlock()
	if len(changes) == 0 {
		return
	}
	s, err := loadAlerts()
	if err != nil || !s.Enabled {
		return
	}
	alertMu.Lock()
	problems, resolved := PlanAlerts(changes, s, alertSent, time.Now())
	alertMu.Unlock()
	if len(problems) == 0 && len(resolved) == 0 {
		return
	}
	title, body, level := composeAlert(problems, resolved)
	for _, e := range deliver(ctx, s, title, body, level) {
		slog.Warn("Alarm nicht zugestellt", "fehler", e)
	}
}

func composeAlert(problems, resolved []metrics.Finding) (string, string, metrics.Status) {
	host, _ := os.Hostname()
	sort.SliceStable(problems, func(i, j int) bool { return metrics.Worse(problems[i].Status, problems[j].Status) })
	level := metrics.StatusOK
	var b strings.Builder
	for _, f := range problems {
		if metrics.Worse(f.Status, level) {
			level = f.Status
		}
		mark := "Warnung"
		if f.Status == metrics.StatusCritical {
			mark = "Störung"
		}
		fmt.Fprintf(&b, "%s: %s\n", mark, f.Title)
		if f.Detail != "" {
			fmt.Fprintf(&b, "  %s\n", f.Detail)
		}
	}
	for _, f := range resolved {
		fmt.Fprintf(&b, "Behoben: %s\n", f.Title)
	}
	var title string
	switch {
	case len(problems) == 1 && len(resolved) == 0:
		title = problems[0].Title
	case len(problems) == 0 && len(resolved) == 1:
		title = "Behoben: " + resolved[0].Title
	default:
		title = fmt.Sprintf("%d neue Meldungen, %d behoben", len(problems), len(resolved))
	}
	return "[GoDeb " + host + "] " + title, b.String(), level
}

// deliver sends a message on every configured channel and returns errors.
func deliver(ctx context.Context, s AlertSettings, title, body string, level metrics.Status) []string {
	var errs []string
	if s.Email != "" {
		mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := mail.Send(mctx, mail.Message{To: s.Email, Subject: title, Body: body}); err != nil {
			errs = append(errs, "Mail: "+err.Error())
		}
		cancel()
	}
	if s.Ntfy != "" {
		if err := sendNtfy(ctx, s.Ntfy, title, body, level); err != nil {
			errs = append(errs, "ntfy: "+err.Error())
		}
	}
	return errs
}

var ntfyClient = &http.Client{
	Timeout:       10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func sendNtfy(ctx context.Context, target, title, body string, level metrics.Status) error {
	if err := validNtfy(target); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", mime.BEncoding.Encode("utf-8", title))
	switch level {
	case metrics.StatusCritical:
		req.Header.Set("Priority", "high")
		req.Header.Set("Tags", "rotating_light")
	case metrics.StatusWarning:
		req.Header.Set("Tags", "warning")
	default:
		req.Header.Set("Tags", "white_check_mark")
	}
	resp, err := ntfyClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
