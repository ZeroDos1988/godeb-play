package ufw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"

	"godebplay/backend/core"
	"godebplay/backend/db"
	"godebplay/backend/doctor"
	"godebplay/backend/remoteaccess"
)

// Remote access: for a limited time the web UI answers HTTPS on the public
// address (self-signed certificate, login and 2FA as always), so a server
// can be set up before its tunnel works. The agent owns the ufw rule and
// the deadline; the web process serves only before the deadline.
const (
	RemotePort    = remoteaccess.Port
	RemoteDefault = 2 * time.Hour
	RemoteMin     = 15 * time.Minute
	RemoteMax     = 24 * time.Hour
	remoteComment = "GoDeb Fernzugang"
	remoteBase    = "/api/plugins/ufw/remote"
)

func init() {
	doctor.Register(remoteFindings)
}

// remoteRow lives in the agent database: the deadline the agent acts on.
type remoteRow struct {
	ID      int `gorm:"primaryKey"`
	Address string
	Until   string // RFC 3339, empty when closed
}

func (remoteRow) TableName() string { return "ufw_remote" }

var (
	// remoteMu serialises open, close and expiry.
	remoteMu       sync.Mutex
	migrateMu      sync.Mutex
	remoteMigrated = map[string]bool{}
)

func remoteStore() (*gorm.DB, error) {
	gdb, err := db.AgentGorm()
	if err != nil {
		return nil, err
	}
	migrateMu.Lock()
	defer migrateMu.Unlock()
	if path := db.AgentPath(); !remoteMigrated[path] {
		if err := gdb.AutoMigrate(&remoteRow{}); err != nil {
			return nil, err
		}
		remoteMigrated[path] = true
	}
	return gdb, nil
}

func loadRemote() (remoteRow, error) {
	gdb, err := remoteStore()
	if err != nil {
		return remoteRow{}, err
	}
	var row remoteRow
	err = gdb.Where("id = 1").Limit(1).Find(&row).Error
	row.ID = 1
	return row, err
}

func saveRemote(row remoteRow) error {
	gdb, err := remoteStore()
	if err != nil {
		return err
	}
	row.ID = 1
	return gdb.Save(&row).Error
}

// Remote is the state shown in the UI and the CLI.
type Remote struct {
	Open     bool      `json:"open"`
	Address  string    `json:"address,omitempty"`
	Port     int       `json:"port"`
	Until    time.Time `json:"until,omitzero"`
	URL      string    `json:"url,omitempty"`
	PublicIP string    `json:"publicIp,omitempty"`
}

func (row remoteRow) until() time.Time {
	t, _ := time.Parse(time.RFC3339, row.Until)
	return t
}

func (row remoteRow) open(now time.Time) bool {
	return row.Address != "" && now.Before(row.until())
}

// RemoteStatus reports whether the remote access is open.
func RemoteStatus(ctx context.Context) (Remote, error) {
	row, err := loadRemote()
	if err != nil {
		return Remote{}, err
	}
	return remoteView(ctx, row, time.Now()), nil
}

func remoteView(ctx context.Context, row remoteRow, now time.Time) Remote {
	r := Remote{Port: RemotePort, PublicIP: publicAddress(ctx)}
	if row.open(now) {
		r.Open, r.Address, r.Until = true, row.Address, row.until()
		r.URL = "https://" + net.JoinHostPort(row.Address, strconv.Itoa(RemotePort))
	}
	return r
}

// publicAddress is the source address of the default route (the public
// IPv4 of a VPS). Tests replace it.
var publicAddress = func(ctx context.Context) string {
	return core.DefaultRoute(ctx).Src
}

// runRemoteUFW is replaced in tests.
var runRemoteUFW = func(ctx context.Context, args ...string) core.CommandResult {
	return core.RunAdmin(ctx, "ufw", args...)
}

func remoteRule(addr string) []string {
	return []string{"allow", "proto", "tcp", "to", addr, "port", strconv.Itoa(RemotePort)}
}

// OpenRemote opens the access for d (RemoteMin to RemoteMax). Opening again
// sets a new deadline. Web UI and `godeb-play access open` share this function.
func OpenRemote(ctx context.Context, d time.Duration) (Remote, error) {
	if d < RemoteMin || d > RemoteMax {
		return Remote{}, fmt.Errorf("Dauer muss zwischen %s und %s liegen", "15 Minuten", "24 Stunden")
	}
	ip := net.ParseIP(publicAddress(ctx))
	if ip == nil || ip.To4() == nil || ip.IsLoopback() {
		return Remote{}, errors.New("Keine öffentliche IPv4-Adresse gefunden")
	}
	addr := ip.String()
	if res := runRemoteUFW(ctx, "status"); res.Err != nil {
		return Remote{}, errors.New("ufw ist nicht verfügbar; ohne Firewall öffnet GoDeb keinen Fernzugang")
	}
	remoteMu.Lock()
	defer remoteMu.Unlock()
	row, err := loadRemote()
	if err != nil {
		return Remote{}, err
	}
	if row.Address != "" && row.Address != addr {
		_ = runRemoteUFW(ctx, append([]string{"delete"}, remoteRule(row.Address)...)...)
	}
	if res := runRemoteUFW(ctx, append(remoteRule(addr), "comment", remoteComment)...); res.Err != nil {
		return Remote{}, fmt.Errorf("ufw: %s", res.Detail())
	}
	until := time.Now().Add(d).Truncate(time.Second)
	next := remoteRow{Address: addr, Until: until.UTC().Format(time.RFC3339)}
	if err := saveRemote(next); err != nil {
		return Remote{}, err
	}
	if err := remoteaccess.Save(remoteaccess.Access{Address: addr, Port: RemotePort, Until: until}); err != nil {
		return Remote{}, err
	}
	slog.Warn("Fernzugang geöffnet", "adresse", addr, "port", RemotePort, "bis", until.Format(time.DateTime))
	return remoteView(ctx, next, time.Now()), nil
}

// CloseRemote removes the ufw rule and tells the web process to close.
func CloseRemote(ctx context.Context) error {
	return closeRemoteIf(ctx, func(remoteRow) bool { return true })
}

func closeRemoteIf(ctx context.Context, cond func(remoteRow) bool) error {
	remoteMu.Lock()
	defer remoteMu.Unlock()
	row, err := loadRemote()
	if err != nil {
		return err
	}
	if !cond(row) {
		return nil
	}
	if row.Address != "" {
		if res := runRemoteUFW(ctx, append([]string{"delete"}, remoteRule(row.Address)...)...); res.Err != nil {
			slog.Warn("Fernzugang: ufw-Regel nicht entfernt", "fehler", res.Detail())
		}
	}
	if err := saveRemote(remoteRow{}); err != nil {
		return err
	}
	if err := remoteaccess.Save(remoteaccess.Access{}); err != nil {
		return err
	}
	if row.Address != "" {
		slog.Info("Fernzugang geschlossen", "adresse", row.Address)
	}
	return nil
}

// expireRemote closes an access whose deadline has passed. It checks again
// under the lock, so a renewal that just happened is not closed.
func expireRemote(ctx context.Context, now time.Time) {
	row, err := loadRemote()
	if err != nil || row.Address == "" || row.open(now) {
		return
	}
	if err := closeRemoteIf(ctx, func(r remoteRow) bool { return r.Address != "" && !r.open(now) }); err != nil {
		slog.Error("Fernzugang nicht geschlossen", "fehler", err)
	}
}

// WatchRemote closes the access when its time is up, also right after a
// restart. The agent runs it regardless of the plugin manager, so turning
// the plugin off cannot keep the port open.
func WatchRemote(ctx context.Context) {
	for {
		expireRemote(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(20 * time.Second):
		}
	}
}

// remoteFindings warns on the overview while the access is open.
func remoteFindings(ctx context.Context) []doctor.Finding {
	r, err := RemoteStatus(ctx)
	if err != nil || !r.Open {
		return nil
	}
	return []doctor.Finding{{
		Area:  "Fernzugang",
		Level: doctor.Warn,
		Text:  fmt.Sprintf("Weboberfläche von außen erreichbar bis %s (%s)", r.Until.Local().Format("02.01. 15:04"), r.URL),
		Fix:   &core.Fix{Action: "closeRemote", Path: remoteBase + "/close"},
	}}
}

type remoteRequest struct {
	Minutes int `json:"minutes"`
}

func handleRemoteStatus(w http.ResponseWriter, r *http.Request) {
	s, err := RemoteStatus(r.Context())
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, s)
}

func handleRemoteOpen(w http.ResponseWriter, r *http.Request) {
	var req remoteRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	d := RemoteDefault
	if req.Minutes != 0 {
		d = time.Duration(req.Minutes) * time.Minute
	}
	s, err := OpenRemote(r.Context(), d)
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, s)
}

func handleRemoteClose(w http.ResponseWriter, r *http.Request) {
	if err := CloseRemote(r.Context()); err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	handleRemoteStatus(w, r)
}
