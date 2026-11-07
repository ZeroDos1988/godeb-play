// Package firstrun is the first-run setup of a fresh GoDeb install: admin
// account, 2FA, WireGuard role and how GoDeb is reached afterwards. The web
// wizard and `godeb-play setup` use the same functions.
//
// Until the setup is done GoDeb also listens on GODEB_SETUP_ADDR (default
// 0.0.0.0:8443) with a self-signed certificate, so a fresh VPS or home server
// can be set up from a browser. Creating the first admin needs the one-time
// token from /var/lib/godeb-play/setup-token (printed by the package and by
// `godeb-play setup-url`), so nobody else can claim a fresh server first. When the
// setup is finished, the public listener closes.
package firstrun

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"godebplay/backend/auth"
	"godebplay/backend/core"
	"godebplay/plugins/wireguard"
)

// State is setup.json in the state directory (/var/lib/godeb-play).
type State struct {
	Done        bool   `json:"done"`
	Started     bool   `json:"started"` // the wizard created the admin
	Role        string `json:"role,omitempty"`
	Access      string `json:"access,omitempty"`
	CompletedAt string `json:"completedAt,omitempty"`
	Legacy      bool   `json:"legacy,omitempty"` // marked done for an install from before the wizard
}

var (
	stateMu  sync.Mutex
	changeFn []func()
)

// OnChange registers a callback for state or access changes; the daemon
// uses it to open or close its extra listeners.
func OnChange(fn func()) {
	stateMu.Lock()
	defer stateMu.Unlock()
	changeFn = append(changeFn, fn)
}

func notify() {
	stateMu.Lock()
	fns := append([]func(){}, changeFn...)
	stateMu.Unlock()
	for _, fn := range fns {
		go fn()
	}
}

// Load reads the state; a missing file is a fresh install.
func Load() State {
	data, err := os.ReadFile(statePath())
	if err != nil {
		return State{}
	}
	var s State
	if json.Unmarshal(data, &s) != nil {
		return State{}
	}
	return s
}

func save(s State) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(statePath(), append(raw, '\n'), 0o600); err != nil {
		return err
	}
	notify()
	return nil
}

// Required reports whether the first-run setup still has to run.
func Required() bool { return !Load().Done }

// Migrate marks an install from before the wizard as set up, so upgrading
// never re-opens the public setup listener on a configured server.
func Migrate() { migrate(true, true) }

// MigrateUsers is the web process's half of Migrate: accounts exist.
func MigrateUsers() { migrate(true, false) }

// MigrateWireGuard is the agent's half: wg0.conf exists (root only).
func MigrateWireGuard() { migrate(false, true) }

func migrate(checkUsers, checkWG bool) {
	s := Load()
	if s.Done || s.Started {
		return
	}
	users := false
	if checkUsers {
		users, _ = auth.HasUsers()
	}
	// Only a readable wg0.conf counts; a read error is no proof of a set-up
	// server and must not hide the wizard.
	wgOK := false
	if checkWG {
		_, wgErr := core.ReadAdminFile(wireguard.ConfigPath())
		wgOK = wgErr == nil
	}
	if !users && !wgOK {
		return
	}
	role, _ := wireguard.CurrentRole()
	s.Done, s.Legacy, s.Role, s.Access = true, true, string(role.Role), "tunnel"
	s.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	_ = save(s)
}

func markStarted() error {
	s := Load()
	s.Started = true
	return save(s)
}

// MarkDone finishes the setup and removes the one-time token.
func MarkDone(role, access string) error {
	s := Load()
	s.Done, s.Started, s.Role, s.Access = true, true, role, access
	s.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if err := save(s); err != nil {
		return err
	}
	_ = os.Remove(tokenPath())
	return nil
}
