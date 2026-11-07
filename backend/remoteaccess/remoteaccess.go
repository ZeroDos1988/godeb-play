// Package remoteaccess is the hand-over of the temporary remote access
// between the agent and the web process: remote.json in the state
// directory. The agent writes it together with the ufw rule and closes both
// when Until has passed; the web process serves only before Until, so the
// listener also closes on time without the agent.
package remoteaccess

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"godebplay/backend/state"
)

// Port is the HTTPS port on the public address, the same as during setup.
const Port = 8443

// Access is the content of remote.json.
type Access struct {
	Address string    `json:"address,omitempty"`
	Port    int       `json:"port,omitempty"`
	Until   time.Time `json:"until,omitzero"`
}

// Path is remote.json in the state directory.
func Path() string { return filepath.Join(state.Dir(), "remote.json") }

// Load reads remote.json; missing or broken means closed.
func Load() Access {
	data, err := os.ReadFile(Path())
	if err != nil {
		return Access{}
	}
	var a Access
	if json.Unmarshal(data, &a) != nil {
		return Access{}
	}
	return a
}

// Addr is the public HTTPS address while the access is open at now.
func (a Access) Addr(now time.Time) string {
	ip := net.ParseIP(a.Address)
	if ip == nil || ip.To4() == nil || a.Port < 1024 || a.Port > 65535 || !now.Before(a.Until) {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(a.Port))
}

// Save stores the state; an empty value closes the access. As root it goes
// through state.WriteFile (no symlink escape, file handed to the web user).
func Save(a Access) error {
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(Path(), append(raw, '\n'), 0o600)
}
