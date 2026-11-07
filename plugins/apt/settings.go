package apt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"

	"godebplay/backend/core"
)

// settingsPath holds the automatic update settings. They decide what the
// agent installs on its own, so they live in /etc/godeb-play (root), not in the
// web process's data.
const settingsPath = "/etc/godeb-play/apt.json"

const (
	minInterval     = 5
	maxInterval     = 24 * 60
	defaultInterval = 10
)

// Settings is apt.json. Without the file both automatic checks and
// automatic security updates are on.
type Settings struct {
	AutoCheck    bool `json:"autoCheck"`
	Interval     int  `json:"interval"` // minutes between checks
	AutoSecurity bool `json:"autoSecurity"`
}

func defaultSettings() Settings {
	return Settings{AutoCheck: true, Interval: defaultInterval, AutoSecurity: true}
}

func loadSettings() (Settings, error) {
	s := defaultSettings()
	data, err := core.ReadAdminFile(settingsPath)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return defaultSettings(), fmt.Errorf("%s: %w", settingsPath, err)
	}
	return validSettings(s)
}

func validSettings(s Settings) (Settings, error) {
	if s.Interval < minInterval || s.Interval > maxInterval {
		return s, fmt.Errorf("Intervall muss zwischen %d und %d Minuten liegen", minInterval, maxInterval)
	}
	return s, nil
}

func saveSettings(s Settings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return core.WriteAdminFile(settingsPath, append(data, '\n'), 0o600)
}
