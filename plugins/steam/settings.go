package steam

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"godebplay/backend/core"
)

// Game settings that end up on the server's command line (name, world,
// password) are written by the agent to a root-only environment file. The
// unit reads it (EnvironmentFile=) and passes the values as ${NAME}, each as
// one argument. The game account can change its own config file, but never
// what the agent writes here.

var (
	settingName  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,40}$`)
	settingValue = regexp.MustCompile(`^[^"'\\$%;\x00-\x1f\x7f]{0,128}$`)
)

// settingsPath is the root-only environment file of a game.
func (g *Game) settingsPath() string {
	if dir := os.Getenv("GODEB_STEAM_ROOT"); dir != "" {
		return filepath.Join(rootDir(), "settings", g.ID+".env")
	}
	return "/etc/godeb-play/games/" + g.ID + ".env"
}

// renderSettings checks every name and value and writes KEY="value" lines.
// Values have no quotes, backslashes, dollar or percent signs, so systemd
// takes them literally.
func renderSettings(env map[string]string) (string, error) {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# Managed by GoDeb Play. Changes are overwritten when the settings are saved.\n")
	for _, k := range keys {
		v := env[k]
		if !settingName.MatchString(k) {
			return "", fmt.Errorf("ungültiger Name %q", k)
		}
		if !settingValue.MatchString(v) {
			return "", fmt.Errorf("%s enthält unerlaubte Zeichen", k)
		}
		fmt.Fprintf(&b, "%s=\"%s\"\n", k, v)
	}
	return b.String(), nil
}

// writeSettings writes the environment file for a validated configuration.
func writeSettings(g *Game, cfg map[string]any) error {
	if g.Settings == nil {
		return nil
	}
	env, err := g.Settings(cfg)
	if err != nil {
		return err
	}
	body, err := renderSettings(env)
	if err != nil {
		return err
	}
	if os.Getenv("GODEB_STEAM_ROOT") != "" {
		if err := os.MkdirAll(filepath.Dir(g.settingsPath()), 0o700); err != nil {
			return err
		}
		return os.WriteFile(g.settingsPath(), []byte(body), 0o600)
	}
	if err := core.WriteAdminFile(g.settingsPath(), []byte(body), 0o600); err != nil {
		return errors.New("Einstellungen nicht geschrieben: " + err.Error())
	}
	return nil
}
