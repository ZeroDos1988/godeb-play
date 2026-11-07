package firstrun

import (
	"os"
	"path/filepath"
	"strings"

	"godebplay/backend/state"
)

// etcDir holds the setup files: the state directory of the web process
// (/var/lib/godeb-play), which the web process writes itself. GODEB_ETC is the
// older name of the override. The package only ever touches these fixed
// names below it: setup.json, setup-token, access.json, tls/.
func etcDir() string {
	if dir := strings.TrimSpace(os.Getenv("GODEB_ETC")); dir != "" {
		return filepath.Clean(dir)
	}
	return state.Dir()
}

func statePath() string  { return filepath.Join(etcDir(), "setup.json") }
func tokenPath() string  { return filepath.Join(etcDir(), "setup-token") }
func accessPath() string { return filepath.Join(etcDir(), "access.json") }
func certPath() string   { return filepath.Join(etcDir(), "tls", "godeb.crt") }
func keyPath() string    { return filepath.Join(etcDir(), "tls", "godeb.key") }

// writeFile replaces a setup file atomically; as root it stays inside the
// state directory and goes to the web user.
func writeFile(path string, data []byte, perm os.FileMode) error {
	return state.WriteFile(path, data, perm)
}
