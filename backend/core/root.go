package core

import (
	"fmt"
	"os"
	"path/filepath"
)

// RepoRoot resolves the repository root from GODEB_ROOT or by walking up to go.mod.
func RepoRoot() (string, error) {
	if v := os.Getenv("GODEB_ROOT"); v != "" {
		info, err := os.Stat(v)
		if err != nil {
			return "", fmt.Errorf("GODEB_ROOT %s: %w", v, err)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("GODEB_ROOT %s ist kein Verzeichnis", v)
		}
		return v, nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod nicht gefunden; GODEB_ROOT setzen")
		}
		dir = parent
	}
}
