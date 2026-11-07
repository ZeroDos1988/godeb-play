package steam

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"godebplay/backend/core"
)

// Savegame backups: before every update and on request, the game's save
// directory is packed into backups/<game>/<time>-<reason>.tar.gz below the
// root-owned rootDir, out of reach of the game account. Restoring stops the
// server, keeps the current save as one more backup, unpacks the chosen one
// and starts the server again if it ran.

// maxBackups is how many backups per game are kept; the oldest go first.
const maxBackups = 10

var backupName = regexp.MustCompile(`^([0-9]{8}-[0-9]{6})-(manual|update|restore)\.tar\.gz$`)

func backupDir(g *Game) string { return filepath.Join(rootDir(), "backups", g.ID) }

// saveName is the save directory inside the base root, or "" when the game
// has none.
func (g *Game) saveName() string {
	if g.SaveDir == nil {
		return ""
	}
	dir := g.SaveDir(g.currentConfig())
	if !safeRelative(dir) {
		return ""
	}
	return path.Clean(dir)
}

// ensureBackupDir creates backups/<game>, root-only.
func ensureBackupDir(g *Game) error {
	parent := filepath.Join(rootDir(), "backups")
	for _, dir := range []string{rootDir(), parent, backupDir(g)} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	if err := os.Chmod(rootDir(), 0o755); err != nil {
		return err
	}
	return os.Chmod(backupDir(g), 0o700)
}

// backupSave packs the save directory. It returns "" without error when
// there is nothing to back up yet (first start pending).
func backupSave(g *Game, r *os.Root, reason string) (string, error) {
	save := g.saveName()
	if save == "" {
		return "", nil
	}
	if info, err := r.Lstat(save); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	} else if !info.IsDir() {
		return "", fmt.Errorf("%s ist kein Verzeichnis", save)
	}
	if err := ensureBackupDir(g); err != nil {
		return "", err
	}
	stamp := time.Now().Format("20060102-150405")
	name := stamp + "-" + reason + ".tar.gz"
	full := filepath.Join(backupDir(g), name)
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("Backup %s gibt es schon; in einer Sekunde erneut versuchen", name)
	}
	if err != nil {
		return "", err
	}
	if err := writeTarGzFrom(f, r, save); err != nil {
		f.Close()
		os.Remove(full)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(full)
		return "", err
	}
	pruneBackups(g)
	return name, nil
}

// Backup is one archive as the UI lists it.
type Backup struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Time   string `json:"time"` // RFC 3339
	Size   int64  `json:"size"`
}

func listBackups(g *Game) []Backup {
	entries, err := os.ReadDir(backupDir(g))
	if err != nil {
		return []Backup{}
	}
	out := []Backup{}
	for _, e := range entries {
		m := backupName.FindStringSubmatch(e.Name())
		if m == nil || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		at, err := time.ParseInLocation("20060102-150405", m[1], time.Local)
		if err != nil {
			continue
		}
		out = append(out, Backup{Name: e.Name(), Reason: m[2], Time: at.Format(time.RFC3339), Size: info.Size()})
	}
	// Newest first; the name starts with the time.
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out
}

func pruneBackups(g *Game) {
	list := listBackups(g)
	for _, b := range list[min(len(list), maxBackups):] {
		os.Remove(filepath.Join(backupDir(g), b.Name))
	}
}

// stopForSaves stops a running server so the save files are complete, and
// returns whether it ran.
func stopForSaves(ctx context.Context, g *Game, j *jobHandle) (bool, error) {
	if serviceState(ctx, g) != "active" {
		return false, nil
	}
	j.step("Server stoppen")
	if res := core.RunAdmin(ctx, "systemctl", "stop", g.unit()); res.Err != nil {
		return false, fmt.Errorf("systemctl stop: %s", res.Detail())
	}
	return true, nil
}

func startAgain(ctx context.Context, g *Game, j *jobHandle, was bool) error {
	if !was {
		return nil
	}
	j.step("Server starten")
	if res := core.RunAdmin(ctx, "systemctl", "start", g.unit()); res.Err != nil {
		return fmt.Errorf("systemctl start: %s", res.Detail())
	}
	return nil
}

// manualBackup backs up on request, with the server stopped for a moment.
func manualBackup(ctx context.Context, g *Game, j *jobHandle) error {
	if err := requireRoot(); err != nil {
		return err
	}
	r, err := g.openBase()
	if err != nil {
		return err
	}
	defer r.Close()
	was, err := stopForSaves(ctx, g, j)
	if err != nil {
		return err
	}
	j.step("Savegame sichern")
	name, berr := backupSave(g, r, "manual")
	if berr == nil {
		if name == "" {
			j.logf("Noch kein Savegame vorhanden.")
		} else {
			j.logf("Backup %s", name)
		}
	}
	if err := startAgain(ctx, g, j, was); err != nil {
		return errors.Join(berr, err)
	}
	return berr
}

// restoreBackup replaces the save directory with a backup. The current save
// becomes a backup first, so a restore can itself be undone.
func restoreBackup(name string) func(context.Context, *Game, *jobHandle) error {
	return func(ctx context.Context, g *Game, j *jobHandle) error {
		if err := requireRoot(); err != nil {
			return err
		}
		if !backupName.MatchString(name) {
			return errors.New("Unbekanntes Backup")
		}
		save := g.saveName()
		if save == "" {
			return errors.New(g.Name + " hat kein Savegame-Verzeichnis")
		}
		src, err := os.Open(filepath.Join(backupDir(g), name))
		if err != nil {
			return fmt.Errorf("Backup %s: %w", name, err)
		}
		defer src.Close()
		uid, gid, err := lookupUser(g)
		if err != nil {
			return err
		}
		r, err := g.openBase()
		if err != nil {
			return err
		}
		defer r.Close()
		was, err := stopForSaves(ctx, g, j)
		if err != nil {
			return err
		}
		j.step("Aktuelles Savegame sichern")
		if kept, err := backupSave(g, r, "restore"); err != nil {
			return errors.Join(err, startAgain(ctx, g, j, was))
		} else if kept != "" {
			j.logf("Backup %s", kept)
		}
		j.step("Backup " + name + " einspielen")
		if err := r.RemoveAll(save); err != nil {
			return err
		}
		if err := ensureSubdirs(r, uid, gid, save); err != nil {
			return err
		}
		if err := extractTarGzIn(src, r, save, uid, gid); err != nil {
			return fmt.Errorf("Backup entpacken: %w", err)
		}
		return startAgain(ctx, g, j, was)
	}
}

func handleBackups(w http.ResponseWriter, r *http.Request, g *Game) {
	w.Header().Set("Cache-Control", "no-store")
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"supported": g.SaveDir != nil,
		"saveDir":   g.saveName(),
		"keep":      maxBackups,
		"backups":   listBackups(g),
	})
}

func handleRestore(w http.ResponseWriter, r *http.Request, g *Game) {
	name := r.PathValue("name")
	if !backupName.MatchString(name) {
		core.WriteError(w, http.StatusBadRequest, "Unbekanntes Backup")
		return
	}
	if _, err := os.Stat(filepath.Join(backupDir(g), name)); err != nil {
		core.WriteError(w, http.StatusNotFound, "Backup nicht gefunden")
		return
	}
	handleStartJob("restore", restoreBackup(name))(w, r, g)
}
