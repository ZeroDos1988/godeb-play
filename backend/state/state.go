// Package state is the directory of the unprivileged web process,
// /var/lib/godeb-play: its database, master key, login keys and the setup files.
// It belongs to the web user. Root (the agent and the CLI) also writes some
// files there; those writes go through os.Root, so a symlink planted by a
// compromised web process cannot redirect them, and the result is handed
// to the web user.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultDir is the state directory of the packaged install.
const DefaultDir = "/var/lib/godeb-play"

// Dir returns GODEB_STATE_DIR or DefaultDir.
func Dir() string {
	if v := strings.TrimSpace(os.Getenv("GODEB_STATE_DIR")); v != "" {
		return filepath.Clean(v)
	}
	return DefaultDir
}

// WebUser is the account of the web process (GODEB_WEB_USER, default godeb-play).
func WebUser() string {
	if v := strings.TrimSpace(os.Getenv("GODEB_WEB_USER")); v != "" {
		return v
	}
	return "godeb-play"
}

// webIDs returns uid and gid of the web user, ok=false when this process is
// not root or the account does not exist (development).
func webIDs() (int, int, bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	u, err := user.Lookup(WebUser())
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uid, gid, true
}

// rel returns path relative to Dir, ok=false when it lies outside.
func rel(path string) (string, bool) {
	r, err := filepath.Rel(Dir(), filepath.Clean(path))
	if err != nil || r == "." || r == ".." || strings.HasPrefix(r, "../") || filepath.IsAbs(r) {
		return "", false
	}
	return r, true
}

// WriteFile replaces path atomically with perm. Missing parent directories
// are created with 0700. Inside Dir the write cannot follow a symlink out of
// the directory and, as root, file and new directories go to the web user.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	r, inside := rel(path)
	if !inside {
		return writePlain(path, data, perm)
	}
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(Dir())
	if err != nil {
		return err
	}
	defer root.Close()
	uid, gid, give := webIDs()
	if parent := filepath.Dir(r); parent != "." {
		if err := root.MkdirAll(parent, 0o700); err != nil {
			return err
		}
		if give {
			// Every directory between Dir and the file, never a symlink target.
			for p := parent; p != "."; p = filepath.Dir(p) {
				if err := root.Lchown(p, uid, gid); err != nil {
					return err
				}
			}
		}
	}
	tmp := filepath.Join(filepath.Dir(r), "."+filepath.Base(r)+"."+randSuffix())
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if give {
		if err := f.Chown(uid, gid); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, r)
}

// CreateExclusive writes a new file and fails with fs.ErrExist when it is
// already there (the setup token). Same rules as WriteFile.
func CreateExclusive(path string, data []byte, perm os.FileMode) error {
	if _, err := os.Lstat(path); err == nil {
		return fs.ErrExist
	}
	return WriteFile(path, data, perm)
}

// HandOver gives an existing file inside Dir to the web user when root
// created it (the database file). Symlinks are never followed.
func HandOver(path string) error {
	r, inside := rel(path)
	if !inside {
		return nil
	}
	uid, gid, give := webIDs()
	if !give {
		return nil
	}
	root, err := os.OpenRoot(Dir())
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Lchown(r, uid, gid)
}

func writePlain(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func randSuffix() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(errors.New("crypto/rand: " + err.Error()))
	}
	return hex.EncodeToString(b)
}
