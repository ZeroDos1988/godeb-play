package steam

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
)

// The agent runs as root, but everything below a game's base directory
// belongs to the game's account. A compromised game server could swap a
// file or directory for a symlink at any time, so root never follows paths
// there: every access goes through an os.Root opened on the base directory
// (its parent is root-owned, so the base itself cannot be replaced). Names
// below are slash-separated and relative to the base directory.

// openBase opens the game's base directory as a root.
func (g *Game) openBase() (*os.Root, error) {
	return os.OpenRoot(g.baseDir())
}

const (
	serverSub   = "server"
	steamcmdSub = "steamcmd"
	wineSub     = "wine"
	compatSub   = "proton"
)

func (g *Game) configName() string { return path.Join(serverSub, g.ConfigFile) }

// asRoot reports whether ownership can and must be handed to the game
// account (not in unprivileged development runs).
func asRoot() bool { return os.Geteuid() == 0 }

// ensureSubdirs creates the game's directories inside the root and hands
// them to the game account.
func ensureSubdirs(r *os.Root, uid, gid int, names ...string) error {
	for _, name := range names {
		if err := r.MkdirAll(name, 0o750); err != nil {
			return err
		}
		if asRoot() {
			if err := r.Lchown(name, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// chownTreeIn sets the owner of name and everything below it. It walks
// through the root, so a directory swapped for a symlink cannot lead out of
// the base directory, and symlinks themselves are changed, never followed.
func chownTreeIn(r *os.Root, name string, uid, gid int) error {
	if !asRoot() {
		return nil
	}
	return fs.WalkDir(r.FS(), name, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return r.Lchown(p, uid, gid)
	})
}

// readLimited reads a regular file inside the root, at most max bytes.
func readLimited(r *os.Root, name string, max int64) ([]byte, error) {
	info, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s ist keine normale Datei", name)
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("%s ist größer als %d KiB", name, max>>10)
	}
	return raw, nil
}

// writeAtomic replaces name with data: a new temporary file next to it,
// handed to the game account, then renamed over the old one. Lchown and
// Rename stay inside the root even if the game swaps the temporary file.
func writeAtomic(r *os.Root, name string, data []byte, mode os.FileMode, uid, gid int) error {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(name), "."+path.Base(name)+".godeb-"+hex.EncodeToString(suffix))
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer r.Remove(tmp)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if asRoot() {
		if err := r.Lchown(tmp, uid, gid); err != nil {
			return err
		}
	}
	return r.Rename(tmp, name)
}

// tarLimits bound what an archive may unpack.
const (
	maxTarFile  = 4 << 30 // one file
	maxTarTotal = 64 << 30
)

// extractTarGzIn unpacks regular files and directories below dir inside
// the root. Links, devices and paths leaving dir are skipped or rejected.
func extractTarGzIn(src io.Reader, r *os.Root, dir string, uid, gid int) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		rel := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if rel == "." {
			continue
		}
		if path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("Pfad %q verlässt das Zielverzeichnis", hdr.Name)
		}
		target := path.Join(dir, rel)
		mode := os.FileMode(hdr.Mode).Perm() &^ 0o022
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := r.MkdirAll(target, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > maxTarFile || total+hdr.Size > maxTarTotal {
				return fmt.Errorf("%s ist zu groß", hdr.Name)
			}
			total += hdr.Size
			if err := r.MkdirAll(path.Dir(target), 0o750); err != nil {
				return err
			}
			// Remove first: an existing symlink must not be written through.
			_ = r.Remove(target)
			f, err := r.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, io.LimitReader(tr, hdr.Size)); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		default:
			continue
		}
		if asRoot() {
			if err := r.Lchown(target, uid, gid); err != nil {
				return err
			}
		}
	}
}

// writeTarGzFrom packs the regular files and directories below dir inside
// the root into dst. Symlinks and special files are left out, so a game
// cannot smuggle root-only files into a backup.
func writeTarGzFrom(dst io.Writer, r *os.Root, dir string) error {
	gz := gzip.NewWriter(dst)
	tw := tar.NewWriter(gz)
	var total int64
	err := fs.WalkDir(r.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(p, dir), "/")
		if rel == "" {
			return nil
		}
		info, err := r.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: rel + "/", Mode: int64(info.Mode().Perm()), ModTime: info.ModTime()})
		case info.Mode().IsRegular():
			total += info.Size()
			if info.Size() > maxTarFile || total > maxTarTotal {
				return fmt.Errorf("%s ist zu groß für ein Backup", p)
			}
			f, err := r.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: rel, Mode: int64(info.Mode().Perm()), Size: info.Size(), ModTime: info.ModTime()}); err != nil {
				return err
			}
			_, err = io.Copy(tw, io.LimitReader(f, info.Size()))
			return err
		default:
			return nil
		}
	})
	if err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
