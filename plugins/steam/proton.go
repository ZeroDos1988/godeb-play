package steam

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// GE-Proton runs Windows servers with Valve's Wine plus the GE patches. It
// does not come from APT, so the agent downloads one pinned release and
// checks it against a pinned SHA-256 before unpacking anything. A new
// release means changing these three constants (hash from the release's
// .sha512sum, re-hashed with sha256sum after checking).
const (
	protonVersion = "GE-Proton11-12"
	protonURL     = "https://github.com/GloriousEggroll/proton-ge-custom/releases/download/" + protonVersion + "/" + protonVersion + "-x86_64.tar.gz"
	protonSHA256  = "0595159e417c3dbbfb7cc3ae0d3ed15a617cc607aa23ef756ea79029d7af5d70"
	// maxProtonDownload bounds the archive (about 570 MB).
	maxProtonDownload = 2 << 30
)

// protonsDir is shared by all games and owned by root: a game account may
// read and run Proton but never change it, so one compromised server cannot
// plant code into another game's runtime. "proton-ge" cannot be a game ID
// (no dash allowed), so it never collides with a game's base directory.
func protonsDir() string { return filepath.Join(rootDir(), "proton-ge") }

// protonDir is the unpacked pinned release.
func protonDir() string { return filepath.Join(protonsDir(), protonVersion) }

// compatData is the game's Proton prefix (pfx/ below it), written by the
// game account.
func (g *Game) compatData() string { return filepath.Join(g.baseDir(), compatSub) }

// protonEnv are the unit's variables for a Proton server. Protonfixes are
// off: they would download winetricks at start and only target clients.
func (g *Game) protonEnv() []string {
	return []string{
		"STEAM_COMPAT_DATA_PATH=" + g.compatData(),
		"STEAM_COMPAT_CLIENT_INSTALL_PATH=" + g.steamcmdDir(),
		"WINEDEBUG=-all",
		"PROTONFIXES_DISABLE=1",
		"PYTHONDONTWRITEBYTECODE=1",
	}
}

// protonReady reports whether the pinned release is unpacked.
func protonReady() bool {
	info, err := os.Lstat(filepath.Join(protonDir(), "proton"))
	return err == nil && info.Mode().IsRegular()
}

// ensureProton downloads, verifies and unpacks the pinned release once.
// The download lands in a root-only directory, is checked against
// protonSHA256 and only then unpacked into a temporary directory that is
// renamed into place, so a half-unpacked tree is never used.
func ensureProton(ctx context.Context, j *jobHandle) error {
	if protonReady() {
		j.logf("%s vorhanden", protonVersion)
		return nil
	}
	if err := os.MkdirAll(protonsDir(), 0o755); err != nil {
		return err
	}
	if err := os.Chmod(protonsDir(), 0o755); err != nil {
		return err
	}
	r, err := os.OpenRoot(protonsDir())
	if err != nil {
		return err
	}
	defer r.Close()

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tag := hex.EncodeToString(suffix)
	archive := ".download-" + tag
	partial := ".partial-" + tag
	defer r.Remove(archive)
	defer r.RemoveAll(partial)

	j.logf("Lade %s (ca. 570 MB)", protonURL)
	if err := downloadVerified(ctx, r, archive); err != nil {
		return err
	}
	j.logf("Prüfsumme stimmt (SHA-256 %s…)", protonSHA256[:16])
	f, err := r.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := r.Mkdir(partial, 0o755); err != nil {
		return err
	}
	if err := extractProton(f, r, partial, protonVersion+"-x86_64"); err != nil {
		return fmt.Errorf("%s entpacken: %w", protonVersion, err)
	}
	if info, err := r.Lstat(path.Join(partial, "proton")); err != nil || !info.Mode().IsRegular() {
		return errors.New("proton fehlt im Archiv")
	}
	_ = r.RemoveAll(protonVersion)
	if err := r.Rename(partial, protonVersion); err != nil {
		return err
	}
	j.logf("%s entpackt nach %s", protonVersion, protonDir())
	return nil
}

// downloadVerified fetches protonURL into name inside r and fails unless
// the SHA-256 matches.
func downloadVerified(ctx context.Context, r *os.Root, name string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, protonURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 60 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s herunterladen: %w", protonVersion, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s herunterladen: HTTP %d", protonVersion, resp.StatusCode)
	}
	out, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, maxProtonDownload+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s herunterladen: %w", protonVersion, err)
	}
	if n > maxProtonDownload {
		return fmt.Errorf("%s ist größer als erwartet", protonVersion)
	}
	return checkSHA256(sum.Sum(nil), protonSHA256)
}

func checkSHA256(got []byte, want string) error {
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("Prüfsumme von %s stimmt nicht (erwartet %s, erhalten %s); Download verworfen", protonVersion, want, hex.EncodeToString(got))
	}
	return nil
}

// extractProton unpacks the verified archive below dir, dropping the
// archive's top directory top. Unlike extractTarGzIn it keeps symlinks,
// because Proton's default prefix links into its own libraries; a link
// must be relative and stay inside the unpacked tree. Everything is owned
// by root and not writable for group or others.
func extractProton(src io.Reader, r *os.Root, dir, top string) error {
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
		name := path.Clean(strings.TrimPrefix(hdr.Name, "./"))
		if name == top {
			continue
		}
		rel, ok := strings.CutPrefix(name, top+"/")
		if !ok || rel == "" || path.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, "../") {
			return fmt.Errorf("Pfad %q liegt nicht in %s", hdr.Name, top)
		}
		target := path.Join(dir, rel)
		mode := os.FileMode(hdr.Mode).Perm() &^ 0o022
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := r.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size > maxTarFile || total+hdr.Size > maxTarTotal {
				return fmt.Errorf("%s ist zu groß", hdr.Name)
			}
			total += hdr.Size
			if err := r.MkdirAll(path.Dir(target), 0o755); err != nil {
				return err
			}
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
			// OpenFile applies the umask; set the archive's mode exactly.
			if err := r.Chmod(target, mode); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if !linkInside(rel, hdr.Linkname) {
				return fmt.Errorf("Link %s → %s verlässt %s", hdr.Name, hdr.Linkname, top)
			}
			if err := r.MkdirAll(path.Dir(target), 0o755); err != nil {
				return err
			}
			_ = r.Remove(target)
			if err := r.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		default:
			continue
		}
	}
}

// linkInside reports whether a symlink at rel pointing to link stays inside
// the unpacked tree (relative, no escape through ..).
func linkInside(rel, link string) bool {
	if link == "" || path.IsAbs(link) || strings.ContainsRune(link, 0) {
		return false
	}
	resolved := path.Join(path.Dir(rel), link)
	return resolved != ".." && !strings.HasPrefix(resolved, "../")
}
