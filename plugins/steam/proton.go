package steam

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GE-Proton runs Windows servers with Valve's Wine plus the GE patches. It
// does not come from APT. GoDeb Play ships one checked release (pinned
// below, hash verified by hand). Newer releases can be installed from the
// panel with a fresh 2FA code; they are checked against the .sha512sum of
// the same GitHub release, which catches broken downloads but trusts the
// GE release account. The version a game uses is the one in its unit's
// ExecStart, so the unit stays the source of truth.
const (
	protonPinned       = "GE-Proton11-12"
	protonPinnedSHA512 = "2e37447902529c9fc39138dc0b3f24aed3513b59a190b825e6b4a668e49e2033bdf6b8a7998e8686e067bbb3f61f3a6633e2408f0cc96f6dad983bd18e2db31e"
	// maxProtonDownload bounds one archive (about 570 MB today).
	maxProtonDownload = 2 << 30
)

// Release sources; variables so tests can point them at a local server.
var (
	protonDownloadBase = "https://github.com/GloriousEggroll/proton-ge-custom/releases/download/"
	protonReleasesAPI  = "https://api.github.com/repos/GloriousEggroll/proton-ge-custom/releases?per_page=20"
	protonHTTP         = &http.Client{Timeout: 60 * time.Minute}
)

// protonTag is the only form a version may take; it ends up in URLs, paths
// and the unit, so nothing else gets through.
var protonTag = regexp.MustCompile(`^GE-Proton([0-9]{1,2})-([0-9]{1,3})$`)

// protonsDir is shared by all games and owned by root: a game account may
// read and run Proton but never change it, so one compromised server cannot
// plant code into another game's runtime. "proton-ge" cannot be a game ID
// (no dash allowed), so it never collides with a game's base directory.
func protonsDir() string { return filepath.Join(rootDir(), "proton-ge") }

// protonDir is one unpacked release.
func protonDir(version string) string { return filepath.Join(protonsDir(), version) }

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

// protonVersionOf returns the release a game's unit starts, or the pinned
// one when there is no unit (yet) or it names none.
func (g *Game) protonVersionOf() string {
	raw, err := os.ReadFile(g.unitPath())
	if err == nil {
		if v := unitProtonVersion(string(raw)); v != "" {
			return v
		}
	}
	return protonPinned
}

// unitProtonVersion finds <protonsDir>/<version>/proton in ExecStart.
func unitProtonVersion(unit string) string {
	prefix := "ExecStart=" + protonsDir() + "/"
	for _, line := range strings.Split(unit, "\n") {
		rest, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		v, _, _ := strings.Cut(rest, "/")
		if protonTag.MatchString(v) {
			return v
		}
	}
	return ""
}

// protonReady reports whether a release is unpacked.
func protonReady(version string) bool {
	if !protonTag.MatchString(version) {
		return false
	}
	info, err := os.Lstat(filepath.Join(protonDir(version), "proton"))
	return err == nil && info.Mode().IsRegular()
}

// protonOlder orders versions by major and minor number.
func protonOlder(a, b string) bool {
	am, an := protonNumbers(a)
	bm, bn := protonNumbers(b)
	if am != bm {
		return am < bm
	}
	return an < bn
}

func protonNumbers(v string) (int, int) {
	m := protonTag.FindStringSubmatch(v)
	if m == nil {
		return 0, 0
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major, minor
}

// installedProtons lists the unpacked releases, newest first.
func installedProtons() []string {
	entries, err := os.ReadDir(protonsDir())
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() && protonReady(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return protonOlder(out[j], out[i]) })
	return out
}

// protonUsers lists the installed games whose unit starts version.
func protonUsers(version string) []string {
	out := []string{}
	for _, g := range sortedGames() {
		if g.Platform == Proton && g.ready() && g.protonVersionOf() == version {
			out = append(out, g.ID)
		}
	}
	return out
}

// protonAsset is the archive name of a release. Since GE-Proton11 the
// archives carry the architecture; older ones do not.
func protonAssets(version string) []string {
	return []string{version + "-x86_64", version}
}

// ensureProton downloads, verifies and unpacks a release once. The download
// lands in a root-only directory, is checked against the pinned SHA-512 or
// the release's .sha512sum, and only then unpacked into a temporary
// directory that is renamed into place, so a half-unpacked tree is never
// used.
func ensureProton(ctx context.Context, j *jobHandle, version string) error {
	if !protonTag.MatchString(version) {
		return fmt.Errorf("Ungültige GE-Proton-Version %q", version)
	}
	if protonReady(version) {
		j.logf("%s vorhanden", version)
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

	asset, err := downloadProton(ctx, j, r, archive, version)
	if err != nil {
		return err
	}
	f, err := r.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := r.Mkdir(partial, 0o755); err != nil {
		return err
	}
	j.logf("Entpacke %s", asset)
	if err := extractProton(f, r, partial, asset); err != nil {
		return fmt.Errorf("%s entpacken: %w", version, err)
	}
	if info, err := r.Lstat(path.Join(partial, "proton")); err != nil || !info.Mode().IsRegular() {
		return errors.New("proton fehlt im Archiv")
	}
	_ = r.RemoveAll(version)
	if err := r.Rename(partial, version); err != nil {
		return err
	}
	j.logf("%s liegt unter %s", version, protonDir(version))
	return nil
}

// downloadProton fetches the archive of version into name and verifies it.
// It returns the asset name (also the archive's top directory).
func downloadProton(ctx context.Context, j *jobHandle, r *os.Root, name, version string) (string, error) {
	var lastErr error
	for _, asset := range protonAssets(version) {
		url := protonDownloadBase + version + "/" + asset + ".tar.gz"
		want := ""
		if version == protonPinned {
			want = protonPinnedSHA512
		} else {
			sum, err := fetchSHA512(ctx, protonDownloadBase+version+"/"+asset+".sha512sum", asset+".tar.gz")
			if errors.Is(err, errNotFound) {
				lastErr = err
				continue
			}
			if err != nil {
				return "", err
			}
			want = sum
		}
		j.logf("Lade %s", url)
		err := downloadVerified(ctx, r, name, url, want)
		if errors.Is(err, errNotFound) {
			lastErr = err
			_ = r.Remove(name)
			continue
		}
		if err != nil {
			return "", err
		}
		if version == protonPinned {
			j.logf("Prüfsumme stimmt (in GoDeb Play festgelegt)")
		} else {
			j.logf("Prüfsumme stimmt (SHA-512 aus dem Release)")
		}
		return asset, nil
	}
	return "", fmt.Errorf("%s: kein Archiv für x86_64 gefunden (%v)", version, lastErr)
}

var errNotFound = errors.New("nicht gefunden")

func httpGet(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "godeb-play")
	resp, err := protonHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d von %s", resp.StatusCode, url)
	}
	return resp, nil
}

// fetchSHA512 reads a sha512sum file and returns the hash listed for file.
func fetchSHA512(ctx context.Context, url, file string) (string, error) {
	resp, err := httpGet(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return parseSHA512Sum(io.LimitReader(resp.Body, 4<<10), file)
}

var sha512Hex = regexp.MustCompile(`^[0-9a-f]{128}$`)

// parseSHA512Sum accepts the sha512sum format: "<hash>  [*]<name>".
func parseSHA512Sum(src io.Reader, file string) (string, error) {
	sc := bufio.NewScanner(src)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		if sha512Hex.MatchString(sum) && path.Base(strings.TrimPrefix(fields[1], "*")) == file {
			return sum, nil
		}
	}
	return "", fmt.Errorf("Keine SHA-512 für %s in der Prüfsummendatei", file)
}

// downloadVerified fetches url into name inside r and fails unless the
// SHA-512 matches want.
func downloadVerified(ctx context.Context, r *os.Root, name, url, want string) error {
	resp, err := httpGet(ctx, url)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return err
		}
		return fmt.Errorf("Herunterladen: %w", err)
	}
	defer resp.Body.Close()
	out, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	sum := sha512.New()
	n, err := io.Copy(io.MultiWriter(out, sum), io.LimitReader(resp.Body, maxProtonDownload+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("Herunterladen: %w", err)
	}
	if n > maxProtonDownload {
		return errors.New("Archiv ist größer als erwartet")
	}
	return checkSHA512(sum.Sum(nil), want)
}

func checkSHA512(got []byte, want string) error {
	if hex.EncodeToString(got) != want {
		return fmt.Errorf("Prüfsumme stimmt nicht (erwartet %s…, erhalten %s…); Download verworfen", want[:16], hex.EncodeToString(got)[:16])
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

// ProtonRelease is one release on GitHub.
type ProtonRelease struct {
	Version   string `json:"version"`
	Published string `json:"published"`
	Installed bool   `json:"installed"`
	Pinned    bool   `json:"pinned"`
}

// releaseCache keeps the GitHub answer for a while: the API allows 60
// unauthenticated requests per hour.
var releaseCache struct {
	sync.Mutex
	at   time.Time
	list []ProtonRelease
}

const releaseCacheTTL = 15 * time.Minute

// protonReleases lists stable x86_64 releases, newest first.
func protonReleases(ctx context.Context, force bool) ([]ProtonRelease, time.Time, error) {
	releaseCache.Lock()
	defer releaseCache.Unlock()
	if !force && releaseCache.list != nil && time.Since(releaseCache.at) < releaseCacheTTL {
		return markInstalled(releaseCache.list), releaseCache.at, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	resp, err := httpGet(ctx, protonReleasesAPI)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("GitHub nicht erreichbar: %w", err)
	}
	defer resp.Body.Close()
	list, err := parseReleases(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, time.Time{}, err
	}
	releaseCache.list, releaseCache.at = list, time.Now()
	return markInstalled(list), releaseCache.at, nil
}

func parseReleases(src io.Reader) ([]ProtonRelease, error) {
	var raw []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Published  string `json:"published_at"`
		Assets     []struct {
			Name string `json:"name"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(src).Decode(&raw); err != nil {
		return nil, fmt.Errorf("Antwort von GitHub unlesbar: %w", err)
	}
	out := []ProtonRelease{}
	for _, rel := range raw {
		if rel.Draft || rel.Prerelease || !protonTag.MatchString(rel.Tag) {
			continue
		}
		archive := false
		for _, a := range rel.Assets {
			for _, name := range protonAssets(rel.Tag) {
				if a.Name == name+".tar.gz" {
					archive = true
				}
			}
		}
		if archive {
			out = append(out, ProtonRelease{Version: rel.Tag, Published: rel.Published, Pinned: rel.Tag == protonPinned})
		}
	}
	sort.Slice(out, func(i, j int) bool { return protonOlder(out[j].Version, out[i].Version) })
	return out, nil
}

func markInstalled(list []ProtonRelease) []ProtonRelease {
	out := make([]ProtonRelease, len(list))
	for i, rel := range list {
		rel.Installed = protonReady(rel.Version)
		out[i] = rel
	}
	return out
}

// useProton installs version if needed and switches the game to it: stop,
// back up the savegame, rewrite the unit, start again.
func useProton(version string) func(context.Context, *Game, *jobHandle) error {
	return func(ctx context.Context, g *Game, j *jobHandle) error {
		if err := requireRoot(); err != nil {
			return err
		}
		j.step(version)
		if err := ensureProton(ctx, j, version); err != nil {
			return err
		}
		current := g.protonVersionOf()
		if current == version {
			j.logf("%s nutzt bereits %s", g.Name, version)
			return nil
		}
		j.logf("Wechsel von %s auf %s", current, version)
		r, err := g.openBase()
		if err != nil {
			return err
		}
		defer r.Close()
		was, err := stopForSaves(ctx, g, j)
		if err != nil {
			return err
		}
		if g.SaveDir != nil {
			j.step("Savegame sichern")
			name, err := backupSave(g, r, "update")
			if err != nil {
				return errors.Join(fmt.Errorf("Savegame-Backup vor dem Wechsel: %w", err), startAgain(ctx, g, j, was))
			}
			if name != "" {
				j.logf("Backup %s", name)
			}
		}
		j.step("systemd-Dienst " + g.unit())
		if err := writeUnitVersion(ctx, g, version); err != nil {
			return errors.Join(err, startAgain(ctx, g, j, was))
		}
		return startAgain(ctx, g, j, was)
	}
}

// deleteProton removes an unpacked release no game uses.
func deleteProton(version string) error {
	if !protonTag.MatchString(version) {
		return fmt.Errorf("Ungültige GE-Proton-Version %q", version)
	}
	if !protonReady(version) {
		return fmt.Errorf("%s ist nicht installiert", version)
	}
	if users := protonUsers(version); len(users) > 0 {
		return fmt.Errorf("%s wird noch benutzt von: %s", version, strings.Join(users, ", "))
	}
	r, err := os.OpenRoot(protonsDir())
	if err != nil {
		return err
	}
	defer r.Close()
	return r.RemoveAll(version)
}
