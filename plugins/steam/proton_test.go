package steam

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name, link, body string
	typ              byte
	mode             int64
}

func protonTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: e.mode, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

const top = "GE-Proton-test-x86_64"

func TestExtractProtonKeepsInnerSymlinksAndModes(t *testing.T) {
	base, r, _ := baseRoot(t)
	r.Mkdir("dst", 0o755)
	raw := protonTar(t, []tarEntry{
		{name: top + "/", typ: tar.TypeDir, mode: 0o755},
		{name: top + "/proton", typ: tar.TypeReg, mode: 0o777, body: "#!/usr/bin/env python3"},
		{name: top + "/files/lib/wine/x.dll", typ: tar.TypeReg, mode: 0o644, body: "dll"},
		{name: top + "/files/share/default_pfx/drive_c/x.dll", typ: tar.TypeSymlink, link: "../../../lib/wine/x.dll"},
	})
	if err := extractProton(bytes.NewReader(raw), r, "dst", top); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(base, "dst", "proton"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("proton: %v %v (group/other must not write)", info, err)
	}
	got, err := os.ReadFile(filepath.Join(base, "dst", "files/share/default_pfx/drive_c/x.dll"))
	if err != nil || string(got) != "dll" {
		t.Fatalf("inner symlink: %q %v", got, err)
	}
}

func TestExtractProtonRejectsEscapes(t *testing.T) {
	cases := map[string][]tarEntry{
		"absolute link":  {{name: top + "/a", typ: tar.TypeSymlink, link: "/etc/shadow"}},
		"link escape":    {{name: top + "/files/a", typ: tar.TypeSymlink, link: "../../../etc"}},
		"outside top":    {{name: "other/proton", typ: tar.TypeReg, mode: 0o755, body: "x"}},
		"path traversal": {{name: top + "/../evil", typ: tar.TypeReg, mode: 0o644, body: "x"}},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			base, r, _ := baseRoot(t)
			r.Mkdir("dst", 0o755)
			if err := extractProton(bytes.NewReader(protonTar(t, entries)), r, "dst", top); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Lstat(filepath.Join(base, "evil")); err == nil {
				t.Fatal("file escaped")
			}
		})
	}
}

func TestLinkInside(t *testing.T) {
	for _, c := range []struct {
		rel, link string
		ok        bool
	}{
		{"files/share/default_pfx/drive_c/windows/system32/a.dll", "../../../../../lib/wine/x86_64-windows/a.dll", true},
		{"files/lib/libx.so", "libx.so.1", true},
		{"a", "..", false},
		{"files/a", "../../b", false},
		{"a", "/usr/lib", false},
		{"a", "", false},
	} {
		if got := linkInside(c.rel, c.link); got != c.ok {
			t.Errorf("linkInside(%q, %q) = %v", c.rel, c.link, got)
		}
	}
}

func testJob() *jobHandle { return &jobHandle{r: &jobRunner{job: &Job{}}} }

// fakeGitHub serves one release archive and its sha512sum like GitHub does.
func fakeGitHub(t *testing.T, version, asset string, archive []byte, sum string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+version+"/"+asset+".tar.gz", func(w http.ResponseWriter, _ *http.Request) { w.Write(archive) })
	mux.HandleFunc("/"+version+"/"+asset+".sha512sum", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  %s.tar.gz\n", sum, asset)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	old := protonDownloadBase
	protonDownloadBase = srv.URL + "/"
	t.Cleanup(func() { protonDownloadBase = old })
}

func releaseArchive(t *testing.T, asset string) []byte {
	return protonTar(t, []tarEntry{
		{name: asset + "/", typ: tar.TypeDir, mode: 0o755},
		{name: asset + "/proton", typ: tar.TypeReg, mode: 0o755, body: "#!/usr/bin/env python3"},
	})
}

func TestEnsureProtonVerifiesReleaseChecksum(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	const v = "GE-Proton99-1"
	archive := releaseArchive(t, v+"-x86_64")
	sum := sha512.Sum512(archive)
	fakeGitHub(t, v, v+"-x86_64", archive, hex.EncodeToString(sum[:]))
	if err := ensureProton(context.Background(), testJob(), v); err != nil {
		t.Fatal(err)
	}
	if !protonReady(v) {
		t.Fatal("not unpacked")
	}
	if got := installedProtons(); len(got) != 1 || got[0] != v {
		t.Fatalf("installed = %v", got)
	}
	if entries, _ := os.ReadDir(protonsDir()); len(entries) != 1 {
		t.Fatalf("leftovers: %v", entries)
	}
}

func TestEnsureProtonRejectsTamperedArchive(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	const v = "GE-Proton99-2"
	archive := releaseArchive(t, v+"-x86_64")
	other := sha512.Sum512([]byte("something else"))
	fakeGitHub(t, v, v+"-x86_64", archive, hex.EncodeToString(other[:]))
	err := ensureProton(context.Background(), testJob(), v)
	if err == nil || !strings.Contains(err.Error(), "Prüfsumme") {
		t.Fatalf("err = %v", err)
	}
	if protonReady(v) {
		t.Fatal("tampered archive unpacked")
	}
	if entries, _ := os.ReadDir(protonsDir()); len(entries) != 0 {
		t.Fatalf("leftovers: %v", entries)
	}
}

func TestEnsureProtonFallsBackToOldAssetName(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	const v = "GE-Proton9-27"
	archive := releaseArchive(t, v)
	sum := sha512.Sum512(archive)
	fakeGitHub(t, v, v, archive, hex.EncodeToString(sum[:]))
	if err := ensureProton(context.Background(), testJob(), v); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureProtonRejectsBadVersion(t *testing.T) {
	for _, v := range []string{"../etc", "GE-Proton11-12/../../x", "Proton-9", "GE-Proton11-12 ", ""} {
		if err := ensureProton(context.Background(), testJob(), v); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}

func TestPinnedHashIsSHA512(t *testing.T) {
	if !sha512Hex.MatchString(protonPinnedSHA512) || !protonTag.MatchString(protonPinned) {
		t.Fatal("pinned release is malformed")
	}
	sum := sha512.Sum512([]byte("tampered"))
	if checkSHA512(sum[:], protonPinnedSHA512) == nil {
		t.Fatal("mismatch accepted")
	}
}

func TestParseSHA512Sum(t *testing.T) {
	h := strings.Repeat("ab", 64)
	if got, err := parseSHA512Sum(strings.NewReader(h+"  GE-Proton11-12-x86_64.tar.gz\n"), "GE-Proton11-12-x86_64.tar.gz"); err != nil || got != h {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := parseSHA512Sum(strings.NewReader(h+"  other.tar.gz\n"), "GE-Proton11-12-x86_64.tar.gz"); err == nil {
		t.Fatal("hash for another file accepted")
	}
	if _, err := parseSHA512Sum(strings.NewReader("abc  GE-Proton11-12-x86_64.tar.gz\n"), "GE-Proton11-12-x86_64.tar.gz"); err == nil {
		t.Fatal("short hash accepted")
	}
}

func TestParseReleases(t *testing.T) {
	raw := `[
	 {"tag_name":"GE-Proton11-9","published_at":"2026-09-01T00:00:00Z","assets":[{"name":"GE-Proton11-9-x86_64.tar.gz"}]},
	 {"tag_name":"GE-Proton11-12","published_at":"2026-11-03T00:00:00Z","assets":[{"name":"GE-Proton11-12-x86_64.tar.gz"},{"name":"GE-Proton11-12-aarch64.tar.gz"}]},
	 {"tag_name":"GE-Proton11-13","prerelease":true,"assets":[{"name":"GE-Proton11-13-x86_64.tar.gz"}]},
	 {"tag_name":"GE-Proton11-10","assets":[{"name":"GE-Proton11-10-aarch64.tar.gz"}]},
	 {"tag_name":"../evil","assets":[{"name":"../evil.tar.gz"}]}
	]`
	list, err := parseReleases(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Version != "GE-Proton11-12" || !list[0].Pinned || list[1].Version != "GE-Proton11-9" {
		t.Fatalf("list = %+v", list)
	}
}

func TestUnitNamesProtonVersion(t *testing.T) {
	g := enshrouded(t)
	if got := unitProtonVersion(renderUnit(g, "GE-Proton11-9")); got != "GE-Proton11-9" {
		t.Fatalf("version = %q", got)
	}
	if got := unitProtonVersion("ExecStart=/usr/bin/wine x.exe"); got != "" {
		t.Fatalf("version = %q", got)
	}
}

func TestDeleteProtonRefusesUsedVersion(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	g := enshrouded(t)
	for _, v := range []string{"GE-Proton11-9", "GE-Proton11-12"} {
		os.MkdirAll(protonDir(v), 0o755)
		os.WriteFile(filepath.Join(protonDir(v), "proton"), []byte("x"), 0o755)
	}
	if err := os.WriteFile(g.unitPath(), []byte(renderUnit(g, "GE-Proton11-9")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := deleteProton("GE-Proton11-9"); err == nil || !strings.Contains(err.Error(), "enshrouded") {
		t.Fatalf("err = %v", err)
	}
	if err := deleteProton("GE-Proton11-12"); err != nil {
		t.Fatal(err)
	}
	if protonReady("GE-Proton11-12") || !protonReady("GE-Proton11-9") {
		t.Fatal("wrong version removed")
	}
	if err := deleteProton("../backups"); err == nil {
		t.Fatal("traversal accepted")
	}
}

func TestProtonDirCannotBeAGame(t *testing.T) {
	if gameID.MatchString(filepath.Base(protonsDir())) {
		t.Fatal("a game could take over the shared Proton directory")
	}
}
