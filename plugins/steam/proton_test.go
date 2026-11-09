package steam

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
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

func TestChecksumMismatchIsRejected(t *testing.T) {
	sum := sha256.Sum256([]byte("tampered"))
	if err := checkSHA256(sum[:], protonSHA256); err == nil || !strings.Contains(err.Error(), "Prüfsumme") {
		t.Fatalf("err = %v", err)
	}
	if len(protonSHA256) != 64 || strings.Trim(protonSHA256, "0123456789abcdef") != "" {
		t.Fatal("pinned hash is not a SHA-256")
	}
}

func TestProtonDirCannotBeAGame(t *testing.T) {
	if gameID.MatchString(filepath.Base(protonsDir())) {
		t.Fatal("a game could take over the shared Proton directory")
	}
}
