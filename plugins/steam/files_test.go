package steam

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A compromised game account controls everything below its base directory.
// These tests plant symlinks there and check that root never acts outside.

func baseRoot(t *testing.T) (string, *os.Root, string) {
	t.Helper()
	base := t.TempDir()
	outside := t.TempDir()
	r, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return base, r, outside
}

func TestReadConfigDoesNotFollowSymlinkOut(t *testing.T) {
	base, r, outside := baseRoot(t)
	secret := filepath.Join(outside, "shadow")
	if err := os.WriteFile(secret, []byte("root:secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(base, "server"), 0o750)
	if err := os.Symlink(secret, filepath.Join(base, "server", "enshrouded_server.json")); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLimited(r, "server/enshrouded_server.json", maxConfigSize); err == nil {
		t.Fatalf("read through symlink: %q", raw)
	}
}

func TestWriteAtomicReplacesSymlinkInsteadOfWritingThrough(t *testing.T) {
	base, r, outside := baseRoot(t)
	target := filepath.Join(outside, "passwd")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(base, "server"), 0o750)
	link := filepath.Join(base, "server", "enshrouded_server.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(r, "server/enshrouded_server.json", []byte("{}\n"), 0o640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "keep" {
		t.Fatalf("wrote through the symlink: %q", got)
	}
	if info, err := os.Lstat(link); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("config is not a regular file now: %v %v", info, err)
	}
}

func TestDirectorySwappedForSymlinkStaysInside(t *testing.T) {
	base, r, outside := baseRoot(t)
	// The game replaces its server directory with a link to /etc (here: outside).
	if err := os.Symlink(outside, filepath.Join(base, "server")); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(r, "server/x.json", []byte("x"), 0o640, os.Getuid(), os.Getgid()); err == nil {
		t.Fatal("wrote through a symlinked directory")
	}
	if err := chownTreeIn(r, "server", os.Getuid(), os.Getgid()); err != nil && !strings.Contains(err.Error(), "escapes") && !os.IsNotExist(err) {
		t.Logf("chownTreeIn: %v", err)
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("files appeared outside: %v", entries)
	}
}

func TestBackupSkipsSymlinksAndRestoreRoundTrip(t *testing.T) {
	base, r, outside := baseRoot(t)
	secret := filepath.Join(outside, "shadow")
	os.WriteFile(secret, []byte("root:secret"), 0o600)
	save := filepath.Join(base, "server", "savegame")
	os.MkdirAll(filepath.Join(save, "sub"), 0o750)
	os.WriteFile(filepath.Join(save, "world.sav"), []byte("world"), 0o640)
	os.WriteFile(filepath.Join(save, "sub", "char.sav"), []byte("char"), 0o640)
	os.Symlink(secret, filepath.Join(save, "steal"))

	var buf bytes.Buffer
	if err := writeTarGzFrom(&buf, r, "server/savegame"); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(buf.Bytes(), []byte("root:secret")) {
		t.Fatal("backup followed a symlink")
	}
	if err := r.RemoveAll("server/savegame"); err != nil {
		t.Fatal(err)
	}
	if err := r.MkdirAll("server/savegame", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := extractTarGzIn(bytes.NewReader(buf.Bytes()), r, "server/savegame", os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"world.sav": "world", "sub/char.sav": "char"} {
		if got, err := os.ReadFile(filepath.Join(save, name)); err != nil || string(got) != want {
			t.Errorf("%s = %q, %v", name, got, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(save, "steal")); err == nil {
		t.Error("symlink restored")
	}
}

func TestBackupSaveListAndPrune(t *testing.T) {
	t.Setenv("GODEB_STEAM_ROOT", t.TempDir())
	g := enshrouded(t)
	os.MkdirAll(filepath.Join(g.serverDir(), "savegame"), 0o750)
	os.WriteFile(filepath.Join(g.serverDir(), "savegame", "w.sav"), []byte("w"), 0o640)
	r, err := g.openBase()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	name, err := backupSave(g, r, "manual")
	if err != nil || !backupName.MatchString(name) {
		t.Fatalf("backup %q: %v", name, err)
	}
	if info, _ := os.Stat(backupDir(g)); info.Mode().Perm() != 0o700 {
		t.Fatalf("backup dir mode %v", info.Mode())
	}
	for i := 0; i < maxBackups+3; i++ {
		f := filepath.Join(backupDir(g), "2026010"+string(rune('1'+i%9))+"-0000"+string(rune('0'+i%10))+"0-update.tar.gz")
		os.WriteFile(f, nil, 0o600)
	}
	pruneBackups(g)
	if got := listBackups(g); len(got) != maxBackups || got[0].Name != name {
		t.Fatalf("after prune: %d, newest %v", len(got), got[0])
	}
}

func TestBackupNameRejectsTraversal(t *testing.T) {
	for _, bad := range []string{"../x.tar.gz", "20260101-000000-manual.tar.gz/../../etc", "20260101-000000-evil.tar.gz", ""} {
		if backupName.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
