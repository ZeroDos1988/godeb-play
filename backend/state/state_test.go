package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileInsideDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_STATE_DIR", dir)
	p := filepath.Join(dir, "tls", "godeb.key")
	if err := WriteFile(p, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v %v", st, err)
	}
	if err := WriteFile(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "tls"))
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
}

func TestWriteFileRefusesSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	t.Setenv("GODEB_STATE_DIR", dir)
	if err := os.Symlink(outside, filepath.Join(dir, "tls")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(dir, "tls", "godeb.key"), []byte("x"), 0o600); err == nil {
		t.Fatal("write followed a symlink out of the state directory")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("file created outside: %v", entries)
	}
}

func TestCreateExclusive(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_STATE_DIR", dir)
	p := filepath.Join(dir, "setup-token")
	if err := CreateExclusive(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateExclusive(p, []byte("b"), 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second create: %v", err)
	}
}

func TestOutsideDirIsPlainWrite(t *testing.T) {
	t.Setenv("GODEB_STATE_DIR", t.TempDir())
	p := filepath.Join(t.TempDir(), "a", "b.json")
	if err := WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := HandOver(p); err != nil {
		t.Fatal(err)
	}
}
