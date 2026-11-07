package db

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestQuickCheckFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	t.Setenv("GODEB_DB", filepath.Join(dir, "godeb.db"))
	t.Setenv("GODEB_MASTER_KEY", filepath.Join(dir, "master.key"))
	if _, err := Open(); err != nil {
		t.Fatal(err)
	}
	if found, err := QuickCheckFile(ctx, filepath.Join(dir, "godeb.db")); !found || err != nil {
		t.Fatalf("healthy db: found=%v err=%v", found, err)
	}
	if found, err := QuickCheckFile(ctx, filepath.Join(dir, "missing.db")); found || err != nil {
		t.Fatalf("missing db: found=%v err=%v", found, err)
	}
	broken := filepath.Join(dir, "broken.db")
	if err := os.WriteFile(broken, []byte("SQLite format 3\x00 but nothing else"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := QuickCheckFile(ctx, broken); err == nil {
		t.Fatal("broken db passed")
	}
}
