package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSealOpenAndKeyFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GODEB_MASTER_KEY", filepath.Join(dir, "master.key"))

	sealed, err := Seal("totp-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "v1:") || strings.Contains(sealed, "totp-secret-value") {
		t.Fatalf("sealed = %q", sealed)
	}
	again, err := Seal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if again != sealed {
		t.Fatal("Seal encrypted an already sealed value")
	}
	plain, err := Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "totp-secret-value" {
		t.Fatalf("plain = %q", plain)
	}
	if legacy, err := Open("still-legacy"); err != nil || legacy != "still-legacy" {
		t.Fatalf("legacy = %q err=%v", legacy, err)
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Fatalf("key mode=%v size=%d", info.Mode().Perm(), info.Size())
	}
	other, err := Seal("totp-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if other == sealed {
		t.Fatal("nonce was reused")
	}
}
