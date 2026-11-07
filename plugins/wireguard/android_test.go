package wireguard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHandleAndroidInfoMissing(t *testing.T) {
	// Ensure default path is missing in the test environment.
	if _, err := os.Stat(apkPath()); err == nil {
		t.Skip("APK (current or legacy name) already present on this host")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/plugins/wireguard/android", nil)
	req.Host = "godeb.local:8080"
	handleAndroidInfo(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var info androidClientInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info.Available {
		t.Fatal("expected unavailable")
	}
	if info.DownloadPath != "/api/plugins/wireguard/android/apk" {
		t.Fatalf("downloadPath = %q", info.DownloadPath)
	}
}

func TestHandleAndroidAPKServesFile(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "test.apk")
	payload := []byte("PK\x03\x04-fake-apk")
	if err := os.WriteFile(apk, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/apk", nil)
	http.ServeContent(rec, req, "godeb-wireguard.apk", st.ModTime(), f)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Body.Bytes(); string(got) != string(payload) {
		t.Fatalf("body = %q", got)
	}
}
