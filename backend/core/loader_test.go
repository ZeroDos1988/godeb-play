package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, dir, id, body string) {
	t.Helper()
	path := filepath.Join(dir, id)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMountsOnlyReadyPlugins(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "demo", `{"id":"demo","name":"Demo","description":"Beispiel","icon":"server","group":"network","order":20}`)
	writeManifest(t, dir, "ghost", `{"id":"ghost","name":"Geist","description":"ohne Handler","icon":"server","order":10}`)
	writeManifest(t, dir, "bad", `{"id":"other","name":"Falsch","description":"id weicht ab","icon":"server"}`)
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := NewRegistry()
	reg.Register("demo", func(mux *http.ServeMux) {
		mux.HandleFunc("GET /api/plugins/demo/ping", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
	})

	mux := http.NewServeMux()
	metas, err := reg.Load(dir, mux)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("metas = %#v", metas)
	}
	if metas[0].ID != "ghost" || metas[0].Ready {
		t.Fatalf("first = %#v", metas[0])
	}
	if metas[0].Group != "apps" {
		t.Fatalf("group fallback = %q", metas[0].Group)
	}
	if metas[1].ID != "demo" || !metas[1].Ready || metas[1].Name != "Demo" || metas[1].Group != "network" {
		t.Fatalf("second = %#v", metas[1])
	}

	ok := httptest.NewRecorder()
	mux.ServeHTTP(ok, httptest.NewRequest(http.MethodGet, "/api/plugins/demo/ping", nil))
	if ok.Code != http.StatusNoContent {
		t.Fatalf("demo status = %d", ok.Code)
	}

	missing := httptest.NewRecorder()
	mux.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/plugins/ghost/ping", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("ghost status = %d", missing.Code)
	}
}

func TestLoadMissingDirectory(t *testing.T) {
	metas, err := NewRegistry().Load(filepath.Join(t.TempDir(), "missing"), http.NewServeMux())
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 0 {
		t.Fatalf("metas = %#v", metas)
	}
}
