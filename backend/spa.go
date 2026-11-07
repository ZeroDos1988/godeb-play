package main

import (
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Go's built-in MIME table lacks the web app manifest; with nosniff the
// browser relies on the declared type.
func init() {
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
}

func spaHandler(dist string) http.Handler {
	dist = filepath.Clean(dist)
	index := filepath.Join(dist, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		full, ok := resolveDistFile(dist, r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		info, err := os.Stat(full)
		if err != nil || info.IsDir() {
			http.ServeFile(w, r, index)
			return
		}
		http.ServeFile(w, r, full)
	})
}

// resolveDistFile maps a URL path onto dist and rejects paths that escape it.
func resolveDistFile(dist, urlPath string) (string, bool) {
	dist = filepath.Clean(dist)
	rel := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if rel == "" || rel == "." {
		return filepath.Join(dist, "index.html"), true
	}
	full := filepath.Join(dist, rel)
	if full != dist && !strings.HasPrefix(full, dist+string(os.PathSeparator)) {
		return "", false
	}
	return full, true
}
