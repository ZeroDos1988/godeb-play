package wireguard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"godebplay/backend/core"
)

const (
	androidDir      = "/etc/godeb-play/android"
	androidAPKName  = "godeb-tunnel.apk"
	androidVersion  = "version.txt"
	androidToken    = "download.token"
	androidAPKPath  = androidDir + "/" + androidAPKName
	androidVerPath  = androidDir + "/" + androidVersion
	androidTokPath  = androidDir + "/" + androidToken
	defaultAPKLabel = "godeb-tunnel.apk"
	// legacyAPKPath is the file name before the app was renamed to GoDeb
	// Tunnel; servers set up earlier still serve it.
	legacyAPKPath = androidDir + "/godeb-wireguard.apk"
)

// apkPath returns the APK to serve: the current name, else the old one.
func apkPath() string {
	if _, err := os.Stat(androidAPKPath); err == nil {
		return androidAPKPath
	}
	if _, err := os.Stat(legacyAPKPath); err == nil {
		return legacyAPKPath
	}
	return androidAPKPath
}

type androidClientInfo struct {
	Available     bool   `json:"available"`
	Filename      string `json:"filename"`
	Size          int64  `json:"size,omitempty"`
	Version       string `json:"version,omitempty"`
	Modified      string `json:"modified,omitempty"`
	DownloadPath  string `json:"downloadPath"`
	TokenRequired bool   `json:"tokenRequired"`
	TokenSet      bool   `json:"tokenSet"` // admin UI only; same as TokenRequired
	Detail        string `json:"detail,omitempty"`
}

func mountAndroid(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/plugins/wireguard/android", handleAndroidInfo)
	mux.HandleFunc("GET /api/plugins/wireguard/android/apk", handleAndroidAPK)
	mux.HandleFunc("GET /api/plugins/wireguard/android/token", handleAndroidTokenGet)
	mux.HandleFunc("POST /api/plugins/wireguard/android/token", handleAndroidToken)
}

func handleAndroidInfo(w http.ResponseWriter, r *http.Request) {
	tok := readAPKToken()
	info := androidClientInfo{
		Filename:      defaultAPKLabel,
		DownloadPath:  "/api/plugins/wireguard/android/apk",
		TokenRequired: tok != "",
		TokenSet:      tok != "",
	}
	path := apkPath()
	st, err := os.Stat(path)
	if err != nil {
		info.Detail = "Keine APK unter " + androidAPKPath + ". Signierte Release-APK von github.com/ZeroDos1988/godeb-tunnel-android dort ablegen."
		core.WriteJSON(w, http.StatusOK, info)
		return
	}
	if st.IsDir() {
		info.Detail = path + " ist ein Verzeichnis"
		core.WriteJSON(w, http.StatusOK, info)
		return
	}
	info.Available = true
	info.Size = st.Size()
	info.Modified = st.ModTime().UTC().Format(time.RFC3339)
	if ver, err := os.ReadFile(androidVerPath); err == nil {
		info.Version = strings.TrimSpace(string(ver))
	}
	core.WriteJSON(w, http.StatusOK, info)
}

func handleAndroidAPK(w http.ResponseWriter, r *http.Request) {
	if want := readAPKToken(); want != "" {
		got := strings.TrimSpace(r.URL.Query().Get("token"))
		if got == "" {
			got = strings.TrimSpace(r.Header.Get("X-GoDeb-APK-Token"))
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			core.WriteError(w, http.StatusUnauthorized, "APK-Token fehlt oder ist falsch")
			return
		}
	}
	f, err := os.Open(apkPath())
	if err != nil {
		if os.IsNotExist(err) {
			core.WriteError(w, http.StatusNotFound, "Android-APK nicht vorhanden")
			return
		}
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", `attachment; filename="`+defaultAPKLabel+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, defaultAPKLabel, st.ModTime(), f)
}

func handleAndroidTokenGet(w http.ResponseWriter, r *http.Request) {
	tok := readAPKToken()
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"tokenSet": tok != "",
		"token":    tok,
		"path":     "/api/plugins/wireguard/android/apk",
	})
}

func handleAndroidToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"` // generate | clear
	}
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	switch req.Action {
	case "generate":
		tok, err := newAPKToken()
		if err != nil {
			core.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := writeAPKToken(tok); err != nil {
			core.WriteError(w, http.StatusInternalServerError, err.Error())
			return
		}
		core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "tokenSet": true, "token": tok})
	case "clear":
		_ = os.Remove(androidTokPath)
		core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "tokenSet": false})
	default:
		core.WriteError(w, http.StatusBadRequest, "action muss generate oder clear sein")
	}
}

func readAPKToken() string {
	b, err := os.ReadFile(androidTokPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func newAPKToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeAPKToken(tok string) error {
	if err := os.MkdirAll(androidDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(androidDir, ".token-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), androidTokPath)
}
