package auth

import (
	"database/sql"
	"errors"
	"net/http"
	"regexp"
	"time"

	"godebplay/backend/core"
)

var hexColor = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// ThemeSettings is the persisted appearance of one account.
type ThemeSettings struct {
	ThemeMode    string `json:"themeMode"`
	ColorPrimary string `json:"colorPrimary"`
	ColorBg      string `json:"colorBg"`
	ColorAccent  string `json:"colorAccent"`
	ColorText    string `json:"colorText"`
	Language     string `json:"language"`
}

func allowedLanguage(code string) bool {
	switch code {
	case "", "de", "en", "es", "fr", "pt", "zh", "ar":
		return true
	default:
		return false
	}
}

func defaultTheme() ThemeSettings {
	return ThemeSettings{
		ThemeMode:    "system",
		ColorPrimary: "#a80030",
		ColorBg:      "#f3efe6",
		ColorAccent:  "#246b45",
		ColorText:    "#1c1915",
	}
}

func (h handlers) getSettings(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	username, err := SessionUser(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	settings, err := loadSettings(username)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Einstellungen nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, settings)
}

func (h handlers) saveSettings(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	username, err := SessionUser(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	var req ThemeSettings
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	if req.ThemeMode != "light" && req.ThemeMode != "dark" && req.ThemeMode != "system" && req.ThemeMode != "custom" {
		core.WriteError(w, http.StatusBadRequest, "themeMode muss light, dark, system oder custom sein")
		return
	}
	for _, color := range []string{req.ColorPrimary, req.ColorBg, req.ColorAccent, req.ColorText} {
		if !hexColor.MatchString(color) {
			core.WriteError(w, http.StatusBadRequest, "Farben müssen als #rrggbb angegeben werden")
			return
		}
	}
	if !allowedLanguage(req.Language) {
		core.WriteError(w, http.StatusBadRequest, "Sprache wird nicht unterstützt")
		return
	}
	if err := storeSettings(username, req); err != nil {
		core.WriteError(w, http.StatusInternalServerError, "Einstellungen nicht gespeichert")
		return
	}
	core.WriteJSON(w, http.StatusOK, req)
}

func loadSettings(username string) (ThemeSettings, error) {
	fallback := defaultTheme()
	conn, err := ready()
	if err != nil {
		return fallback, err
	}
	var settings ThemeSettings
	err = conn.QueryRow(
		`SELECT theme_mode, color_primary, color_bg, color_accent, color_text, language FROM user_settings WHERE username = ?`,
		username,
	).Scan(&settings.ThemeMode, &settings.ColorPrimary, &settings.ColorBg, &settings.ColorAccent, &settings.ColorText, &settings.Language)
	if errors.Is(err, sql.ErrNoRows) {
		return fallback, nil
	}
	if err != nil {
		return fallback, err
	}
	return settings, nil
}

func storeSettings(username string, settings ThemeSettings) error {
	conn, err := ready()
	if err != nil {
		return err
	}
	_, err = conn.Exec(
		`INSERT INTO user_settings (username, theme_mode, color_primary, color_bg, color_accent, color_text, language, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(username) DO UPDATE SET
		   theme_mode = excluded.theme_mode,
		   color_primary = excluded.color_primary,
		   color_bg = excluded.color_bg,
		   color_accent = excluded.color_accent,
		   color_text = excluded.color_text,
		   language = excluded.language,
		   updated_at = excluded.updated_at`,
		username, settings.ThemeMode, settings.ColorPrimary, settings.ColorBg, settings.ColorAccent, settings.ColorText, settings.Language,
		now().UTC().Format(time.RFC3339),
	)
	return err
}
