package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"godebplay/backend/security"

	"godebplay/backend/core"
)

const oidcCookie = "godeb_oidc"

var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,63}$`)

// OIDCProvider is the public description of a configured identity provider.
type OIDCProvider struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	TenantID string `json:"tenantId,omitempty"`
	ClientID string `json:"clientId,omitempty"`
}

// OIDCConfig is the stored provider setup, including the admin allow-list.
type OIDCConfig struct {
	ID           string      `json:"id"`
	TenantID     string      `json:"tenantId"`
	ClientID     string      `json:"clientId"`
	ClientSecret string      `json:"clientSecret,omitempty"`
	SecretSet    bool        `json:"secretSet"`
	Enabled      bool        `json:"enabled"`
	Admins       []OIDCAdmin `json:"admins"`
}

// OIDCAdmin maps an IdP email address to a local GoDeb account.
type OIDCAdmin struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

type oidcTx struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Nonce    string `json:"n"`
	Provider string `json:"p"`
}

func knownProvider(id string) (string, bool) {
	switch id {
	case "microsoft":
		return "Microsoft Entra ID", true
	case "google":
		return "Google", true
	default:
		return "", false
	}
}

func (h handlers) listOIDCProviders(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	providers, err := publicOIDCProviders()
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "OIDC-Konfiguration nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"providers": providers})
}

func (h handlers) getOIDCConfig(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, err := SessionUser(r); err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	configs, err := loadOIDCConfigs(false)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "OIDC-Konfiguration nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"providers": configs})
}

func (h handlers) saveOIDCConfig(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if _, err := SessionUser(r); err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung erforderlich")
		return
	}
	var req OIDCConfig
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	req.ID = r.PathValue("id")
	if _, ok := knownProvider(req.ID); !ok {
		core.WriteError(w, http.StatusNotFound, "Unbekannter Anbieter")
		return
	}
	if err := validateOIDC(req); err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := storeOIDC(req); err != nil {
		core.WriteError(w, http.StatusInternalServerError, "OIDC-Konfiguration nicht gespeichert")
		return
	}
	saved, err := loadOIDCConfig(req.ID, false)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "OIDC-Konfiguration nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, saved)
}

func (h handlers) startOIDC(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id := r.PathValue("id")
	cfg, err := loadOIDCConfig(id, true)
	if err != nil || !cfg.Enabled || cfg.ClientID == "" || cfg.ClientSecret == "" {
		core.WriteError(w, http.StatusConflict, "Dieser Anbieter ist nicht eingerichtet")
		return
	}
	issuer, err := oidcIssuer(cfg)
	if err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	provider, err := oidc.NewProvider(r.Context(), issuer)
	if err != nil {
		core.WriteError(w, http.StatusBadGateway, "OIDC-Discovery fehlgeschlagen")
		return
	}
	tx := oidcTx{State: randomToken(), Verifier: oauth2.GenerateVerifier(), Nonce: randomToken(), Provider: id}
	setCookie(w, r, oidcCookie, encodeTx(tx), "/api/auth/oidc", 10*time.Minute)
	target := oauthConfig(r, cfg, provider).AuthCodeURL(tx.State, oauth2.S256ChallengeOption(tx.Verifier), oidc.Nonce(tx.Nonce))
	http.Redirect(w, r, target, http.StatusFound)
}

func (h handlers) callbackOIDC(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id := r.PathValue("id")
	if r.URL.Query().Get("error") != "" {
		core.WriteError(w, http.StatusUnauthorized, "Anmeldung beim Anbieter abgebrochen")
		return
	}
	cookie, err := r.Cookie(oidcCookie)
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, "OIDC-Anmeldung ist abgelaufen")
		return
	}
	tx, err := decodeTx(cookie.Value)
	if err != nil || tx.Provider != id || tokenDiffers(tx.State, r.URL.Query().Get("state")) {
		core.WriteError(w, http.StatusBadRequest, "OIDC-Status stimmt nicht")
		return
	}
	clearCookie(w, r, oidcCookie, "/api/auth/oidc")
	cfg, err := loadOIDCConfig(id, true)
	if err != nil || !cfg.Enabled {
		core.WriteError(w, http.StatusConflict, "Dieser Anbieter ist nicht eingerichtet")
		return
	}
	issuer, err := oidcIssuer(cfg)
	if err != nil {
		core.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	provider, err := oidc.NewProvider(r.Context(), issuer)
	if err != nil {
		core.WriteError(w, http.StatusBadGateway, "OIDC-Discovery fehlgeschlagen")
		return
	}
	token, err := oauthConfig(r, cfg, provider).Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		h.fail(r, id)
		core.WriteError(w, http.StatusUnauthorized, "OIDC-Code wurde abgelehnt")
		return
	}
	raw, _ := token.Extra("id_token").(string)
	checked, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(r.Context(), raw)
	if err != nil || checked.Nonce != tx.Nonce {
		h.fail(r, id)
		core.WriteError(w, http.StatusUnauthorized, "OIDC-Token ist ungültig")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Preferred     string `json:"preferred_username"`
	}
	if err := checked.Claims(&claims); err != nil {
		core.WriteError(w, http.StatusUnauthorized, "OIDC-Token enthält keine Ansprüche")
		return
	}
	email := claims.Email
	if email == "" {
		email = claims.Preferred
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		core.WriteError(w, http.StatusForbidden, "Die E-Mail-Adresse ist nicht bestätigt")
		return
	}
	username, ok := matchOIDCAdmin(cfg, email)
	if !ok {
		h.fail(r, email)
		core.WriteError(w, http.StatusForbidden, "Diese E-Mail-Adresse ist nicht als Administrator zugelassen")
		return
	}
	if err := h.beginPending(w, r, username); err != nil {
		core.WriteError(w, http.StatusForbidden, err.Error())
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h handlers) resumeOIDC(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	pending, err := pendingSession(r)
	if err != nil {
		core.WriteError(w, http.StatusUnauthorized, "Keine laufende Anmeldung")
		return
	}
	username := pending.Username
	enrolled, _, err := secondFactor.Status(username)
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, "2FA-Status nicht lesbar")
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"username":            username,
		"enrollment_required": !enrolled,
	})
}

func (h handlers) beginPending(w http.ResponseWriter, r *http.Request, username string) error {
	hash, err := passwordHash(username)
	if err != nil {
		return errors.New("Für diese E-Mail gibt es kein lokales Konto")
	}
	token, err := startSession(r, username, stagePending, version(hash, ""), pendingTTL)
	if err != nil {
		return err
	}
	setCookie(w, r, PendingCookie, token, pendingPath, pendingTTL)
	return nil
}

func oauthConfig(r *http.Request, cfg OIDCConfig, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  oidcRedirect(r, cfg.ID),
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

func oidcIssuer(cfg OIDCConfig) (string, error) {
	switch cfg.ID {
	case "google":
		return "https://accounts.google.com", nil
	case "microsoft":
		if cfg.TenantID == "" {
			return "", errors.New("Microsoft braucht eine Tenant-ID")
		}
		return "https://login.microsoftonline.com/" + url.PathEscape(cfg.TenantID) + "/v2.0", nil
	default:
		return "", errors.New("Unbekannter Anbieter")
	}
}

func oidcRedirect(r *http.Request, id string) string {
	if base := strings.TrimRight(os.Getenv("GODEB_PUBLIC_URL"), "/"); base != "" {
		return base + "/api/auth/oidc/" + id + "/callback"
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/auth/oidc/" + id + "/callback"
}

func validateOIDC(cfg OIDCConfig) error {
	if cfg.Enabled && strings.TrimSpace(cfg.ClientID) == "" {
		return errors.New("Client-ID fehlt")
	}
	if cfg.ID == "microsoft" && cfg.Enabled && !tenantPattern.MatchString(cfg.TenantID) {
		return errors.New("Tenant-ID ist ungültig")
	}
	if strings.ContainsAny(cfg.ClientID, " \t\r\n") || len(cfg.ClientID) > 200 {
		return errors.New("Client-ID ist ungültig")
	}
	seen := map[string]bool{}
	for _, admin := range cfg.Admins {
		email, err := normalizeEmail(admin.Email)
		if err != nil {
			return err
		}
		if seen[email] {
			return fmt.Errorf("E-Mail %s ist doppelt", email)
		}
		seen[email] = true
		if !ValidUsername(admin.Username) {
			return fmt.Errorf("Benutzer für %s ist ungültig", email)
		}
	}
	return nil
}

func normalizeEmail(raw string) (string, error) {
	addr, err := mail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || strings.Contains(addr.Address, " ") {
		return "", fmt.Errorf("E-Mail %q ist ungültig", raw)
	}
	return strings.ToLower(addr.Address), nil
}

func matchOIDCAdmin(cfg OIDCConfig, raw string) (string, bool) {
	email, err := normalizeEmail(raw)
	if err != nil {
		return "", false
	}
	for _, admin := range cfg.Admins {
		if strings.EqualFold(admin.Email, email) {
			return admin.Username, true
		}
	}
	return "", false
}

func publicOIDCProviders() ([]OIDCProvider, error) {
	configs, err := loadOIDCConfigs(false)
	if err != nil {
		return nil, err
	}
	out := make([]OIDCProvider, 0, len(configs))
	for _, cfg := range configs {
		name, _ := knownProvider(cfg.ID)
		out = append(out, OIDCProvider{ID: cfg.ID, Name: name, Enabled: cfg.Enabled && cfg.ClientID != "" && cfg.SecretSet})
	}
	return out, nil
}

func loadOIDCConfigs(withSecret bool) ([]OIDCConfig, error) {
	out := make([]OIDCConfig, 0, 2)
	for _, id := range []string{"microsoft", "google"} {
		cfg, err := loadOIDCConfig(id, withSecret)
		if err != nil {
			return nil, err
		}
		out = append(out, cfg)
	}
	return out, nil
}

func loadOIDCConfig(id string, withSecret bool) (OIDCConfig, error) {
	cfg := OIDCConfig{ID: id, Admins: []OIDCAdmin{}}
	if _, ok := knownProvider(id); !ok {
		return cfg, errors.New("Unbekannter Anbieter")
	}
	conn, err := ready()
	if err != nil {
		return cfg, err
	}
	var enabled int
	var secret string
	err = conn.QueryRow(
		`SELECT tenant_id, client_id, client_secret, enabled FROM oidc_providers WHERE id = ?`, id,
	).Scan(&cfg.TenantID, &cfg.ClientID, &secret, &enabled)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return cfg, err
	}
	opened, err := security.Open(secret)
	if err != nil {
		return cfg, err
	}
	cfg.Enabled = enabled == 1
	cfg.SecretSet = opened != ""
	if withSecret {
		cfg.ClientSecret = opened
	}
	rows, err := conn.Query(`SELECT email, username FROM oidc_admin_emails WHERE provider = ? ORDER BY email`, id)
	if err != nil {
		return cfg, err
	}
	defer rows.Close()
	for rows.Next() {
		var admin OIDCAdmin
		if err := rows.Scan(&admin.Email, &admin.Username); err != nil {
			return cfg, err
		}
		cfg.Admins = append(cfg.Admins, admin)
	}
	return cfg, rows.Err()
}

func storeOIDC(cfg OIDCConfig) error {
	conn, err := ready()
	if err != nil {
		return err
	}
	secret := cfg.ClientSecret
	if secret == "" {
		_ = conn.QueryRow(`SELECT client_secret FROM oidc_providers WHERE id = ?`, cfg.ID).Scan(&secret)
	} else {
		sealed, err := security.Seal(secret)
		if err != nil {
			return err
		}
		secret = sealed
	}
	enabled := 0
	if cfg.Enabled {
		enabled = 1
	}
	tx, err := conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(
		`INSERT INTO oidc_providers (id, tenant_id, client_id, client_secret, enabled) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id, client_id = excluded.client_id,
		   client_secret = excluded.client_secret, enabled = excluded.enabled`,
		cfg.ID, strings.TrimSpace(cfg.TenantID), strings.TrimSpace(cfg.ClientID), secret, enabled,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM oidc_admin_emails WHERE provider = ?`, cfg.ID); err != nil {
		return err
	}
	for _, admin := range cfg.Admins {
		email, err := normalizeEmail(admin.Email)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(
			`INSERT INTO oidc_admin_emails (provider, email, username) VALUES (?, ?, ?)`,
			cfg.ID, email, admin.Username,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func randomToken() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

func encodeTx(tx oidcTx) string {
	raw, _ := json.Marshal(tx)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeTx(raw string) (oidcTx, error) {
	var tx oidcTx
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return tx, err
	}
	err = json.Unmarshal(data, &tx)
	return tx, err
}

func tokenDiffers(a, b string) bool {
	if len(a) != len(b) {
		return true
	}
	diff := 0
	for i := range a {
		diff |= int(a[i] ^ b[i])
	}
	return diff != 0
}
