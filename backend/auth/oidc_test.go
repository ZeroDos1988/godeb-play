package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOIDCConfigRoundTripAndAllowList(t *testing.T) {
	setup(t)
	if err := SetPassword("admin", "correct horse battery"); err != nil {
		t.Fatal(err)
	}
	cfg := OIDCConfig{
		ID:           "microsoft",
		TenantID:     "contoso.onmicrosoft.com",
		ClientID:     "app-id",
		ClientSecret: "secret-value",
		Enabled:      true,
		Admins:       []OIDCAdmin{{Email: "Admin@Example.com", Username: "admin"}},
	}
	if err := storeOIDC(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := loadOIDCConfig("microsoft", false)
	if err != nil {
		t.Fatal(err)
	}
	if !got.SecretSet || got.ClientSecret != "" || got.Admins[0].Email != "admin@example.com" {
		t.Fatalf("stored = %+v", got)
	}
	if err := storeOIDC(OIDCConfig{ID: "microsoft", TenantID: cfg.TenantID, ClientID: cfg.ClientID, Enabled: true, Admins: cfg.Admins}); err != nil {
		t.Fatal(err)
	}
	got, err = loadOIDCConfig("microsoft", true)
	if err != nil || got.ClientSecret != "secret-value" {
		t.Fatalf("secret kept = %+v err=%v", got, err)
	}
	user, ok := matchOIDCAdmin(got, "admin@example.com")
	if !ok || user != "admin" {
		t.Fatalf("match = %q %v", user, ok)
	}
	if _, ok := matchOIDCAdmin(got, "other@example.com"); ok {
		t.Fatal("unknown email matched")
	}

	issuer, err := oidcIssuer(got)
	if err != nil || issuer != "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0" {
		t.Fatalf("issuer = %s err=%v", issuer, err)
	}
	google, err := oidcIssuer(OIDCConfig{ID: "google"})
	if err != nil || google != "https://accounts.google.com" {
		t.Fatalf("google = %s err=%v", google, err)
	}

	public, err := publicOIDCProviders()
	if err != nil || len(public) != 2 || !public[0].Enabled || public[0].Name != "Microsoft Entra ID" || public[1].Enabled {
		t.Fatalf("public = %+v err=%v", public, err)
	}
}

func TestOIDCStartRejectsUnconfiguredProvider(t *testing.T) {
	setup(t)
	mux := http.NewServeMux()
	Mount(mux, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/google/start", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "nicht eingerichtet") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestOIDCConfigRequiresSession(t *testing.T) {
	setup(t)
	mux := http.NewServeMux()
	Mount(mux, nil)
	req := httptest.NewRequest(http.MethodPut, "/api/auth/oidc/providers/google", strings.NewReader(`{"clientId":"x","enabled":false,"admins":[]}`))
	rec := httptest.NewRecorder()
	RequireSession(mux).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}
