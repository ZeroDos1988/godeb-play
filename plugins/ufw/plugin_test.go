package ufw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectsUnsafeRule(t *testing.T) {
	mux := http.NewServeMux()
	Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/api/plugins/ufw/rules", strings.NewReader(`{"action":"allow","rule":"22/tcp;id"}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
}
