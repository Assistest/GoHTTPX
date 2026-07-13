package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealth(t *testing.T) {
	s := newServer("secret", 48<<20, 24*time.Hour)

	health := httptest.NewRecorder()
	s.routes().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}
	var h healthResponse
	if err := json.Unmarshal(health.Body.Bytes(), &h); err != nil {
		t.Fatal(err)
	}
	if h.Status != "ok" || h.ProtocolVersion != 1 {
		t.Fatalf("health = %#v", h)
	}
}

func TestCapabilitiesRequiresToken(t *testing.T) {
	s := newServer("secret", 48<<20, 24*time.Hour)
	unauthorized := httptest.NewRecorder()
	s.routes().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}
	var apiErr errorResponse
	if err := json.Unmarshal(unauthorized.Body.Bytes(), &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "UNAUTHORIZED" {
		t.Fatalf("error = %#v", apiErr)
	}

	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil)
	req.Header.Set("Authorization", "Bearer secret")
	s.routes().ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", authorized.Code)
	}
}
