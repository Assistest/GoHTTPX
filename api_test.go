package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

var expectedFingerprints = []string{
	"360_11_0", "360_7_5", "360_auto", "android_11_okhttp", "chrome_100", "chrome_100_psk",
	"chrome_102", "chrome_106_shuffle", "chrome_112_psk_shuffle", "chrome_114_padding_psk_shuffle",
	"chrome_115_pq", "chrome_115_pq_psk", "chrome_120", "chrome_120_pq", "chrome_131", "chrome_133",
	"chrome_58", "chrome_62", "chrome_70", "chrome_72", "chrome_83", "chrome_87", "chrome_96",
	"chrome_auto", "edge_106", "edge_85", "edge_auto", "firefox_102", "firefox_105", "firefox_120",
	"firefox_55", "firefox_56", "firefox_63", "firefox_65", "firefox_99", "firefox_auto", "golang",
	"ios_11_1", "ios_12_1", "ios_13", "ios_14", "ios_auto", "qq_11_1", "qq_auto", "randomized",
	"randomized_alpn", "randomized_no_alpn", "safari_16_0", "safari_auto",
}

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

func TestFingerprintCatalogHasAndroidDefault(t *testing.T) {
	if _, ok := fingerprints["android_11_okhttp"]; !ok {
		t.Fatal("missing android_11_okhttp")
	}
	if len(fingerprints) != 49 {
		t.Fatalf("fingerprints count = %d", len(fingerprints))
	}
}

func TestFingerprintCapabilitiesAreCompleteAndSorted(t *testing.T) {
	s := newServer("", 48<<20, 24*time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d", response.Code)
	}
	var capabilities struct {
		TLSFingerprints []string `json:"tls_fingerprints"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(capabilities.TLSFingerprints, expectedFingerprints) {
		t.Fatalf("tls_fingerprints = %#v", capabilities.TLSFingerprints)
	}
}

func TestClientLifecycleUsesDefaultFingerprintAndDeleteIsIdempotent(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	handler := s.routes()
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(`{"protocol_version":1}`)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", created.Code, created.Body.String())
	}
	var response createClientResponse
	if err := json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.ProtocolVersion != protocolVersion || len(response.ClientID) != 32 || response.ExpiresAt.IsZero() {
		t.Fatalf("create response = %#v", response)
	}

	s.mu.RLock()
	session := s.clients[response.ClientID]
	s.mu.RUnlock()
	if session == nil {
		t.Fatal("client session was not stored")
	}
	if session.config.TLSFingerprint != "android_11_okhttp" {
		t.Fatalf("tls fingerprint = %q", session.config.TLSFingerprint)
	}
	if session.client.GetClient().Jar != nil {
		t.Fatal("client cookie jar must be disabled")
	}

	for i := 0; i < 2; i++ {
		deleted := httptest.NewRecorder()
		handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/v1/clients/"+response.ClientID, nil))
		if deleted.Code != http.StatusNoContent {
			t.Fatalf("delete %d status = %d", i+1, deleted.Code)
		}
	}
}

func TestClientLifecycleRejectsUnsupportedFingerprint(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(`{"protocol_version":1,"tls_fingerprint":"not-a-fingerprint"}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var apiErr errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "UNSUPPORTED_FEATURE" {
		t.Fatalf("error = %#v", apiErr)
	}
}

func TestIdleCleanupKeepsActiveAndRecentClients(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	now := time.Now()
	client, err := buildReqClient(createClientRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s.clients = map[string]*clientSession{
		"expired": {client: client, lastUsed: now.Add(-2 * time.Hour)},
		"active":  {client: client, lastUsed: now.Add(-2 * time.Hour), activeCalls: 1},
		"recent":  {client: client, lastUsed: now.Add(-time.Minute)},
	}

	s.cleanupIdleClients(now)

	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.clients["expired"]; ok {
		t.Fatal("expired client was not removed")
	}
	if s.clients["active"] == nil || s.clients["recent"] == nil {
		t.Fatalf("remaining clients = %#v", s.clients)
	}
}
