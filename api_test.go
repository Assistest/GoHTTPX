package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
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

func TestClientLifecycleRejectsNonConfigurationJSON(t *testing.T) {
	tests := map[string]string{
		"headers":  `{"protocol_version":1,"headers":{"X-Test":"value"}}`,
		"cookies":  `{"protocol_version":1,"cookies":{"session":"secret"}}`,
		"trailing": `{"protocol_version":1} {}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			s := newServer("", 48<<20, time.Hour)
			response := httptest.NewRecorder()
			s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(body)))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var apiErr errorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &apiErr); err != nil {
				t.Fatal(err)
			}
			if apiErr.Error.Code != "INVALID_REQUEST" {
				t.Fatalf("error = %#v", apiErr)
			}
		})
	}
}

func TestBuildReqClientPreservesRawHTTPBehavior(t *testing.T) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write([]byte("compressed body")); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	acceptEncoding := make(chan string, 1)
	redirected := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/compressed":
			acceptEncoding <- r.Header.Get("Accept-Encoding")
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("X-Raw", "preserved")
			_, _ = w.Write(compressed.Bytes())
		case "/charset":
			w.Header().Set("Content-Type", "text/plain; charset=iso-8859-1")
			_, _ = w.Write([]byte{0xe9})
		case "/redirect":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			redirected <- struct{}{}
		}
	}))
	defer target.Close()

	client, err := buildReqClient(createClientRequest{})
	if err != nil {
		t.Fatal(err)
	}
	compressedResponse, err := client.R().Get(target.URL + "/compressed")
	if err != nil {
		t.Fatal(err)
	}
	if got := <-acceptEncoding; got != "" {
		t.Fatalf("Accept-Encoding = %q", got)
	}
	if compressedResponse.Header.Get("Content-Encoding") != "gzip" || compressedResponse.Header.Get("X-Raw") != "preserved" {
		t.Fatalf("response headers = %#v", compressedResponse.Header)
	}
	if !bytes.Equal(compressedResponse.Bytes(), compressed.Bytes()) {
		t.Fatalf("compressed body = %x", compressedResponse.Bytes())
	}

	charsetResponse, err := client.R().Get(target.URL + "/charset")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(charsetResponse.Bytes(), []byte{0xe9}) {
		t.Fatalf("charset body = %x", charsetResponse.Bytes())
	}

	redirectResponse, err := client.R().Get(target.URL + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	if redirectResponse.StatusCode != http.StatusFound {
		t.Fatalf("redirect status = %d", redirectResponse.StatusCode)
	}
	select {
	case <-redirected:
		t.Fatal("client followed redirect")
	default:
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

func addTestClient(t *testing.T, s *server) string {
	t.Helper()
	client, err := buildReqClient(createClientRequest{})
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "test-client"
	s.mu.Lock()
	s.clients[clientID] = &clientSession{client: client, lastUsed: time.Now()}
	s.mu.Unlock()
	return clientID
}

func sendRawRequest(t *testing.T, handler http.Handler, clientID string, input requestEnvelope) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+clientID+"/requests", bytes.NewReader(body)))
	return response
}

func decodeAPIError(t *testing.T, response *httptest.ResponseRecorder) apiError {
	t.Helper()
	var result errorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.Error
}

func TestRawRequestPreservesDuplicateHeadersAndBinaryBodies(t *testing.T) {
	var method string
	var duplicateHeaders []string
	var requestBody []byte
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		duplicateHeaders = r.Header.Values("X-Dupe")
		requestBody, _ = io.ReadAll(r.Body)
		w.Header().Add("Set-Cookie", "a=1")
		w.Header().Add("Set-Cookie", "b=2")
		w.Header().Set("X-Latin-1", string([]byte{0xff}))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte{3, 2, 1, 0xff})
	}))
	defer target.Close()

	s := newServer("", 48<<20, time.Hour)
	clientID := addTestClient(t, s)
	response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodPost,
		URL:             target.URL + "/raw",
		Headers:         [][2]string{{"X-Dupe", "first"}, {"X-Dupe", "\u00ff"}},
		BodyBase64:      base64.StdEncoding.EncodeToString([]byte{0, 1, 2, 0xff}),
	})
	if response.Code != http.StatusOK {
		t.Fatalf("control status = %d, body = %s", response.Code, response.Body.String())
	}
	if method != http.MethodPost || !reflect.DeepEqual(duplicateHeaders, []string{"first", string([]byte{0xff})}) || !bytes.Equal(requestBody, []byte{0, 1, 2, 0xff}) {
		t.Fatalf("target request method=%q headers=%q body=%x", method, duplicateHeaders, requestBody)
	}

	var result responseEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	decodedBody, err := base64.StdEncoding.DecodeString(result.BodyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProtocolVersion != protocolVersion || result.RequestID == "" || result.StatusCode != http.StatusCreated || result.ReasonPhrase != "Created" || result.URL != target.URL+"/raw" || result.HTTPVersion == "" || !bytes.Equal(decodedBody, []byte{3, 2, 1, 0xff}) {
		t.Fatalf("response envelope = %#v, body=%x", result, decodedBody)
	}
	var cookies []string
	latin1 := ""
	for _, pair := range result.Headers {
		switch pair[0] {
		case "Set-Cookie":
			cookies = append(cookies, pair[1])
		case "X-Latin-1":
			latin1 = pair[1]
		}
	}
	if !reflect.DeepEqual(cookies, []string{"a=1", "b=2"}) || latin1 != "\u00ff" {
		t.Fatalf("response headers = %#v", result.Headers)
	}
}

func TestRawRequestUsesHostHeader(t *testing.T) {
	var host string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodGet,
		URL:             target.URL,
		Headers:         [][2]string{{"host", "httpx.example"}},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("control status = %d, body = %s", response.Code, response.Body.String())
	}
	if host != "httpx.example" {
		t.Fatalf("upstream Host = %q", host)
	}
}

func TestAllMethods(t *testing.T) {
	var gotMethod string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	clientID := addTestClient(t, s)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions, "PURGE"} {
		t.Run(method, func(t *testing.T) {
			response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: method, URL: target.URL})
			if response.Code != http.StatusOK || gotMethod != method {
				t.Fatalf("control status=%d target method=%q body=%s", response.Code, gotMethod, response.Body.String())
			}
		})
	}
}

func TestUpstreamHTTPErrorIsAResponse(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "failed", http.StatusInternalServerError)
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL})
	if response.Code != http.StatusOK {
		t.Fatalf("control status = %d, body = %s", response.Code, response.Body.String())
	}
	var result responseEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusInternalServerError {
		t.Fatalf("upstream status = %d", result.StatusCode)
	}
}

func TestRawRequestRejectsOversizedResponseBeforeReadingBody(t *testing.T) {
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
	}))
	defer func() {
		close(release)
		target.Close()
	}()
	s := newServer("", 4, time.Hour)
	response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodGet,
		URL:             target.URL,
		TimeoutMS:       100,
	})
	if response.Code != http.StatusBadGateway || decodeAPIError(t, response).Code != "UPSTREAM_PROTOCOL_ERROR" {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRawRequestReusesConnectionAfterBoundedRead(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := newServer("", 4, time.Hour)
	clientID := addTestClient(t, s)
	var result responseEnvelope
	for i := 0; i < 2; i++ {
		response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{
			ProtocolVersion: protocolVersion,
			Method:          http.MethodGet,
			URL:             target.URL,
			Options:         requestOptions{Trace: true},
		})
		if response.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, body = %s", i+1, response.Code, response.Body.String())
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
	}
	if result.Trace == nil || !result.Trace.ConnectionReused {
		t.Fatalf("second trace = %#v", result.Trace)
	}
}

func TestRawRequestTrace(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodGet,
		URL:             target.URL,
		Options:         requestOptions{Trace: true},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("control status = %d, body = %s", response.Code, response.Body.String())
	}
	var result responseEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Trace == nil || result.Trace.RemoteAddress == "" || result.Trace.TotalMS < 0 {
		t.Fatalf("trace = %#v", result.Trace)
	}
}

func TestRequestValidation(t *testing.T) {
	tests := []struct {
		name string
		code string
		edit func(*requestEnvelope)
	}{
		{name: "protocol", code: "PROTOCOL_MISMATCH", edit: func(input *requestEnvelope) { input.ProtocolVersion = 2 }},
		{name: "empty method", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Method = "" }},
		{name: "invalid method", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Method = "BAD METHOD" }},
		{name: "long method", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Method = strings.Repeat("A", 65) }},
		{name: "relative URL", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.URL = "/relative" }},
		{name: "unsupported URL scheme", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.URL = "ftp://example.com/file" }},
		{name: "long URL", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.URL = "http://example.com/" + strings.Repeat("a", 16384) }},
		{name: "too many headers", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) {
			input.Headers = make([][2]string, 257)
			for i := range input.Headers {
				input.Headers[i] = [2]string{"X-Test", "a"}
			}
		}},
		{name: "invalid header name", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Headers = [][2]string{{"Bad Name", "a"}} }},
		{name: "long header name", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Headers = [][2]string{{strings.Repeat("A", 257), "a"}} }},
		{name: "invalid header value", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Headers = [][2]string{{"X-Test", "a\nb"}} }},
		{name: "non latin-1 header", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Headers = [][2]string{{"X-Test", "中文"}} }},
		{name: "long header value", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.Headers = [][2]string{{"X-Test", strings.Repeat("a", 16385)}} }},
		{name: "large total headers", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) {
			input.Headers = make([][2]string, 65)
			for i := range input.Headers {
				input.Headers[i] = [2]string{"X-Test", strings.Repeat("a", 16384)}
			}
		}},
		{name: "invalid base64", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.BodyBase64 = "%%%" }},
		{name: "large body", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.BodyBase64 = base64.StdEncoding.EncodeToString([]byte("12345")) }},
		{name: "negative timeout", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.TimeoutMS = -1 }},
		{name: "large timeout", code: "INVALID_REQUEST", edit: func(input *requestEnvelope) { input.TimeoutMS = 600001 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newServer("", 4, time.Hour)
			clientID := addTestClient(t, s)
			input := requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: "http://example.com"}
			test.edit(&input)
			response := sendRawRequest(t, s.routes(), clientID, input)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if got := decodeAPIError(t, response).Code; got != test.code {
				t.Fatalf("error code = %q", got)
			}
		})
	}

	for name, body := range map[string]string{
		"malformed":        `{`,
		"unknown field":    `{"protocol_version":1,"method":"GET","url":"http://example.com","unknown":true}`,
		"unknown option":   `{"protocol_version":1,"method":"GET","url":"http://example.com","options":{"unknown":true}}`,
		"trailing content": `{"protocol_version":1,"method":"GET","url":"http://example.com"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer("", 48<<20, time.Hour)
			clientID := addTestClient(t, s)
			response := httptest.NewRecorder()
			s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+clientID+"/requests", strings.NewReader(body)))
			if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	for name, headers := range map[string]string{
		"short header pair": `[["X-Test"]]`,
		"long header pair":  `[["X-Test","a","ignored"]]`,
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer("", 48<<20, time.Hour)
			clientID := addTestClient(t, s)
			body := `{"protocol_version":1,"method":"GET","url":"` + target.URL + `","headers":` + headers + `}`
			response := httptest.NewRecorder()
			s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+clientID+"/requests", strings.NewReader(body)))
			if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestRawRequestReturnsClientNotFoundBeforeUpstream(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := sendRawRequest(t, s.routes(), "missing", requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: "http://127.0.0.1:1"})
	if response.Code != http.StatusNotFound || decodeAPIError(t, response).Code != "CLIENT_NOT_FOUND" {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRawRequestTracksActiveCalls(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	clientID := addTestClient(t, s)
	s.clients[clientID].mu.Lock()
	s.clients[clientID].lastUsed = time.Now().Add(-time.Hour)
	previousLastUsed := s.clients[clientID].lastUsed
	s.clients[clientID].mu.Unlock()
	body, err := json.Marshal(requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients/"+clientID+"/requests", bytes.NewReader(body)))
		done <- response
	}()
	<-started
	s.clients[clientID].mu.Lock()
	activeCalls := s.clients[clientID].activeCalls
	lastUsed := s.clients[clientID].lastUsed
	s.clients[clientID].mu.Unlock()
	if activeCalls != 1 || !lastUsed.After(previousLastUsed) {
		t.Fatalf("active calls=%d last used=%s", activeCalls, lastUsed)
	}
	close(release)
	response := <-done
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	s.clients[clientID].mu.Lock()
	defer s.clients[clientID].mu.Unlock()
	if s.clients[clientID].activeCalls != 0 {
		t.Fatalf("active calls = %d", s.clients[clientID].activeCalls)
	}
}

func TestUpstreamErrors(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		s := newServer("", 48<<20, time.Hour)
		response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL, TimeoutMS: 10})
		if response.Code != http.StatusGatewayTimeout || decodeAPIError(t, response).Code != "UPSTREAM_TIMEOUT" {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("connect", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		s := newServer("", 48<<20, time.Hour)
		response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: "http://" + address})
		if response.Code != http.StatusBadGateway || decodeAPIError(t, response).Code != "UPSTREAM_CONNECT_ERROR" {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("TLS", func(t *testing.T) {
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		defer target.Close()
		s := newServer("", 48<<20, time.Hour)
		response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL})
		if response.Code != http.StatusBadGateway || decodeAPIError(t, response).Code != "UPSTREAM_TLS_ERROR" {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	t.Run("protocol", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		go func() {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			defer connection.Close()
			_, _ = bufio.NewReader(connection).ReadString('\n')
			_, _ = connection.Write([]byte("HTTP/1.1 invalid\r\n\r\n"))
		}()
		s := newServer("", 48<<20, time.Hour)
		response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: "http://" + listener.Addr().String()})
		if response.Code != http.StatusBadGateway || decodeAPIError(t, response).Code != "UPSTREAM_PROTOCOL_ERROR" {
			t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
		}
	})

	code, retryable := classifyUpstreamError(&neturl.Error{Err: &net.DNSError{Err: "no such host", Name: "missing.invalid"}})
	if code != "UPSTREAM_DNS_ERROR" || !retryable {
		t.Fatalf("DNS classification = %q, retryable=%t", code, retryable)
	}
}

func TestClientOptionsMapSerializableConfiguration(t *testing.T) {
	verify := false
	keepAlive := false
	allowGetBody := false
	client, err := buildReqClient(createClientRequest{
		TLSFingerprint: "golang",
		ProxyURL:       "http://proxy.example:8080",
		Verify:         &verify,
		HTTPVersion:    "auto",
		KeepAlive:      &keepAlive,
		Compression:    true,
		AllowGetBody:   &allowGetBody,
		Transport: transportConfig{
			TLSHandshakeTimeoutMS:   1,
			ResponseHeaderTimeoutMS: 2,
			ExpectContinueTimeoutMS: 3,
			IdleConnTimeoutMS:       4,
			MaxIdleConns:            5,
			MaxIdleConnsPerHost:     6,
			MaxConnsPerHost:         7,
			MaxResponseHeaderBytes:  8,
			ReadBufferSize:          9,
			WriteBufferSize:         10,
			ProxyConnectHeaders:     map[string][]string{"X-Proxy": {"one", "two"}},
		},
		HTTP2: http2Config{
			Settings:                   []http2Setting{{ID: 1, Value: 4096}, {ID: 6, Value: 8192}},
			ConnectionFlow:             func() *uint32 { value := uint32(65535); return &value }(),
			HeaderPriority:             &priorityParam{StreamDependency: 1, Exclusive: true, Weight: 2},
			PriorityFrames:             []priorityFrame{{StreamID: 3, Priority: priorityParam{StreamDependency: 1, Weight: 4}}},
			MaxHeaderListSize:          func() *uint32 { value := uint32(16384); return &value }(),
			StrictMaxConcurrentStreams: true,
			ReadIdleTimeoutMS:          11,
			PingTimeoutMS:              12,
			WriteByteTimeoutMS:         13,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.GetTransport()
	proxy, err := transport.Proxy(&http.Request{URL: &neturl.URL{Scheme: "https", Host: "target.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.String() != "http://proxy.example:8080" || !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("proxy=%v TLS=%#v", proxy, transport.TLSClientConfig)
	}
	if !transport.DisableKeepAlives || transport.DisableCompression || client.AllowGetMethodPayload {
		t.Fatalf("keepalive=%t compression=%t allow_get_body=%t", transport.DisableKeepAlives, transport.DisableCompression, client.AllowGetMethodPayload)
	}
	if transport.TLSHandshakeTimeout != time.Millisecond || transport.ResponseHeaderTimeout != 2*time.Millisecond || transport.ExpectContinueTimeout != 3*time.Millisecond || transport.IdleConnTimeout != 4*time.Millisecond {
		t.Fatalf("timeouts = %#v", transport.Options)
	}
	if transport.MaxIdleConns != 5 || transport.MaxIdleConnsPerHost != 6 || transport.MaxConnsPerHost != 7 || transport.MaxResponseHeaderBytes != 8 || transport.ReadBufferSize != 9 || transport.WriteBufferSize != 10 {
		t.Fatalf("transport = %#v", transport.Options)
	}
	if !reflect.DeepEqual(transport.ProxyConnectHeader.Values("X-Proxy"), []string{"one", "two"}) {
		t.Fatalf("proxy connect headers = %#v", transport.ProxyConnectHeader)
	}
}

func TestClientOptionsValidateBoundaries(t *testing.T) {
	tests := []struct {
		name  string
		input createClientRequest
	}{
		{name: "proxy scheme", input: createClientRequest{ProxyURL: "ftp://proxy.example"}},
		{name: "proxy host", input: createClientRequest{ProxyURL: "http:///missing"}},
		{name: "root CA PEM", input: createClientRequest{RootCAPEM: "not PEM"}},
		{name: "client certificate pair", input: createClientRequest{ClientCertPEM: "certificate only"}},
		{name: "client certificate PEM", input: createClientRequest{ClientCertPEM: "bad", ClientKeyPEM: "bad"}},
		{name: "HTTP version", input: createClientRequest{HTTPVersion: "http4"}},
		{name: "retry count", input: createClientRequest{Retry: retryConfig{Count: 11, Mode: retryNone}}},
		{name: "retry zero fixed", input: createClientRequest{Retry: retryConfig{Mode: retryFixed, FixedIntervalMS: 1}}},
		{name: "retry fixed interval", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed}}},
		{name: "retry backoff order", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryBackoff, BackoffMinMS: 2, BackoffMaxMS: 1}}},
		{name: "retry status", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{99}}}},
		{name: "duplicate retry status", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{500, 500}}}},
		{name: "duration negative", input: createClientRequest{Transport: transportConfig{TLSHandshakeTimeoutMS: -1}}},
		{name: "duration large", input: createClientRequest{HTTP2: http2Config{PingTimeoutMS: 600001}}},
		{name: "connection large", input: createClientRequest{Transport: transportConfig{MaxIdleConns: 100001}}},
		{name: "buffer large", input: createClientRequest{Transport: transportConfig{ReadBufferSize: 16777217}}},
		{name: "response header large", input: createClientRequest{Transport: transportConfig{MaxResponseHeaderBytes: 16777217}}},
		{name: "setting ID", input: createClientRequest{HTTP2: http2Config{Settings: []http2Setting{{ID: 7}}}}},
		{name: "duplicate setting", input: createClientRequest{HTTP2: http2Config{Settings: []http2Setting{{ID: 1}, {ID: 1}}}}},
		{name: "priority dependency", input: createClientRequest{HTTP2: http2Config{HeaderPriority: &priorityParam{StreamDependency: 1 << 31}}}},
		{name: "priority weight", input: createClientRequest{HTTP2: http2Config{HeaderPriority: &priorityParam{Weight: 256}}}},
		{name: "priority stream", input: createClientRequest{HTTP2: http2Config{PriorityFrames: []priorityFrame{{StreamID: 1 << 31}}}}},
		{name: "impersonate fingerprint", input: createClientRequest{TLSFingerprint: "golang", Impersonate: "chrome"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := buildReqClient(test.input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestClientOptionsHTTPVersions(t *testing.T) {
	for _, version := range []string{"auto", "http1", "http2", "http3", "h2c"} {
		t.Run(version, func(t *testing.T) {
			client, err := buildReqClient(createClientRequest{HTTPVersion: version})
			if err != nil {
				t.Fatal(err)
			}
			if got := client.GetTransport().Options.EnableH2C; got != (version == "h2c") {
				t.Fatalf("EnableH2C = %t", got)
			}
		})
	}
}

func TestClientOptionsRetryModesAndStatusCodes(t *testing.T) {
	for _, retry := range []retryConfig{
		{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{503}},
		{Count: 1, Mode: retryBackoff, BackoffMinMS: 1, BackoffMaxMS: 2, StatusCodes: []int{503}},
	} {
		var calls int
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		client, err := buildReqClient(createClientRequest{Retry: retry})
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.R().Get(target.URL)
		target.Close()
		if err != nil || response.StatusCode != http.StatusNoContent || calls != 2 {
			t.Fatalf("response=%v err=%v calls=%d", response, err, calls)
		}
	}
}

func TestClientOptionsStrictNestedJSONAndInvalidConfigurationCode(t *testing.T) {
	for _, body := range []string{
		`{"protocol_version":1,"retry":{"unknown":1}}`,
		`{"protocol_version":1,"transport":{"unknown":1}}`,
		`{"protocol_version":1,"http2":{"settings":[{"id":1,"value":1,"unknown":1}]}}`,
		`{"protocol_version":1,"proxy_url":"ftp://proxy.example"}`,
		`{"protocol_version":1,"impersonate":"chrome","tls_fingerprint":"golang"}`,
	} {
		s := newServer("", 48<<20, time.Hour)
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
			t.Fatalf("body=%s status=%d response=%s", body, response.Code, response.Body.String())
		}
	}
}

func TestRequestOptionsMapChunkedCloseRetryTraceAndDump(t *testing.T) {
	var calls int
	var closed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		closed = r.Close
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("dump body"))
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	client, err := buildReqClient(createClientRequest{Retry: retryConfig{Count: 2, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{503}}})
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	options := requestOptions{ForceChunked: true, CloseConnection: true, RetryCount: &zero, Trace: true, Dump: true}
	mappedRequest := client.R()
	var mappedDump bytes.Buffer
	applyRequestOptions(mappedRequest, options, &mappedDump)
	mappedValue := reflect.ValueOf(mappedRequest).Elem()
	if !mappedValue.FieldByName("forceChunkedEncoding").Bool() || !mappedValue.FieldByName("close").Bool() || mappedValue.FieldByName("retryOption").Elem().FieldByName("MaxRetries").Int() != 0 {
		t.Fatal("request options were not mapped to req.Request")
	}
	const clientID = "advanced-request"
	s.clients[clientID] = &clientSession{client: client, lastUsed: time.Now()}
	response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodPost,
		URL:             target.URL,
		BodyBase64:      base64.StdEncoding.EncodeToString([]byte("request body")),
		Options:         options,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result responseEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !closed || result.Trace == nil || result.Dump == nil || !strings.Contains(*result.Dump, "dump body") {
		t.Fatalf("calls=%d closed=%t trace=%#v dump=%v", calls, closed, result.Trace, result.Dump)
	}
}

func TestRequestOptionsValidateRetryOverride(t *testing.T) {
	for _, count := range []int{-1, 11} {
		s := newServer("", 48<<20, time.Hour)
		response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{
			ProtocolVersion: protocolVersion,
			Method:          http.MethodGet,
			URL:             "http://example.com",
			Options:         requestOptions{RetryCount: &count},
		})
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
			t.Fatalf("count=%d status=%d body=%s", count, response.Code, response.Body.String())
		}
	}
}

func TestRequestOptionsOmitDisabledDump(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	s := newServer("", 48<<20, time.Hour)
	response := sendRawRequest(t, s.routes(), addTestClient(t, s), requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL})
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["dump"]; ok {
		t.Fatalf("disabled dump must be omitted: %s", response.Body.String())
	}
}

func TestClientOptionsFingerprintWithMTLS(t *testing.T) {
	trustedCA, trustedCAPEM, trustedCAKey := newTestCA(t, "trusted CA")
	untrustedCA, untrustedCAPEM, untrustedCAKey := newTestCA(t, "untrusted CA")
	serverCertificate, _, _ := newTestCertificate(t, trustedCA, trustedCAKey, "server", true)
	_, clientCertPEM, clientKeyPEM := newTestCertificate(t, trustedCA, trustedCAKey, "trusted client", false)
	_, untrustedClientCertPEM, untrustedClientKeyPEM := newTestCertificate(t, untrustedCA, untrustedCAKey, "untrusted client", false)

	clientCAPool := x509.NewCertPool()
	clientCAPool.AddCert(trustedCA)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 || r.TLS.PeerCertificates[0].Subject.CommonName != "trusted client" {
			t.Errorf("peer certificates = %#v", r.TLS.PeerCertificates)
		}
		if strings.HasPrefix(r.Host, "localhost:") && r.TLS.ServerName != "localhost" {
			t.Errorf("SNI = %q", r.TLS.ServerName)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	target.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAPool,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()

	verifyFalse := false
	for _, test := range []struct {
		input      createClientRequest
		protoMajor int
	}{
		{input: createClientRequest{TLSFingerprint: "chrome_120", RootCAPEM: trustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM}, protoMajor: 2},
		{input: createClientRequest{Impersonate: "chrome", RootCAPEM: trustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM}, protoMajor: 2},
		{input: createClientRequest{TLSFingerprint: "chrome_120", Verify: &verifyFalse, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM}, protoMajor: 2},
	} {
		client, err := buildReqClient(test.input)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.R().Get(target.URL)
		if err != nil || response.StatusCode != http.StatusNoContent || response.ProtoMajor != test.protoMajor {
			t.Fatalf("input=%#v response=%v err=%v", test.input, response, err)
		}
	}
	sniClient, err := buildReqClient(createClientRequest{TLSFingerprint: "chrome_120", RootCAPEM: trustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sniClient.R().Get(strings.Replace(target.URL, "127.0.0.1", "localhost", 1)); err != nil {
		t.Fatal(err)
	}

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		upstream, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		downstream, buffered, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		go func() {
			_, _ = io.Copy(upstream, downstream)
			_ = upstream.Close()
		}()
		_, _ = io.Copy(downstream, upstream)
		_ = downstream.Close()
	}))
	proxiedClient, err := buildReqClient(createClientRequest{TLSFingerprint: "chrome_120", ProxyURL: proxy.URL, RootCAPEM: trustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	proxiedResponse, err := proxiedClient.R().Get(target.URL)
	proxy.Close()
	if err != nil || proxiedResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("proxied response=%v err=%v", proxiedResponse, err)
	}

	failures := []createClientRequest{
		{TLSFingerprint: "chrome_120", RootCAPEM: trustedCAPEM, HTTPVersion: "http1"},
		{TLSFingerprint: "chrome_120", RootCAPEM: trustedCAPEM, ClientCertPEM: untrustedClientCertPEM, ClientKeyPEM: untrustedClientKeyPEM, HTTPVersion: "http1"},
		{TLSFingerprint: "chrome_120", RootCAPEM: untrustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM, HTTPVersion: "http1"},
	}
	for _, input := range failures {
		client, err := buildReqClient(input)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.R().Get(target.URL); err == nil {
			t.Fatalf("input=%#v unexpectedly completed mTLS handshake", input)
		}
	}

	untrustedClient, err := buildReqClient(failures[2])
	if err != nil {
		t.Fatal(err)
	}
	s := newServer("", 48<<20, time.Hour)
	s.clients["mtls-error"] = &clientSession{client: untrustedClient, lastUsed: time.Now()}
	response := sendRawRequest(t, s.routes(), "mtls-error", requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL})
	if response.Code != http.StatusBadGateway || decodeAPIError(t, response).Code != "UPSTREAM_TLS_ERROR" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func newTestCA(t *testing.T, commonName string) (*x509.Certificate, string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

func newTestCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, commonName string, server bool) (tls.Certificate, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		template.DNSNames = []string{"localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	return certificate, certificatePEM, keyPEM
}
