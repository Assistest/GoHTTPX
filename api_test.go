package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
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
	if h.Status != "ok" || h.ProtocolVersion != 1 || h.ServerVersion != serverVersion {
		t.Fatalf("health = %#v", h)
	}
}

func TestCapabilitiesUseExactServerVersionEnvelope(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var capabilities map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &capabilities); err != nil {
		t.Fatal(err)
	}
	wantFields := []string{"max_body_bytes", "protocol_version", "server_version", "tls_fingerprints"}
	gotFields := make([]string, 0, len(capabilities))
	for name := range capabilities {
		gotFields = append(gotFields, name)
	}
	sort.Strings(gotFields)
	if !reflect.DeepEqual(gotFields, wantFields) {
		t.Fatalf("capabilities fields = %q", gotFields)
	}
	var version string
	if err := json.Unmarshal(capabilities["server_version"], &version); err != nil {
		t.Fatal(err)
	}
	if version != serverVersion {
		t.Fatalf("server_version = %q", version)
	}
}

func TestVersionFlagNeedsNoTokenAndReportsFixedBuildVersions(t *testing.T) {
	command := exec.Command("go", "run", ".", "--version")
	command.Env = append(os.Environ(), "GOHTTPX_TOKEN=")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, output)
	}
	want := "GoHTTPX server 2.1.2 protocol 1 req/v3 v3.59.0 uTLS v1.8.2\n"
	if string(output) != want {
		t.Fatalf("--version output = %q, want %q", output, want)
	}
}

func TestVersionFlagUsesLinkerServerVersion(t *testing.T) {
	command := exec.Command("go", "run", "-ldflags", "-X main.serverVersion=1.2.3", ".", "--version")
	command.Env = append(os.Environ(), "GOHTTPX_TOKEN=")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("--version failed: %v\n%s", err, output)
	}
	if !strings.HasPrefix(string(output), "GoHTTPX server 1.2.3 protocol 1 ") {
		t.Fatalf("--version output = %q", output)
	}
}

func TestCLIHelpDescribesBidirectionalBodyLimit(t *testing.T) {
	command := exec.Command("go", "run", ".", "--help")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "最大目标请求与响应正文（MiB）") {
		t.Fatalf("--help output = %q", output)
	}
}

func TestCLIFlagTokenOverridesEnvironment(t *testing.T) {
	options, err := parseCLI([]string{"--token", "flag-secret"}, "env-secret")
	if err != nil {
		t.Fatal(err)
	}
	if options.token != "flag-secret" {
		t.Fatalf("token = %q", options.token)
	}
	options, err = parseCLI(nil, "env-secret")
	if err != nil {
		t.Fatal(err)
	}
	if options.token != "env-secret" {
		t.Fatalf("environment token = %q", options.token)
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

func TestControlPOSTRequiresJSONContentType(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	t.Cleanup(s.Close)
	handler := s.routes()
	endpoints := []struct {
		path        string
		body        string
		validStatus int
	}{
		{path: "/api/v1/clients", body: `{"protocol_version":1,"sdk_version":"` + serverVersion + `"}`, validStatus: http.StatusCreated},
		{path: "/api/v1/clients/missing/requests", body: `{}`, validStatus: http.StatusNotFound},
	}
	invalid := []struct {
		name        string
		contentType string
		status      int
		code        string
	}{
		{name: "missing", status: http.StatusUnsupportedMediaType, code: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "wrong", contentType: "text/plain", status: http.StatusUnsupportedMediaType, code: "UNSUPPORTED_MEDIA_TYPE"},
		{name: "malformed", contentType: "application/json; charset", status: http.StatusBadRequest, code: "INVALID_REQUEST"},
	}
	for _, endpoint := range endpoints {
		for _, test := range invalid {
			t.Run(endpoint.path+"/"+test.name, func(t *testing.T) {
				request := httptest.NewRequest(http.MethodPost, endpoint.path, strings.NewReader(endpoint.body))
				if test.contentType != "" {
					request.Header.Set("Content-Type", test.contentType)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != test.status || response.Header().Get("Content-Type") != "application/json" || decodeAPIError(t, response).Code != test.code {
					t.Fatalf("status=%d content-type=%q body=%s", response.Code, response.Header().Get("Content-Type"), response.Body.String())
				}
			})
		}
		t.Run(endpoint.path+"/valid", func(t *testing.T) {
			request := newJSONControlRequest(endpoint.path, strings.NewReader(endpoint.body))
			request.Header.Set("Content-Type", "Application/JSON; Charset=UTF-8")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != endpoint.validStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
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
	handler.ServeHTTP(created, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`"}`)))
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

func TestClientLifecycleRejectsMismatchedSDKVersion(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"0.0.0"}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	apiErr := decodeAPIError(t, response)
	if apiErr.Code != "VERSION_MISMATCH" || !strings.Contains(apiErr.Message, "pip install --upgrade gohttpx") || !strings.Contains(apiErr.Message, "Release") {
		t.Fatalf("error = %#v", apiErr)
	}
}

func TestClientLifecycleRejectsUnsupportedFingerprint(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`","tls_fingerprint":"not-a-fingerprint"}`)))
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
			s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(body)))
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

func newJSONControlRequest(target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, body)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func sendRawRequest(t *testing.T, handler http.Handler, clientID string, input requestEnvelope) *httptest.ResponseRecorder {
	t.Helper()
	if input.Headers == nil {
		input.Headers = [][2]string{}
	}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := newJSONControlRequest("/api/v1/clients/"+clientID+"/requests", bytes.NewReader(body))
	handler.ServeHTTP(response, request)
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

func TestRawRequestHTTP1PreservesPreparedHeaderWireContract(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	captured := make(chan string, 2)
	serverErrors := make(chan error, 1)
	go func() {
		for range 2 {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				return
			}
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(connection)
			var raw strings.Builder
			for {
				line, readErr := reader.ReadString('\n')
				if readErr != nil {
					_ = connection.Close()
					serverErrors <- readErr
					return
				}
				raw.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			captured <- raw.String()
			_, _ = connection.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
			_ = connection.Close()
		}
	}()

	s := newServer("", 48<<20, time.Hour)
	t.Cleanup(s.Close)
	client, err := buildReqClient(createClientRequest{HTTPVersion: "http1"})
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "raw-header-client"
	s.clients[clientID] = &clientSession{client: client, lastUsed: time.Now()}
	targetURL := "http://" + listener.Addr().String()
	tests := []requestEnvelope{
		{
			ProtocolVersion: protocolVersion,
			Method:          http.MethodPost,
			URL:             targetURL,
			Headers:         [][2]string{{"X-Second", "2"}, {"x-Repeat", "one"}, {"x-Repeat", "two"}, {"X-First", "1"}},
			BodyBase64:      base64.StdEncoding.EncodeToString([]byte("payload")),
		},
		{
			ProtocolVersion: protocolVersion,
			Method:          http.MethodGet,
			URL:             targetURL,
			Headers:         [][2]string{{"X-First", "1"}, {"x-Second", "2"}},
			Options:         requestOptions{HeaderOrder: []string{"x-Second", "X-First"}},
		},
	}
	for _, input := range tests {
		response := sendRawRequest(t, s.routes(), clientID, input)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}

	first, second := <-captured, <-captured
	select {
	case serverErr := <-serverErrors:
		t.Fatal(serverErr)
	default:
	}
	firstLower := strings.ToLower(first)
	if strings.Contains(firstLower, "\r\nuser-agent:") || strings.Contains(firstLower, "\r\ncontent-type:") {
		t.Fatalf("unexpected synthesized business header:\n%s", first)
	}
	secondIndex := strings.Index(first, "\r\nX-Second: 2\r\n")
	repeatIndex := strings.Index(first, "\r\nx-Repeat: one\r\nx-Repeat: two\r\n")
	firstIndex := strings.Index(first, "\r\nX-First: 1\r\n")
	if secondIndex < 0 || repeatIndex < 0 || firstIndex < 0 || !(secondIndex < repeatIndex && repeatIndex < firstIndex) {
		t.Fatalf("automatic header order/casing/duplicates lost:\n%s", first)
	}
	if secondIndex = strings.Index(second, "\r\nx-Second: 2\r\n"); secondIndex < 0 || strings.Index(second, "\r\nX-First: 1\r\n") < secondIndex {
		t.Fatalf("explicit header order ignored:\n%s", second)
	}
}

func TestRawRequestConcurrentContentTypePresenceIsIsolated(t *testing.T) {
	type observedRequest struct {
		path        string
		contentType []string
		body        string
	}
	type contentTypeCase struct {
		path    string
		headers [][2]string
		want    []string
	}
	const pairs = 12
	tests := []contentTypeCase{
		{path: "/plain/", headers: [][2]string{}, want: nil},
		{path: "/typed/", headers: [][2]string{{"content-type", "application/one"}, {"CONTENT-TYPE", "application/two"}}, want: []string{"application/one", "application/two"}},
		{path: "/empty/", headers: [][2]string{{"Content-Type", ""}}, want: []string{""}},
		{path: "/mixed/", headers: [][2]string{{"content-type", ""}, {"Content-Type", "application/two"}}, want: []string{"", "application/two"}},
	}
	observed := make(chan observedRequest, pairs*len(tests))
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		observed <- observedRequest{path: r.URL.Path, contentType: r.Header.Values("Content-Type"), body: string(body)}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	s := newServer("", 48<<20, time.Hour)
	clientID := addTestClient(t, s)
	handler := s.routes()
	errors := make(chan string, pairs*len(tests))
	var requests sync.WaitGroup
	for i := 0; i < pairs; i++ {
		for _, test := range tests {
			requests.Add(1)
			go func(i int, test contentTypeCase) {
				defer requests.Done()
				input, _ := json.Marshal(requestEnvelope{
					ProtocolVersion: protocolVersion,
					Method:          http.MethodPost,
					URL:             target.URL + test.path + fmt.Sprint(i),
					Headers:         test.headers,
					BodyBase64:      base64.StdEncoding.EncodeToString([]byte("payload")),
				})
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, newJSONControlRequest("/api/v1/clients/"+clientID+"/requests", bytes.NewReader(input)))
				if response.Code != http.StatusOK {
					errors <- response.Body.String()
				}
			}(i, test)
		}
	}
	requests.Wait()
	close(errors)
	close(observed)
	for message := range errors {
		t.Error(message)
	}
	for request := range observed {
		if request.body != "payload" {
			t.Errorf("%s body = %q", request.path, request.body)
		}
		for _, test := range tests {
			if strings.HasPrefix(request.path, test.path) && !reflect.DeepEqual(request.contentType, test.want) {
				t.Errorf("%s Content-Type = %q, want %q", request.path, request.contentType, test.want)
			}
		}
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
			s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients/"+clientID+"/requests", strings.NewReader(body)))
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
			s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients/"+clientID+"/requests", strings.NewReader(body)))
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
	body, err := json.Marshal(requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: target.URL, Headers: [][2]string{}})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients/"+clientID+"/requests", bytes.NewReader(body)))
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
		{name: "retry count negative", input: createClientRequest{Retry: retryConfig{Count: -1, Mode: retryNone}}},
		{name: "retry zero fixed", input: createClientRequest{Retry: retryConfig{Mode: retryFixed, FixedIntervalMS: 1}}},
		{name: "retry fixed interval", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed}}},
		{name: "retry backoff order", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryBackoff, BackoffMinMS: 2, BackoffMaxMS: 1}}},
		{name: "retry status", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{99}}}},
		{name: "retry status large", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{600}}}},
		{name: "duplicate retry status", input: createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{500, 500}}}},
		{name: "duration negative", input: createClientRequest{Transport: transportConfig{TLSHandshakeTimeoutMS: -1}}},
		{name: "duration large", input: createClientRequest{HTTP2: http2Config{PingTimeoutMS: 600001}}},
		{name: "connection large", input: createClientRequest{Transport: transportConfig{MaxIdleConns: 100001}}},
		{name: "connection negative", input: createClientRequest{Transport: transportConfig{MaxConnsPerHost: -1}}},
		{name: "buffer large", input: createClientRequest{Transport: transportConfig{ReadBufferSize: 16777217}}},
		{name: "buffer negative", input: createClientRequest{Transport: transportConfig{WriteBufferSize: -1}}},
		{name: "response header large", input: createClientRequest{Transport: transportConfig{MaxResponseHeaderBytes: 16777217}}},
		{name: "response header negative", input: createClientRequest{Transport: transportConfig{MaxResponseHeaderBytes: -1}}},
		{name: "setting ID", input: createClientRequest{HTTP2: http2Config{Settings: []http2Setting{{ID: 7}}}}},
		{name: "setting ID zero", input: createClientRequest{HTTP2: http2Config{Settings: []http2Setting{{ID: 0}}}}},
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

func TestClientOptionsAcceptExactBoundaries(t *testing.T) {
	connectionFlow := uint32(0xffffffff)
	maxHeaderListSize := uint32(0xffffffff)
	_, err := buildReqClient(createClientRequest{
		Retry: retryConfig{Count: 10, Mode: retryBackoff, BackoffMinMS: 1, BackoffMaxMS: 600000, StatusCodes: []int{100, 599}},
		Transport: transportConfig{
			TLSHandshakeTimeoutMS: 600000, ResponseHeaderTimeoutMS: 600000, ExpectContinueTimeoutMS: 600000, IdleConnTimeoutMS: 600000,
			MaxIdleConns: 100000, MaxIdleConnsPerHost: 100000, MaxConnsPerHost: 100000,
			MaxResponseHeaderBytes: 16777216, ReadBufferSize: 16777216, WriteBufferSize: 16777216,
		},
		HTTP2: http2Config{
			Settings:          []http2Setting{{ID: 1, Value: 0xffffffff}, {ID: 6, Value: 0xffffffff}},
			ConnectionFlow:    &connectionFlow,
			HeaderPriority:    &priorityParam{StreamDependency: math.MaxInt32, Weight: math.MaxUint8},
			PriorityFrames:    []priorityFrame{{StreamID: math.MaxInt32, Priority: priorityParam{StreamDependency: math.MaxInt32, Weight: math.MaxUint8}}},
			MaxHeaderListSize: &maxHeaderListSize,
			ReadIdleTimeoutMS: 600000, PingTimeoutMS: 600000, WriteByteTimeoutMS: 600000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestClientOptionsHTTPVersions(t *testing.T) {
	for _, version := range []string{"auto", "http1", "http2", "h2c"} {
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

func TestHTTP2RejectsExplicitFingerprintAndBrowserImpersonation(t *testing.T) {
	for _, input := range []createClientRequest{
		{HTTPVersion: "http2", TLSFingerprint: "android_11_okhttp", tlsFingerprintSet: true},
		{HTTPVersion: "http2", Impersonate: "chrome"},
	} {
		if err := validateClientConfig(input); err == nil {
			t.Fatal("expected HTTP/2 validation error")
		}
	}
	if err := validateClientConfig(createClientRequest{HTTPVersion: "http2", Impersonate: "none"}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP2WithoutFingerprintDecodesAsDefaultTLS(t *testing.T) {
	var input createClientRequest
	if err := json.Unmarshal([]byte(`{"protocol_version":1,"http_version":"http2","impersonate":"none"}`), &input); err != nil {
		t.Fatal(err)
	}
	if input.tlsFingerprintSet || input.TLSFingerprint != "" || input.Impersonate != "none" {
		t.Fatalf("input=%#v", input)
	}
}

func TestClientOptionsH2CSendsCleartextHTTP2(t *testing.T) {
	protocol := make(chan int, 1)
	target := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protocol <- r.ProtoMajor
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer target.Close()

	client, err := buildReqClient(createClientRequest{HTTPVersion: "h2c"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.R().Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent || <-protocol != 2 {
		t.Fatalf("status=%d protocol=%s", response.StatusCode, response.Proto)
	}
}

func TestClientOptionsHTTP3UsesQUICWithTLSConfiguration(t *testing.T) {
	ca, caPEM, caKey := newTestCA(t, "HTTP3 CA")
	serverCertificate, _, _ := newTestCertificate(t, ca, caKey, "localhost", true)
	_, clientCertificatePEM, clientKeyPEM := newTestCertificate(t, ca, caKey, "HTTP3 client", false)
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)
	protocol := make(chan int, 4)
	acceptEncoding := make(chan string, 1)
	requestBodies := make(chan string, 2)
	contentTypes := make(chan []string, 2)
	var retryCalls atomic.Int32
	var handshakes atomic.Int32
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			protocol <- r.ProtoMajor
			switch r.URL.Path {
			case "/body":
				body, _ := io.ReadAll(r.Body)
				requestBodies <- string(body)
			case "/content-type":
				contentTypes <- r.Header.Values("Content-Type")
			case "/compression":
				acceptEncoding <- r.Header.Get("Accept-Encoding")
			case "/large-header":
				w.Header().Set("X-Large", strings.Repeat("a", 1024))
			case "/redirect":
				http.Redirect(w, r, "/", http.StatusFound)
				return
			case "/slow":
				time.Sleep(50 * time.Millisecond)
			case "/retry":
				if retryCalls.Add(1) != 1 {
					break
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("retry"))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				handshakes.Add(1)
				return nil, nil
			},
		},
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	targetURL := "https://" + listener.LocalAddr().String()
	verifyFalse := false

	for _, input := range []createClientRequest{
		{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM},
		{HTTPVersion: "http3", Verify: &verifyFalse, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM},
	} {
		client, buildErr := buildReqClient(input)
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		response, requestErr := client.R().Get(targetURL)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if response.StatusCode != http.StatusNoContent || <-protocol != 3 {
			t.Fatalf("status=%d protocol=%s", response.StatusCode, response.Proto)
		}
		client.GetClient().CloseIdleConnections()
	}

	client, err := buildReqClient(createClientRequest{
		HTTPVersion:   "http3",
		RootCAPEM:     caPEM,
		ClientCertPEM: clientCertificatePEM,
		ClientKeyPEM:  clientKeyPEM,
		Retry:         retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{http.StatusServiceUnavailable}},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer("", 48<<20, time.Hour)
	const clientID = "http3-high-level"
	s.clients[clientID] = &clientSession{client: client, lastUsed: time.Now()}
	response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodGet,
		URL:             targetURL + "/retry",
		Options:         requestOptions{Trace: true, Dump: true},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result responseEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	firstProtocol, secondProtocol := <-protocol, <-protocol
	if retryCalls.Load() != 2 || firstProtocol != 3 || secondProtocol != 3 || result.StatusCode != http.StatusNoContent || result.Trace == nil || result.Trace.RemoteAddress == "" || result.Dump == nil || !strings.Contains(*result.Dump, "HTTP/3.0") {
		dump := "<nil>"
		if result.Dump != nil {
			dump = *result.Dump
		}
		t.Fatalf("calls=%d protocols=%d,%d trace=%#v dump=%q result=%#v", retryCalls.Load(), firstProtocol, secondProtocol, result.Trace, dump, result)
	}
	client.GetClient().CloseIdleConnections()

	behaviorConfig := createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM, Compression: true}
	behaviorClient, err := buildReqClient(behaviorConfig)
	if err != nil {
		t.Fatal(err)
	}
	const contentTypeClientID = "http3-content-type"
	s.clients[contentTypeClientID] = &clientSession{client: behaviorClient, config: behaviorConfig, lastUsed: time.Now()}
	for _, test := range []struct {
		headers [][2]string
		want    []string
	}{
		{headers: [][2]string{}, want: nil},
		{headers: [][2]string{{"content-type", "application/one"}, {"CONTENT-TYPE", "application/two"}}, want: []string{"application/one", "application/two"}},
		{headers: [][2]string{{"Content-Type", ""}}, want: []string{""}},
		{headers: [][2]string{{"content-type", ""}, {"Content-Type", "application/two"}}, want: []string{"", "application/two"}},
	} {
		bridgeResponse := sendRawRequest(t, s.routes(), contentTypeClientID, requestEnvelope{
			ProtocolVersion: protocolVersion,
			Method:          http.MethodPost,
			URL:             targetURL + "/content-type",
			Headers:         test.headers,
			BodyBase64:      base64.StdEncoding.EncodeToString([]byte("payload")),
		})
		if bridgeResponse.Code != http.StatusOK || <-protocol != 3 {
			t.Fatalf("status=%d body=%s", bridgeResponse.Code, bridgeResponse.Body.String())
		}
		if got := <-contentTypes; !reflect.DeepEqual(got, test.want) {
			t.Fatalf("Content-Type = %q, want %q", got, test.want)
		}
	}
	compressedResponse, err := behaviorClient.R().Get(targetURL + "/compression")
	if err != nil || compressedResponse.StatusCode != http.StatusNoContent || <-protocol != 3 || <-acceptEncoding != "gzip" {
		t.Fatalf("compression response=%v err=%v", compressedResponse, err)
	}
	bodyResponse, err := behaviorClient.R().SetBodyBytes([]byte("payload")).Get(targetURL + "/body")
	if err != nil || bodyResponse.StatusCode != http.StatusNoContent || <-protocol != 3 || <-requestBodies != "payload" {
		t.Fatalf("GET body response=%v err=%v", bodyResponse, err)
	}
	redirectResponse, err := behaviorClient.R().Get(targetURL + "/redirect")
	if err != nil || redirectResponse.StatusCode != http.StatusFound || <-protocol != 3 {
		t.Fatalf("redirect response=%v err=%v", redirectResponse, err)
	}
	behaviorClient.GetClient().CloseIdleConnections()

	allowGetBodyFalse := false
	noGetBodyClient, err := buildReqClient(createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM, AllowGetBody: &allowGetBodyFalse})
	if err != nil {
		t.Fatal(err)
	}
	noBodyResponse, err := noGetBodyClient.R().SetBodyBytes([]byte("payload")).Get(targetURL + "/body")
	if err != nil || noBodyResponse.StatusCode != http.StatusNoContent || <-protocol != 3 || <-requestBodies != "" {
		t.Fatalf("disabled GET body response=%v err=%v", noBodyResponse, err)
	}
	noGetBodyClient.GetClient().CloseIdleConnections()

	limitedHeaderClient, err := buildReqClient(createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM, Transport: transportConfig{MaxResponseHeaderBytes: 128}})
	if err != nil {
		t.Fatal(err)
	}
	if response, requestErr := limitedHeaderClient.R().Get(targetURL + "/large-header"); requestErr == nil {
		t.Fatalf("oversized H3 response header accepted: %#v", response)
	}
	if <-protocol != 3 {
		t.Fatal("large header request did not use HTTP/3")
	}
	limitedHeaderClient.GetClient().CloseIdleConnections()
	beforeClose := handshakes.Load()
	afterClose, err := client.R().Get(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	if afterClose.StatusCode != http.StatusNoContent || <-protocol != 3 || handshakes.Load() <= beforeClose {
		t.Fatalf("HTTP/3 connection remained after close: before=%d after=%d", beforeClose, handshakes.Load())
	}
	client.GetClient().CloseIdleConnections()

	keepAliveConfig := createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM}
	keepAliveClient, err := buildReqClient(keepAliveConfig)
	if err != nil {
		t.Fatal(err)
	}
	const keepAliveClientID = "http3-keepalive"
	s.clients[keepAliveClientID] = &clientSession{client: keepAliveClient, config: keepAliveConfig, lastUsed: time.Now()}
	handshakesBeforeReuse := handshakes.Load()
	for range 2 {
		bridgeResponse := sendRawRequest(t, s.routes(), keepAliveClientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: targetURL})
		if bridgeResponse.Code != http.StatusOK || <-protocol != 3 {
			t.Fatalf("status=%d body=%s", bridgeResponse.Code, bridgeResponse.Body.String())
		}
	}
	if got := handshakes.Load() - handshakesBeforeReuse; got != 1 {
		t.Fatalf("keep_alive=true handshakes = %d", got)
	}
	keepAliveClient.GetClient().CloseIdleConnections()

	keepAliveFalse := false
	noKeepAliveConfig := createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM, KeepAlive: &keepAliveFalse}
	noKeepAliveClient, err := buildReqClient(noKeepAliveConfig)
	if err != nil {
		t.Fatal(err)
	}
	const noKeepAliveClientID = "http3-no-keepalive"
	s.clients[noKeepAliveClientID] = &clientSession{client: noKeepAliveClient, config: noKeepAliveConfig, lastUsed: time.Now()}
	handshakesBeforeRequests := handshakes.Load()
	for range 2 {
		bridgeResponse := sendRawRequest(t, s.routes(), noKeepAliveClientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: targetURL})
		if bridgeResponse.Code != http.StatusOK || <-protocol != 3 {
			t.Fatalf("status=%d body=%s", bridgeResponse.Code, bridgeResponse.Body.String())
		}
	}
	if got := handshakes.Load() - handshakesBeforeRequests; got != 2 {
		t.Fatalf("keep_alive=false handshakes = %d", got)
	}

	timeoutConfig := createClientRequest{HTTPVersion: "http3", RootCAPEM: caPEM, ClientCertPEM: clientCertificatePEM, ClientKeyPEM: clientKeyPEM}
	timeoutClient, err := buildReqClient(timeoutConfig)
	if err != nil {
		t.Fatal(err)
	}
	const timeoutClientID = "http3-timeout"
	s.clients[timeoutClientID] = &clientSession{client: timeoutClient, config: timeoutConfig, lastUsed: time.Now()}
	warmupResponse := sendRawRequest(t, s.routes(), timeoutClientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: targetURL})
	if warmupResponse.Code != http.StatusOK || <-protocol != 3 {
		t.Fatalf("warmup status=%d body=%s", warmupResponse.Code, warmupResponse.Body.String())
	}
	timeoutResponse := sendRawRequest(t, s.routes(), timeoutClientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: targetURL + "/slow", TimeoutMS: 5})
	if timeoutResponse.Code != http.StatusGatewayTimeout || decodeAPIError(t, timeoutResponse).Code != "UPSTREAM_TIMEOUT" || <-protocol != 3 {
		t.Fatalf("timeout status=%d body=%s", timeoutResponse.Code, timeoutResponse.Body.String())
	}
	timeoutClient.GetClient().CloseIdleConnections()
}

func TestClientOptionsHTTP3MapsOnlyEquivalentConfiguration(t *testing.T) {
	zero := uint32(0)
	client, err := buildReqClient(createClientRequest{
		HTTPVersion: "http3",
		Transport: transportConfig{
			TLSHandshakeTimeoutMS:  11,
			IdleConnTimeoutMS:      12,
			MaxResponseHeaderBytes: 4096,
			ProxyConnectHeaders:    map[string][]string{},
		},
		HTTP2: http2Config{ConnectionFlow: &zero, MaxHeaderListSize: &zero},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.GetClient().Transport.(*http3.Transport)
	if !ok {
		t.Fatalf("transport = %T", client.GetClient().Transport)
	}
	if transport.QUICConfig == nil {
		t.Fatal("QUICConfig is nil")
	}
	if transport.QUICConfig.HandshakeIdleTimeout != 11*time.Millisecond || transport.QUICConfig.MaxIdleTimeout != 12*time.Millisecond || transport.MaxResponseHeaderBytes != 4096 || client.GetClient().Timeout != 0 {
		t.Fatalf("QUIC=%#v max_header=%d client_timeout=%s", transport.QUICConfig, transport.MaxResponseHeaderBytes, client.GetClient().Timeout)
	}
	if !transport.DisableCompression {
		t.Fatal("HTTP/3 default compression is enabled")
	}

	connectionFlow := uint32(1)
	maxHeaderListSize := uint32(1)
	for _, test := range []struct {
		field string
		input createClientRequest
	}{
		{field: "proxy_url", input: createClientRequest{HTTPVersion: "http3", ProxyURL: "http://127.0.0.1:8080"}},
		{field: "response_header_timeout_ms", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{ResponseHeaderTimeoutMS: 1}}},
		{field: "expect_continue_timeout_ms", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{ExpectContinueTimeoutMS: 1}}},
		{field: "max_idle_conns", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{MaxIdleConns: 1}}},
		{field: "max_idle_conns_per_host", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{MaxIdleConnsPerHost: 1}}},
		{field: "max_conns_per_host", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{MaxConnsPerHost: 1}}},
		{field: "read_buffer_size", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{ReadBufferSize: 1}}},
		{field: "write_buffer_size", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{WriteBufferSize: 1}}},
		{field: "proxy_connect_headers", input: createClientRequest{HTTPVersion: "http3", Transport: transportConfig{ProxyConnectHeaders: map[string][]string{"X-Test": {"value"}}}}},
		{field: "http2.settings", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{Settings: []http2Setting{{ID: 1, Value: 1}}}}},
		{field: "http2.connection_flow", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{ConnectionFlow: &connectionFlow}}},
		{field: "http2.header_priority", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{HeaderPriority: &priorityParam{Weight: 1}}}},
		{field: "http2.priority_frames", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{PriorityFrames: []priorityFrame{{StreamID: 1}}}}},
		{field: "http2.max_header_list_size", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{MaxHeaderListSize: &maxHeaderListSize}}},
		{field: "http2.strict_max_concurrent_streams", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{StrictMaxConcurrentStreams: true}}},
		{field: "http2.read_idle_timeout_ms", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{ReadIdleTimeoutMS: 1}}},
		{field: "http2.ping_timeout_ms", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{PingTimeoutMS: 1}}},
		{field: "http2.write_byte_timeout_ms", input: createClientRequest{HTTPVersion: "http3", HTTP2: http2Config{WriteByteTimeoutMS: 1}}},
	} {
		if _, buildErr := buildReqClient(test.input); buildErr == nil || !strings.Contains(buildErr.Error(), test.field) {
			t.Fatalf("field %s error = %v", test.field, buildErr)
		}
	}

	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`","http_version":"http3","transport":{"read_buffer_size":1}}`)))
	if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" || !strings.Contains(response.Body.String(), "read_buffer_size") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`","http_version":"http3","transport":{"proxy_connect_headers":{}},"http2":{"connection_flow":0,"max_header_list_size":0}}`)))
	if response.Code != http.StatusCreated {
		t.Fatalf("default-valued HTTP/3 options rejected: status=%d body=%s", response.Code, response.Body.String())
	}
}

func createHTTP3Session(t *testing.T, s *server) (string, *http3.Transport) {
	t.Helper()
	created := httptest.NewRecorder()
	s.routes().ServeHTTP(created, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`","http_version":"http3"}`)))
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var result createClientResponse
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	session := s.clients[result.ClientID]
	s.mu.RUnlock()
	transport, ok := session.client.GetClient().Transport.(*http3.Transport)
	if !ok {
		t.Fatalf("transport = %T", session.client.GetClient().Transport)
	}
	return result.ClientID, transport
}

func assertHTTP3TransportClosed(t *testing.T, transport *http3.Transport) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = transport.RoundTrip(request); !errors.Is(err, http3.ErrTransportClosed) {
		t.Fatalf("RoundTrip error after close = %v", err)
	}
}

func TestDeleteClientClosesHTTP3Transport(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	for range 3 {
		clientID, transport := createHTTP3Session(t, s)
		deleted := httptest.NewRecorder()
		s.routes().ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/v1/clients/"+clientID, nil))
		if deleted.Code != http.StatusNoContent {
			t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
		}
		assertHTTP3TransportClosed(t, transport)
	}
}

func TestIdleCleanupClosesHTTP3Transport(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	clientID, transport := createHTTP3Session(t, s)
	s.clients[clientID].mu.Lock()
	s.clients[clientID].lastUsed = time.Now().Add(-2 * time.Hour)
	s.clients[clientID].mu.Unlock()

	s.cleanupIdleClients(time.Now())

	assertHTTP3TransportClosed(t, transport)
}

func TestServerCloseClosesAllHTTP3Transports(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	_, first := createHTTP3Session(t, s)
	_, second := createHTTP3Session(t, s)
	normalClient, err := buildReqClient(createClientRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s.clients["http1"] = &clientSession{client: normalClient, lastUsed: time.Now()}

	s.Close()
	s.Close()

	assertHTTP3TransportClosed(t, first)
	assertHTTP3TransportClosed(t, second)
	if len(s.clients) != 0 {
		t.Fatalf("remaining sessions = %d", len(s.clients))
	}
}

func TestHTTP3RejectsConnectionSpecificRequestOptions(t *testing.T) {
	client, err := buildReqClient(createClientRequest{HTTPVersion: "http3"})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer("", 48<<20, time.Hour)
	const clientID = "http3-request-options"
	s.clients[clientID] = &clientSession{client: client, config: createClientRequest{HTTPVersion: "http3"}, lastUsed: time.Now()}
	for _, test := range []struct {
		field   string
		options requestOptions
	}{
		{field: "force_chunked", options: requestOptions{ForceChunked: true}},
		{field: "close_connection", options: requestOptions{CloseConnection: true}},
		{field: "header_order", options: requestOptions{HeaderOrder: []string{"accept"}}},
		{field: "pseudo_header_order", options: requestOptions{PseudoHeaderOrder: []string{":method"}}},
	} {
		response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{ProtocolVersion: protocolVersion, Method: http.MethodGet, URL: "https://127.0.0.1:1", Options: test.options})
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" || !strings.Contains(response.Body.String(), test.field) {
			t.Fatalf("field=%s status=%d body=%s", test.field, response.Code, response.Body.String())
		}
	}
}

func TestClientOptionsRejectUnsafeProtocolCombinations(t *testing.T) {
	for _, input := range []createClientRequest{
		{HTTPVersion: "http2", ProxyURL: "http://127.0.0.1:8080"},
		{HTTPVersion: "http3", ProxyURL: "http://127.0.0.1:8080"},
		{HTTPVersion: "h2c", ProxyURL: "http://127.0.0.1:8080"},
		{HTTPVersion: "http3", TLSFingerprint: "chrome_120"},
		{HTTPVersion: "http3", TLSFingerprint: "android_11_okhttp", tlsFingerprintSet: true},
		{HTTPVersion: "http3", Impersonate: "chrome"},
	} {
		if _, err := buildReqClient(input); err == nil {
			t.Fatalf("unsafe combination accepted: %#v", input)
		}
	}
}

func TestClientOptionsCreateLimit(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	body := `{"protocol_version":1,"root_ca_pem":"` + strings.Repeat("a", 4<<20) + `"}`
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(body)))
	if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" || !strings.Contains(response.Body.String(), "4194304") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(s.clients) != 0 {
		t.Fatal("oversized configuration entered registry")
	}
}

func TestClientOptionsRejectNullAndInvalidRootCAPEM(t *testing.T) {
	_, validCA, _ := newTestCA(t, "strict PEM CA")
	for _, rootCA := range []string{"   ", "garbage" + validCA, validCA + "garbage", strings.Replace(validCA, "CERTIFICATE", "PRIVATE KEY", 2), validCA + "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"} {
		if _, err := buildReqClient(createClientRequest{RootCAPEM: rootCA}); err == nil {
			t.Fatalf("invalid root CA accepted: %q", rootCA)
		}
	}
	if _, err := buildReqClient(createClientRequest{RootCAPEM: validCA}); err != nil {
		t.Fatal(err)
	}

	for _, body := range []string{
		`{"protocol_version":null}`,
		`{"protocol_version":null,"protocol_version":1}`,
		`{"protocol_version":1,"verify":null}`,
		`{"protocol_version":1,"tls_fingerprint":null}`,
		`{"protocol_version":1,"retry":null}`,
		`{"protocol_version":1,"retry":{"status_codes":null}}`,
		`{"protocol_version":1,"retry":{"status_codes":[500,null]}}`,
		`{"protocol_version":1,"transport":{"proxy_connect_headers":{"X-Test":null}}}`,
		`{"protocol_version":1,"http2":{"settings":[null]}}`,
		`{"protocol_version":1,"http2":{"header_priority":null}}`,
	} {
		s := newServer("", 48<<20, time.Hour)
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
			t.Fatalf("null accepted: %s response=%s", body, response.Body.String())
		}
	}
}

func TestRejectJSONNullLexicalBoundaries(t *testing.T) {
	for _, body := range []string{
		`{"value":"null"}`,
		`{"value":"escaped \\\"null\\\" text"}`,
		`{"value":"backslash \\\\ then null"}`,
	} {
		if err := rejectJSONNull([]byte(body)); err != nil {
			t.Fatalf("string content rejected: %s: %v", body, err)
		}
	}
	if err := rejectJSONNull([]byte(`{"value":null,"value":1}`)); err == nil {
		t.Fatal("duplicate-key null accepted")
	}
	var input createClientRequest
	if err := json.Unmarshal([]byte(`{"protocol_version":1,"verify":tru`), &input); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestRequestEnvelopeNearLimitDoesNotBuildGenericJSONTree(t *testing.T) {
	body := []byte(`{"protocol_version":1,"method":"POST","url":"http://example.com","headers":[],"body_base64":"` + strings.Repeat("A", (4<<20)-1024) + `","timeout_ms":1,"options":{}}`)
	result := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			var input requestEnvelope
			if err := json.Unmarshal(body, &input); err != nil {
				b.Fatal(err)
			}
		}
	})
	allocated := result.AllocedBytesPerOp()
	t.Logf("decode allocated %d bytes per operation", allocated)
	if allocated > 16<<20 {
		t.Fatalf("decode allocated %d bytes per operation", allocated)
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

func TestClientOptionsRejectIgnoredRetryFields(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		retry retryConfig
	}{
		{name: "none fixed interval", field: "fixed_interval_ms", retry: retryConfig{FixedIntervalMS: 1}},
		{name: "none backoff minimum", field: "backoff_min_ms", retry: retryConfig{BackoffMinMS: 1}},
		{name: "none backoff maximum", field: "backoff_max_ms", retry: retryConfig{BackoffMaxMS: 1}},
		{name: "none status codes", field: "status_codes", retry: retryConfig{StatusCodes: []int{503}}},
		{name: "none count", field: "count", retry: retryConfig{Count: 1, Mode: retryNone}},
		{name: "zero count fixed mode", field: "mode", retry: retryConfig{Mode: retryFixed}},
		{name: "zero count backoff mode", field: "mode", retry: retryConfig{Mode: retryBackoff}},
		{name: "fixed backoff minimum", field: "backoff_min_ms", retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, BackoffMinMS: 1}},
		{name: "fixed backoff maximum", field: "backoff_max_ms", retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, BackoffMaxMS: 1}},
		{name: "backoff fixed interval", field: "fixed_interval_ms", retry: retryConfig{Count: 1, Mode: retryBackoff, FixedIntervalMS: 1, BackoffMinMS: 1, BackoffMaxMS: 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildReqClient(createClientRequest{Retry: test.retry})
			if err == nil || !strings.Contains(err.Error(), "retry."+test.field) {
				t.Fatalf("error = %v, want retry.%s", err, test.field)
			}
		})
	}
}

func TestCreateClientRejectsIgnoredRetryField(t *testing.T) {
	s := newServer("", 48<<20, time.Hour)
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(`{"protocol_version":1,"sdk_version":"`+serverVersion+`","retry":{"count":1,"mode":"fixed","fixed_interval_ms":1,"backoff_min_ms":1}}`)))
	if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" || !strings.Contains(response.Body.String(), "retry.backoff_min_ms") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCustomTLSJSONCreatesSession(t *testing.T) {
	spec, err := os.ReadFile("testdata/tls/custom_tls13.json")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"protocol_version": protocolVersion, "sdk_version": serverVersion, "tls_spec": json.RawMessage(spec)})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer("", 48<<20, time.Hour)
	defer s.Close()
	response := httptest.NewRecorder()
	s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", bytes.NewReader(body)))
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d response=%s", response.Code, response.Body.String())
	}
}

func TestCustomTLSRejectsIgnoredInvalidAndConflictingConfiguration(t *testing.T) {
	raw, err := os.ReadFile("testdata/tls/custom_tls13.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown top field", func(s map[string]any) { s["fake"] = true }},
		{"case insensitive top field", func(s map[string]any) { s["Cipher_Suites"] = s["cipher_suites"]; delete(s, "cipher_suites") }},
		{"empty suites", func(s map[string]any) { s["cipher_suites"] = []string{} }},
		{"duplicate suites", func(s map[string]any) { s["cipher_suites"] = []string{"TLS_AES_128_GCM_SHA256", "0x1301"} }},
		{"duplicate GREASE aliases", func(s map[string]any) { s["cipher_suites"] = []string{"0x1a1a", "0x2a2a", "0x1301"} }},
		{"unknown suites", func(s map[string]any) { s["cipher_suites"] = []string{"unknown"} }},
		{"missing compression", func(s map[string]any) { delete(s, "compression_methods") }},
		{"null extension", func(s map[string]any) { s["extensions"].([]any)[2] = nil }},
		{"unknown extension", func(s map[string]any) { s["extensions"].([]any)[2] = map[string]any{"name": "pre_shared_key"} }},
		{"ignored extension field", func(s map[string]any) { s["extensions"].([]any)[2].(map[string]any)["unknown"] = 1 }},
		{"missing extension field", func(s map[string]any) {
			delete(s["extensions"].([]any)[2].(map[string]any), "supported_signature_algorithms")
		}},
		{"duplicate extension", func(s map[string]any) { s["extensions"].([]any)[2] = s["extensions"].([]any)[1] }},
		{"static key", func(s map[string]any) {
			s["extensions"].([]any)[5].(map[string]any)["client_shares"].([]any)[1].(map[string]any)["key_exchange"] = []int{1, 2}
		}},
		{"key field typo", func(s map[string]any) {
			s["extensions"].([]any)[5].(map[string]any)["client_shares"].([]any)[1].(map[string]any)["unknown"] = 1
		}},
		{"key group missing", func(s map[string]any) {
			s["extensions"].([]any)[5].(map[string]any)["client_shares"].([]any)[1].(map[string]any)["group"] = "secp384r1"
		}},
		{"non HTTP ALPN", func(s map[string]any) {
			s["extensions"].([]any)[6].(map[string]any)["protocol_name_list"] = []string{"h3"}
		}},
		{"version conflict", func(s map[string]any) { s["min_vers"] = 771 }},
		{"wrong bool type", func(s map[string]any) { s["shuffle_extensions"] = "false" }},
		{"wrong integer type", func(s map[string]any) { s["min_vers"] = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal(raw, &spec); err != nil {
				t.Fatal(err)
			}
			test.change(spec)
			body, err := json.Marshal(map[string]any{"protocol_version": protocolVersion, "sdk_version": serverVersion, "tls_spec": spec})
			if err != nil {
				t.Fatal(err)
			}
			s := newServer("", 48<<20, time.Hour)
			defer s.Close()
			response := httptest.NewRecorder()
			s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", bytes.NewReader(body)))
			if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
				t.Fatalf("unexpected response: %s", response.Body.String())
			}
		})
	}
	for _, data := range []string{
		strings.Replace(string(raw), `"extensions":`, `"extensions":[],"extensions":`, 1),
		strings.Replace(string(raw), `"name": "server_name"`, `"name":"GREASE","name":"server_name"`, 1),
		string(raw) + `{}`,
		`{"cipher_suites":["` + strings.Repeat("x", maxTLSSpecBytes) + `"]}`,
	} {
		var spec tlsSpec
		if err := json.Unmarshal([]byte(data), &spec); err == nil {
			t.Fatal("invalid JSON was accepted")
		}
	}
	var spec tlsSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for _, config := range []createClientRequest{
		{TLSSpec: &spec, TLSFingerprint: "golang"}, {TLSSpec: &spec, tlsFingerprintSet: true},
		{TLSSpec: &spec, Impersonate: "chrome"}, {TLSSpec: &spec, HTTPVersion: "http2"},
		{TLSSpec: &spec, HTTPVersion: "http3"}, {TLSSpec: &spec, HTTPVersion: "h2c"},
	} {
		if _, err := buildReqClient(config); err == nil {
			t.Fatalf("conflicting TLS config accepted: %#v", config)
		}
	}
}

func TestCustomTLSGREASEAliasesNormalizeBeforeDeduplication(t *testing.T) {
	for _, alias := range []string{"GREASE", "0x0a0a", "0x1a1a", "0xfafa"} {
		ids, err := tlsIDs([]string{alias, "0x1301"}, nil)
		if err != nil || !reflect.DeepEqual(ids, []uint16{0x0a0a, 0x1301}) {
			t.Fatalf("alias=%s ids=%x err=%v", alias, ids, err)
		}
		if _, err := tlsIDs([]string{alias, "0x0a0a"}, nil); err == nil {
			t.Fatalf("duplicate GREASE accepted: %s", alias)
		}
	}
	shares, err := parseTLSKeyShares([]byte(`[{"group":"0x1a1a","key_exchange":[0]},{"group":"x25519"}]`))
	if err != nil || len(shares.KeyShares) != 2 || shares.KeyShares[0].Group != 0x0a0a {
		t.Fatalf("shares=%v err=%v", shares, err)
	}
	if _, err := parseTLSKeyShares([]byte(`[{"group":"0x1a1a"},{"group":"0x2a2a"}]`)); err == nil {
		t.Fatal("duplicate GREASE key shares accepted")
	}
}

func TestCustomTLSModernBrowserExtensionsSerializeDeclaredBytes(t *testing.T) {
	tests := []struct {
		name string
		json string
		want []byte
	}{
		{"delegated credentials", `{"name":"delegated_credentials","supported_signature_algorithms":["ecdsa_secp256r1_sha256","ecdsa_secp384r1_sha384","0x0603"]}`,
			[]byte{0x00, 0x22, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03}},
		{"record size limit", `{"name":"record_size_limit","record_size_limit":16385}`,
			[]byte{0x00, 0x1c, 0x00, 0x02, 0x40, 0x01}},
		{"certificate compression", `{"name":"compress_certificate","algorithms":["zlib","brotli","zstd"]}`,
			[]byte{0x00, 0x1b, 0x00, 0x07, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, extension, err := parseTLSExtension([]byte(test.json))
			if err != nil {
				t.Fatal(err)
			}
			wire := make([]byte, extension.Len())
			if _, err := extension.Read(wire); err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, test.want) {
				t.Fatalf("wire=%x want=%x", wire, test.want)
			}
		})
	}
	_, extension, err := parseTLSExtension([]byte(`{"name":"encrypted_client_hello","candidate_cipher_suites":[{"kdf_id":1,"aead_id":3}],"candidate_config_ids":[145],"candidate_payload_lens":[223]}`))
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, extension.Len())
	if _, err := extension.Read(wire); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if len(wire) != 285 || !bytes.Equal(wire[:9], []byte{0xfe, 0x0d, 0x01, 0x19, 0x00, 0x00, 0x01, 0x00, 0x03}) ||
		wire[9] != 145 || !bytes.Equal(wire[10:12], []byte{0x00, 0x20}) || !bytes.Equal(wire[44:46], []byte{0x00, 0xef}) {
		t.Fatalf("unexpected ECH wire shape: len=%d wire=%x", len(wire), wire)
	}

	for _, invalid := range []string{
		`{"name":"record_size_limit","record_size_limit":63}`,
		`{"name":"record_size_limit","record_size_limit":16386}`,
		`{"name":"encrypted_client_hello","candidate_cipher_suites":[]}`,
		`{"name":"encrypted_client_hello","candidate_cipher_suites":[{"kdf_id":1,"aead_id":4}]}`,
		`{"name":"encrypted_client_hello","candidate_payload_lens":[0]}`,
		`{"name":"encrypted_client_hello","candidate_config_ids":[1,1]}`,
	} {
		if _, _, err := parseTLSExtension([]byte(invalid)); err == nil {
			t.Fatalf("invalid extension accepted: %s", invalid)
		}
	}
}

func TestCustomTLSConcurrentHandshakesUseIndependentSpecs(t *testing.T) {
	raw, err := os.ReadFile("testdata/tls/custom_tls13.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec tlsSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	one, err := spec.clientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	two, err := spec.clientHelloSpec()
	if err != nil {
		t.Fatal(err)
	}
	for i := range one.Extensions {
		if one.Extensions[i] == two.Extensions[i] {
			t.Fatal("TLS extension shared across connections")
		}
	}
	var handshakes atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "custom TLS") }))
	target.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if !reflect.DeepEqual(info.CipherSuites[1:], []uint16{0x1302, 0x1303, 0x1301}) {
			t.Errorf("wire cipher suites=%x", info.CipherSuites)
		}
		if !reflect.DeepEqual(info.SignatureSchemes, []tls.SignatureScheme{0x0805, 0x0403, 0x0804}) {
			t.Errorf("wire signature schemes=%x", info.SignatureSchemes)
		}
		handshakes.Add(1)
		return nil, nil
	}}
	target.StartTLS()
	defer target.Close()
	verify, keepAlive := false, false
	client, err := buildReqClient(createClientRequest{TLSSpec: &spec, Verify: &verify, KeepAlive: &keepAlive})
	if err != nil {
		t.Fatal(err)
	}
	defer client.GetClient().CloseIdleConnections()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := client.R().Get(target.URL)
			if err != nil {
				t.Error(err)
				return
			}
			if response.StatusCode != http.StatusOK {
				t.Errorf("status=%d", response.StatusCode)
			}
		}()
	}
	wg.Wait()
	if handshakes.Load() != 12 {
		t.Fatalf("handshakes=%d", handshakes.Load())
	}
}

func TestClientOptionsStrictNestedJSONAndInvalidConfigurationCode(t *testing.T) {
	for _, body := range []string{
		`{"protocol_version":1,"retry":{"unknown":1}}`,
		`{"protocol_version":1,"transport":{"unknown":1}}`,
		`{"protocol_version":1,"http2":{"settings":[{"id":1,"value":1,"unknown":1}]}}`,
		`{"protocol_version":1,"sdk_version":"` + serverVersion + `","proxy_url":"ftp://proxy.example"}`,
		`{"protocol_version":1,"sdk_version":"` + serverVersion + `","impersonate":"chrome","tls_fingerprint":"golang"}`,
	} {
		s := newServer("", 48<<20, time.Hour)
		response := httptest.NewRecorder()
		s.routes().ServeHTTP(response, newJSONControlRequest("/api/v1/clients", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" {
			t.Fatalf("body=%s status=%d response=%s", body, response.Code, response.Body.String())
		}
	}
}

func TestRequestOptionsMapChunkedCloseRetryTraceAndDump(t *testing.T) {
	var calls int
	var closed bool
	var chunked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		closed = r.Close
		chunked = len(r.TransferEncoding) == 1 && r.TransferEncoding[0] == "chunked"
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
	if calls != 1 || !closed || !chunked || result.Trace == nil || result.Dump == nil || !strings.Contains(*result.Dump, "dump body") {
		t.Fatalf("calls=%d closed=%t chunked=%t trace=%#v dump=%v", calls, closed, chunked, result.Trace, result.Dump)
	}
}

func TestForceChunkedBodyRetriesWithFreshReader(t *testing.T) {
	var bodies [][]byte
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
		if len(bodies) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()

	s := newServer("", 48<<20, time.Hour)
	client, err := buildReqClient(createClientRequest{Retry: retryConfig{Count: 1, Mode: retryFixed, FixedIntervalMS: 1, StatusCodes: []int{http.StatusServiceUnavailable}}})
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "chunked-retry"
	s.clients[clientID] = &clientSession{client: client, lastUsed: time.Now()}
	response := sendRawRequest(t, s.routes(), clientID, requestEnvelope{
		ProtocolVersion: protocolVersion,
		Method:          http.MethodPost,
		URL:             target.URL,
		BodyBase64:      base64.StdEncoding.EncodeToString([]byte("retry body")),
		Options:         requestOptions{ForceChunked: true},
	})
	var result responseEnvelope
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.StatusCode != http.StatusNoContent || !reflect.DeepEqual(bodies, [][]byte{[]byte("retry body"), []byte("retry body")}) {
		t.Fatalf("status=%d result=%#v bodies=%q", response.Code, result, bodies)
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
		if response.Code != http.StatusBadRequest || decodeAPIError(t, response).Code != "INVALID_REQUEST" || !strings.Contains(response.Body.String(), "retry_count") {
			t.Fatalf("count=%d status=%d body=%s", count, response.Code, response.Body.String())
		}
	}
}

func TestRequestOptionsOmitDisabledDiagnostics(t *testing.T) {
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
	for _, field := range []string{"trace", "dump"} {
		if _, ok := wire[field]; ok {
			t.Fatalf("disabled %s must be omitted: %s", field, response.Body.String())
		}
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

	for _, proxyTLS := range []*tls.Config{nil, {Certificates: []tls.Certificate{serverCertificate}}} {
		proxy := newTestConnectProxy(t, proxyTLS)
		proxiedClient, err := buildReqClient(createClientRequest{TLSFingerprint: "chrome_120", ProxyURL: proxy.URL, RootCAPEM: trustedCAPEM, ClientCertPEM: clientCertPEM, ClientKeyPEM: clientKeyPEM})
		if err != nil {
			t.Fatal(err)
		}
		proxiedResponse, err := proxiedClient.R().Get(target.URL)
		proxiedClient.GetTransport().CloseIdleConnections()
		proxy.Close()
		if err != nil || proxiedResponse.StatusCode != http.StatusNoContent {
			t.Fatalf("proxy=%s response=%v err=%v", proxy.URL, proxiedResponse, err)
		}
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

func newTestConnectProxy(t *testing.T, tlsConfig *tls.Config) *httptest.Server {
	t.Helper()
	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	if tlsConfig == nil {
		proxy.Start()
	} else {
		proxy.TLS = tlsConfig
		proxy.StartTLS()
	}
	return proxy
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
