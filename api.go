package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
)

const protocolVersion = 1

var fingerprints = map[string]utls.ClientHelloID{
	"golang":                         utls.HelloGolang,
	"randomized":                     utls.HelloRandomized,
	"randomized_alpn":                utls.HelloRandomizedALPN,
	"randomized_no_alpn":             utls.HelloRandomizedNoALPN,
	"android_11_okhttp":              utls.HelloAndroid_11_OkHttp,
	"chrome_auto":                    utls.HelloChrome_Auto,
	"chrome_58":                      utls.HelloChrome_58,
	"chrome_62":                      utls.HelloChrome_62,
	"chrome_70":                      utls.HelloChrome_70,
	"chrome_72":                      utls.HelloChrome_72,
	"chrome_83":                      utls.HelloChrome_83,
	"chrome_87":                      utls.HelloChrome_87,
	"chrome_96":                      utls.HelloChrome_96,
	"chrome_100":                     utls.HelloChrome_100,
	"chrome_102":                     utls.HelloChrome_102,
	"chrome_106_shuffle":             utls.HelloChrome_106_Shuffle,
	"chrome_100_psk":                 utls.HelloChrome_100_PSK,
	"chrome_112_psk_shuffle":         utls.HelloChrome_112_PSK_Shuf,
	"chrome_114_padding_psk_shuffle": utls.HelloChrome_114_Padding_PSK_Shuf,
	"chrome_115_pq":                  utls.HelloChrome_115_PQ,
	"chrome_115_pq_psk":              utls.HelloChrome_115_PQ_PSK,
	"chrome_120":                     utls.HelloChrome_120,
	"chrome_120_pq":                  utls.HelloChrome_120_PQ,
	"chrome_131":                     utls.HelloChrome_131,
	"chrome_133":                     utls.HelloChrome_133,
	"firefox_auto":                   utls.HelloFirefox_Auto,
	"firefox_55":                     utls.HelloFirefox_55,
	"firefox_56":                     utls.HelloFirefox_56,
	"firefox_63":                     utls.HelloFirefox_63,
	"firefox_65":                     utls.HelloFirefox_65,
	"firefox_99":                     utls.HelloFirefox_99,
	"firefox_102":                    utls.HelloFirefox_102,
	"firefox_105":                    utls.HelloFirefox_105,
	"firefox_120":                    utls.HelloFirefox_120,
	"ios_auto":                       utls.HelloIOS_Auto,
	"ios_11_1":                       utls.HelloIOS_11_1,
	"ios_12_1":                       utls.HelloIOS_12_1,
	"ios_13":                         utls.HelloIOS_13,
	"ios_14":                         utls.HelloIOS_14,
	"edge_auto":                      utls.HelloEdge_Auto,
	"edge_85":                        utls.HelloEdge_85,
	"edge_106":                       utls.HelloEdge_106,
	"safari_auto":                    utls.HelloSafari_Auto,
	"safari_16_0":                    utls.HelloSafari_16_0,
	"360_auto":                       utls.Hello360_Auto,
	"360_7_5":                        utls.Hello360_7_5,
	"360_11_0":                       utls.Hello360_11_0,
	"qq_auto":                        utls.HelloQQ_Auto,
	"qq_11_1":                        utls.HelloQQ_11_1,
}

type healthResponse struct {
	Status          string `json:"status"`
	ProtocolVersion int    `json:"protocol_version"`
	ServerVersion   string `json:"server_version"`
}

type apiError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	RequestID string `json:"request_id,omitempty"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

type createClientRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	TLSFingerprint  string `json:"tls_fingerprint,omitempty"`
}

type clientSession struct {
	client      *req.Client
	config      createClientRequest
	lastUsed    time.Time
	activeCalls int
	mu          sync.Mutex
}

type createClientResponse struct {
	ProtocolVersion int       `json:"protocol_version"`
	ClientID        string    `json:"client_id"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type server struct {
	token        string
	maxBodyBytes int64
	idleTTL      time.Duration
	clients      map[string]*clientSession
	mu           sync.RWMutex
}

func newServer(token string, maxBodyBytes int64, idleTTL time.Duration) *server {
	s := &server{
		token:        token,
		maxBodyBytes: maxBodyBytes,
		idleTTL:      idleTTL,
		clients:      make(map[string]*clientSession),
	}
	go s.cleanupLoop()
	return s
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok", ProtocolVersion: protocolVersion, ServerVersion: "1.0.0"})
	})
	mux.Handle("GET /api/v1/capabilities", s.authenticate(http.HandlerFunc(s.handleCapabilities)))
	mux.Handle("POST /api/v1/clients", s.authenticate(http.HandlerFunc(s.handleCreateClient)))
	mux.Handle("DELETE /api/v1/clients/{clientID}", s.authenticate(http.HandlerFunc(s.handleDeleteClient)))
	return mux
}

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, errorResponse{Error: apiError{
			Code:    "UNAUTHORIZED",
			Message: "missing or invalid bearer token",
		}})
	})
}

func (s *server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	tlsFingerprints := make([]string, 0, len(fingerprints))
	for name := range fingerprints {
		tlsFingerprints = append(tlsFingerprints, name)
	}
	sort.Strings(tlsFingerprints)
	writeJSON(w, http.StatusOK, struct {
		ProtocolVersion int      `json:"protocol_version"`
		ServerVersion   string   `json:"server_version"`
		MaxBodyBytes    int64    `json:"max_body_bytes"`
		TLSFingerprints []string `json:"tls_fingerprints"`
	}{
		ProtocolVersion: protocolVersion,
		ServerVersion:   "1.0.0",
		MaxBodyBytes:    s.maxBodyBytes,
		TLSFingerprints: tlsFingerprints,
	})
}

func (s *server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var input createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: "invalid client configuration"}})
		return
	}
	if input.ProtocolVersion != protocolVersion {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "PROTOCOL_MISMATCH", Message: "unsupported protocol version"}})
		return
	}
	if input.TLSFingerprint == "" {
		input.TLSFingerprint = "android_11_okhttp"
	}
	client, err := buildReqClient(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "UNSUPPORTED_FEATURE", Message: err.Error()}})
		return
	}
	clientID, err := newClientID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{Code: "INTERNAL_ERROR", Message: "failed to create client session"}})
		return
	}
	now := time.Now()
	s.mu.Lock()
	s.clients[clientID] = &clientSession{client: client, config: input, lastUsed: now}
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, createClientResponse{
		ProtocolVersion: protocolVersion,
		ClientID:        clientID,
		ExpiresAt:       now.Add(s.idleTTL),
	})
}

func (s *server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	session := s.clients[r.PathValue("clientID")]
	delete(s.clients, r.PathValue("clientID"))
	s.mu.Unlock()
	if session != nil {
		session.client.GetTransport().CloseIdleConnections()
	}
	w.WriteHeader(http.StatusNoContent)
}

func buildReqClient(input createClientRequest) (*req.Client, error) {
	fingerprint := input.TLSFingerprint
	if fingerprint == "" {
		fingerprint = "android_11_okhttp"
	}
	clientHelloID, ok := fingerprints[fingerprint]
	if !ok {
		return nil, fmt.Errorf("unsupported TLS fingerprint %q", fingerprint)
	}
	client := req.C().
		DisableAutoDecompress().
		DisableAutoDecode()
	client.GetClient().Jar = nil
	client.GetClient().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.SetTLSFingerprint(clientHelloID)
	return client, nil
}

func newClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *server) cleanupLoop() {
	ticker := time.NewTicker(s.idleTTL)
	defer ticker.Stop()
	for now := range ticker.C {
		s.cleanupIdleClients(now)
	}
}

func (s *server) cleanupIdleClients(now time.Time) {
	var expired []*clientSession
	s.mu.Lock()
	for clientID, session := range s.clients {
		session.mu.Lock()
		idle := session.activeCalls == 0 && now.Sub(session.lastUsed) > s.idleTTL
		session.mu.Unlock()
		if idle {
			delete(s.clients, clientID)
			expired = append(expired, session)
		}
	}
	s.mu.Unlock()
	for _, session := range expired {
		session.client.GetTransport().CloseIdleConnections()
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("JSON 响应编码失败: %v", err)
	}
}
