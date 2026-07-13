package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http/httpguts"
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

type requestOptions struct {
	HeaderOrder       []string `json:"header_order,omitempty"`
	PseudoHeaderOrder []string `json:"pseudo_header_order,omitempty"`
	ForceChunked      bool     `json:"force_chunked,omitempty"`
	CloseConnection   bool     `json:"close_connection,omitempty"`
	Trace             bool     `json:"trace,omitempty"`
	Dump              bool     `json:"dump,omitempty"`
	RetryCount        *int     `json:"retry_count,omitempty"`
}

type requestEnvelope struct {
	ProtocolVersion int            `json:"protocol_version"`
	Method          string         `json:"method"`
	URL             string         `json:"url"`
	Headers         [][2]string    `json:"headers"`
	BodyBase64      string         `json:"body_base64"`
	TimeoutMS       int64          `json:"timeout_ms"`
	Options         requestOptions `json:"options"`
}

type responseTrace struct {
	DNSLookupMS      float64 `json:"dns_lookup_ms"`
	ConnectMS        float64 `json:"connect_ms"`
	TLSHandshakeMS   float64 `json:"tls_handshake_ms"`
	FirstByteMS      float64 `json:"first_byte_ms"`
	ResponseMS       float64 `json:"response_ms"`
	TotalMS          float64 `json:"total_ms"`
	ConnectionReused bool    `json:"connection_reused"`
	RemoteAddress    string  `json:"remote_address"`
}

type responseEnvelope struct {
	ProtocolVersion int            `json:"protocol_version"`
	RequestID       string         `json:"request_id"`
	StatusCode      int            `json:"status_code"`
	ReasonPhrase    string         `json:"reason_phrase"`
	Headers         [][2]string    `json:"headers"`
	BodyBase64      string         `json:"body_base64"`
	URL             string         `json:"url"`
	HTTPVersion     string         `json:"http_version"`
	ElapsedMS       float64        `json:"elapsed_ms"`
	Trace           *responseTrace `json:"trace"`
	Dump            *string        `json:"dump"`
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
	mux.Handle("POST /api/v1/clients/{clientID}/requests", s.authenticate(http.HandlerFunc(s.handleRawRequest)))
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
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: "invalid client configuration"}})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
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

func (s *server) handleRawRequest(w http.ResponseWriter, r *http.Request) {
	requestID, err := newClientID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{Code: "INTERNAL_ERROR", Message: "failed to create request ID"}})
		return
	}
	started := time.Now()
	method := ""
	host := ""
	status := 0
	errorCode := ""
	defer func() {
		log.Printf("request_id=%q method=%q host=%q status=%d elapsed_ms=%.3f error_code=%q", requestID, method, host, status, float64(time.Since(started))/float64(time.Millisecond), errorCode)
	}()
	writeError := func(httpStatus int, code, message string, retryable bool) {
		status = httpStatus
		errorCode = code
		writeJSON(w, httpStatus, errorResponse{Error: apiError{Code: code, Message: message, Retryable: retryable, RequestID: requestID}})
	}

	s.mu.RLock()
	session := s.clients[r.PathValue("clientID")]
	if session != nil {
		session.mu.Lock()
		session.activeCalls++
		session.lastUsed = time.Now()
		session.mu.Unlock()
	}
	s.mu.RUnlock()
	if session == nil {
		writeError(http.StatusNotFound, "CLIENT_NOT_FOUND", "client session not found", false)
		return
	}
	defer func() {
		session.mu.Lock()
		session.activeCalls--
		session.mu.Unlock()
	}()

	input, headers, body, validationError := decodeRequestEnvelope(w, r, s.maxBodyBytes)
	method = input.Method
	if parsedURL, parseErr := url.Parse(input.URL); parseErr == nil {
		host = parsedURL.Host
	}
	if validationError != nil {
		writeError(http.StatusBadRequest, validationError.Code, validationError.Message, false)
		return
	}

	ctx := r.Context()
	if input.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	targetReq := session.client.R().SetContext(ctx)
	if targetReq.Headers == nil {
		targetReq.Headers = make(http.Header)
	}
	for _, pair := range headers {
		targetReq.Headers.Add(pair[0], pair[1])
	}
	if len(input.Options.HeaderOrder) > 0 {
		targetReq.SetHeaderOrder(input.Options.HeaderOrder...)
	}
	if len(input.Options.PseudoHeaderOrder) > 0 {
		targetReq.SetPseudoHeaderOrder(input.Options.PseudoHeaderOrder...)
	}
	if len(body) > 0 {
		targetReq.SetBodyBytes(body)
	}
	if input.Options.Trace {
		targetReq.EnableTrace()
	}

	response, err := targetReq.Send(input.Method, input.URL)
	if err != nil {
		code, retryable := classifyUpstreamError(err)
		message := map[string]string{
			"UPSTREAM_TIMEOUT":        "target request timed out",
			"UPSTREAM_DNS_ERROR":      "target DNS lookup failed",
			"UPSTREAM_CONNECT_ERROR":  "target connection failed",
			"UPSTREAM_TLS_ERROR":      "target TLS handshake failed",
			"UPSTREAM_PROTOCOL_ERROR": "target protocol failed",
		}[code]
		httpStatus := http.StatusBadGateway
		if code == "UPSTREAM_TIMEOUT" {
			httpStatus = http.StatusGatewayTimeout
		}
		writeError(httpStatus, code, message, retryable)
		return
	}
	if int64(len(response.Bytes())) > s.maxBodyBytes {
		writeError(http.StatusBadGateway, "UPSTREAM_PROTOCOL_ERROR", "target response body exceeds limit", false)
		return
	}

	headerNames := make([]string, 0, len(response.Header))
	for name := range response.Header {
		headerNames = append(headerNames, name)
	}
	sort.Strings(headerNames)
	responseHeaders := make([][2]string, 0, len(response.Header))
	for _, name := range headerNames {
		for _, value := range response.Header.Values(name) {
			responseHeaders = append(responseHeaders, [2]string{bytesToLatin1(name), bytesToLatin1(value)})
		}
	}
	responseURL := input.URL
	if response.Request != nil && response.Request.URL != nil {
		responseURL = response.Request.URL.String()
	}
	reasonPhrase := http.StatusText(response.StatusCode)
	if prefix := fmt.Sprintf("%d ", response.StatusCode); strings.HasPrefix(response.Status, prefix) {
		reasonPhrase = strings.TrimPrefix(response.Status, prefix)
	}
	var trace *responseTrace
	if input.Options.Trace {
		info := response.TraceInfo()
		remoteAddress := ""
		if info.RemoteAddr != nil {
			remoteAddress = info.RemoteAddr.String()
		}
		trace = &responseTrace{
			DNSLookupMS:      float64(info.DNSLookupTime) / float64(time.Millisecond),
			ConnectMS:        float64(info.ConnectTime) / float64(time.Millisecond),
			TLSHandshakeMS:   float64(info.TLSHandshakeTime) / float64(time.Millisecond),
			FirstByteMS:      float64(info.FirstResponseTime) / float64(time.Millisecond),
			ResponseMS:       float64(info.ResponseTime) / float64(time.Millisecond),
			TotalMS:          float64(info.TotalTime) / float64(time.Millisecond),
			ConnectionReused: info.IsConnReused,
			RemoteAddress:    remoteAddress,
		}
	}
	status = response.StatusCode
	writeJSON(w, http.StatusOK, responseEnvelope{
		ProtocolVersion: protocolVersion,
		RequestID:       requestID,
		StatusCode:      response.StatusCode,
		ReasonPhrase:    reasonPhrase,
		Headers:         responseHeaders,
		BodyBase64:      base64.StdEncoding.EncodeToString(response.Bytes()),
		URL:             responseURL,
		HTTPVersion:     response.Proto,
		ElapsedMS:       float64(response.TotalTime()) / float64(time.Millisecond),
		Trace:           trace,
	})
}

func decodeRequestEnvelope(w http.ResponseWriter, r *http.Request, maxBodyBytes int64) (requestEnvelope, [][2]string, []byte, *apiError) {
	maxEnvelopeBytes := int64(math.MaxInt64)
	if maxBodyBytes <= (math.MaxInt64-(8<<20))/2 {
		maxEnvelopeBytes = maxBodyBytes*2 + 8<<20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEnvelopeBytes)
	var input requestEnvelope
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid request envelope"}
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid request envelope"}
	}
	if input.ProtocolVersion != protocolVersion {
		return input, nil, nil, &apiError{Code: "PROTOCOL_MISMATCH", Message: "unsupported protocol version"}
	}
	if input.Method == "" || len(input.Method) > 64 || !httpguts.ValidHeaderFieldName(input.Method) {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid HTTP method"}
	}
	if len(input.URL) > 16384 {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid target URL"}
	}
	parsedURL, err := url.Parse(input.URL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid target URL"}
	}
	if len(input.Headers) > 256 {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "too many headers"}
	}
	headers := make([][2]string, 0, len(input.Headers))
	headerBytes := 0
	for _, pair := range input.Headers {
		name, ok := latin1ToBytes(pair[0])
		if !ok || len(name) == 0 || len(name) > 256 || !httpguts.ValidHeaderFieldName(name) {
			return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid header name"}
		}
		value, ok := latin1ToBytes(pair[1])
		if !ok || len(value) > 16384 || !httpguts.ValidHeaderFieldValue(value) {
			return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid header value"}
		}
		headerBytes += len(name) + len(value)
		if headerBytes > 1<<20 {
			return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "headers exceed limit"}
		}
		headers = append(headers, [2]string{name, value})
	}
	body, err := base64.StdEncoding.DecodeString(input.BodyBase64)
	if err != nil || int64(len(body)) > maxBodyBytes {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid request body"}
	}
	if input.TimeoutMS < 0 || input.TimeoutMS > 600000 {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid request timeout"}
	}
	return input, headers, body, nil
}

func latin1ToBytes(value string) (string, bool) {
	var result strings.Builder
	result.Grow(len(value))
	for _, char := range value {
		if char > 255 {
			return "", false
		}
		result.WriteByte(byte(char))
	}
	return result.String(), true
}

func bytesToLatin1(value string) string {
	chars := make([]rune, len(value))
	for i, char := range []byte(value) {
		chars[i] = rune(char)
	}
	return string(chars)
}

func classifyUpstreamError(err error) (string, bool) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "UPSTREAM_TIMEOUT", true
	}
	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		return "UPSTREAM_DNS_ERROR", true
	}
	var certificateInvalid x509.CertificateInvalidError
	var unknownAuthority x509.UnknownAuthorityError
	var certificateVerification *tls.CertificateVerificationError
	var recordHeader tls.RecordHeaderError
	var utlsRecordHeader utls.RecordHeaderError
	message := strings.ToLower(err.Error())
	if errors.As(err, &certificateInvalid) || errors.As(err, &unknownAuthority) || errors.As(err, &certificateVerification) || errors.As(err, &recordHeader) || errors.As(err, &utlsRecordHeader) || strings.Contains(message, "tls:") || strings.Contains(message, "certificate") {
		return "UPSTREAM_TLS_ERROR", false
	}
	var protocolError *http.ProtocolError
	if errors.As(err, &protocolError) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(message, "malformed http") {
		return "UPSTREAM_PROTOCOL_ERROR", false
	}
	var netError net.Error
	if errors.As(err, &netError) {
		if netError.Timeout() {
			return "UPSTREAM_TIMEOUT", true
		}
		return "UPSTREAM_CONNECT_ERROR", true
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return "UPSTREAM_PROTOCOL_ERROR", false
	}
	return "UPSTREAM_PROTOCOL_ERROR", false
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
		DisableCompression().
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
