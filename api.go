package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/imroc/req/v3"
	"github.com/imroc/req/v3/http2"
	"github.com/quic-go/quic-go"
	quichttp3 "github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
)

const (
	protocolVersion      = 1
	maxClientConfigBytes = 4 << 20
	retryNone            = "none"
	retryFixed           = "fixed"
	retryBackoff         = "backoff"
)

var serverVersion = "2.1.0"

func versionLine() string {
	versions := map[string]string{}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range info.Deps {
			version := dependency.Version
			if dependency.Replace != nil {
				version = dependency.Replace.Version
			}
			versions[dependency.Path] = version
		}
	}
	return fmt.Sprintf(
		"GoHTTPX server %s protocol %d req/v3 %s uTLS %s",
		serverVersion,
		protocolVersion,
		versions["github.com/imroc/req/v3"],
		versions["github.com/refraction-networking/utls"],
	)
}

var errUnsupportedTLSFingerprint = errors.New("unsupported TLS fingerprint")

type requestHeaderStateKey struct{}

type requestHeaderState struct {
	headers           http.Header
	headerOrder       []string
	pseudoHeaderOrder []string
}

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
	ProtocolVersion int             `json:"protocol_version"`
	SDKVersion      string          `json:"sdk_version"`
	TLSFingerprint  string          `json:"tls_fingerprint,omitempty"`
	TLSSpec         *tlsSpec        `json:"tls_spec,omitempty"`
	Impersonate     string          `json:"impersonate,omitempty"`
	ProxyURL        string          `json:"proxy_url,omitempty"`
	Verify          *bool           `json:"verify,omitempty"`
	RootCAPEM       string          `json:"root_ca_pem,omitempty"`
	ClientCertPEM   string          `json:"client_cert_pem,omitempty"`
	ClientKeyPEM    string          `json:"client_key_pem,omitempty"`
	HTTPVersion     string          `json:"http_version,omitempty"`
	KeepAlive       *bool           `json:"keep_alive,omitempty"`
	Compression     bool            `json:"compression,omitempty"`
	AllowGetBody    *bool           `json:"allow_get_body,omitempty"`
	Retry           retryConfig     `json:"retry,omitempty"`
	Transport       transportConfig `json:"transport,omitempty"`
	HTTP2           http2Config     `json:"http2,omitempty"`

	tlsFingerprintSet bool
}

type retryConfig struct {
	Count           int    `json:"count,omitempty"`
	Mode            string `json:"mode,omitempty"`
	FixedIntervalMS int64  `json:"fixed_interval_ms,omitempty"`
	BackoffMinMS    int64  `json:"backoff_min_ms,omitempty"`
	BackoffMaxMS    int64  `json:"backoff_max_ms,omitempty"`
	StatusCodes     []int  `json:"status_codes,omitempty"`
}

type transportConfig struct {
	TLSHandshakeTimeoutMS   int64               `json:"tls_handshake_timeout_ms,omitempty"`
	ResponseHeaderTimeoutMS int64               `json:"response_header_timeout_ms,omitempty"`
	ExpectContinueTimeoutMS int64               `json:"expect_continue_timeout_ms,omitempty"`
	IdleConnTimeoutMS       int64               `json:"idle_conn_timeout_ms,omitempty"`
	MaxIdleConns            int                 `json:"max_idle_conns,omitempty"`
	MaxIdleConnsPerHost     int                 `json:"max_idle_conns_per_host,omitempty"`
	MaxConnsPerHost         int                 `json:"max_conns_per_host,omitempty"`
	MaxResponseHeaderBytes  int64               `json:"max_response_header_bytes,omitempty"`
	ReadBufferSize          int                 `json:"read_buffer_size,omitempty"`
	WriteBufferSize         int                 `json:"write_buffer_size,omitempty"`
	ProxyConnectHeaders     map[string][]string `json:"proxy_connect_headers,omitempty"`
}

type http2Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

type priorityParam struct {
	StreamDependency uint32 `json:"stream_dependency"`
	Exclusive        bool   `json:"exclusive"`
	Weight           uint32 `json:"weight"`
}

type priorityFrame struct {
	StreamID uint32        `json:"stream_id"`
	Priority priorityParam `json:"priority"`
}

type http2Config struct {
	Settings                   []http2Setting  `json:"settings,omitempty"`
	ConnectionFlow             *uint32         `json:"connection_flow,omitempty"`
	HeaderPriority             *priorityParam  `json:"header_priority,omitempty"`
	PriorityFrames             []priorityFrame `json:"priority_frames,omitempty"`
	MaxHeaderListSize          *uint32         `json:"max_header_list_size,omitempty"`
	StrictMaxConcurrentStreams bool            `json:"strict_max_concurrent_streams,omitempty"`
	ReadIdleTimeoutMS          int64           `json:"read_idle_timeout_ms,omitempty"`
	PingTimeoutMS              int64           `json:"ping_timeout_ms,omitempty"`
	WriteByteTimeoutMS         int64           `json:"write_byte_timeout_ms,omitempty"`
}

type clientSession struct {
	client      *req.Client
	config      createClientRequest
	closer      io.Closer
	lastUsed    time.Time
	activeCalls int
	mu          sync.Mutex
}

func (s *clientSession) close() {
	if s.closer != nil {
		_ = s.closer.Close()
		return
	}
	s.client.GetClient().CloseIdleConnections()
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

func decodeStrictJSON(data []byte, target any) error {
	if err := rejectJSONNull(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing JSON value")
	}
	return nil
}

func rejectJSONNull(data []byte) error {
	inString := false
	escaped := false
	for i, current := range data {
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			continue
		}
		if current == 'n' && len(data)-i >= 4 && bytes.Equal(data[i:i+4], []byte("null")) {
			return errors.New("null is not allowed")
		}
	}
	return nil
}

func (input *createClientRequest) UnmarshalJSON(data []byte) error {
	type wire createClientRequest
	var decoded wire
	if err := decodeStrictJSON(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*input = createClientRequest(decoded)
	_, input.tlsFingerprintSet = fields["tls_fingerprint"]
	return nil
}

func (input *retryConfig) UnmarshalJSON(data []byte) error {
	type wire retryConfig
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *transportConfig) UnmarshalJSON(data []byte) error {
	type wire transportConfig
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *http2Setting) UnmarshalJSON(data []byte) error {
	type wire http2Setting
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *priorityParam) UnmarshalJSON(data []byte) error {
	type wire priorityParam
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *priorityFrame) UnmarshalJSON(data []byte) error {
	type wire priorityFrame
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *http2Config) UnmarshalJSON(data []byte) error {
	type wire http2Config
	return decodeStrictJSON(data, (*wire)(input))
}

func (input *requestOptions) UnmarshalJSON(data []byte) error {
	type wire requestOptions
	return decodeStrictJSON(data, (*wire)(input))
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

func (input *requestEnvelope) UnmarshalJSON(data []byte) error {
	if err := rejectJSONNull(data); err != nil {
		return err
	}
	var wire struct {
		ProtocolVersion int               `json:"protocol_version"`
		Method          string            `json:"method"`
		URL             string            `json:"url"`
		Headers         []json.RawMessage `json:"headers"`
		BodyBase64      string            `json:"body_base64"`
		TimeoutMS       int64             `json:"timeout_ms"`
		Options         requestOptions    `json:"options"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	headers := make([][2]string, len(wire.Headers))
	for i, rawPair := range wire.Headers {
		var pair []string
		if err := json.Unmarshal(rawPair, &pair); err != nil || len(pair) != 2 {
			return fmt.Errorf("header at index %d must contain exactly two strings", i)
		}
		headers[i] = [2]string{pair[0], pair[1]}
	}
	*input = requestEnvelope{
		ProtocolVersion: wire.ProtocolVersion,
		Method:          wire.Method,
		URL:             wire.URL,
		Headers:         headers,
		BodyBase64:      wire.BodyBase64,
		TimeoutMS:       wire.TimeoutMS,
		Options:         wire.Options,
	}
	return nil
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
	Trace           *responseTrace `json:"trace,omitempty"`
	Dump            *string        `json:"dump,omitempty"`
}

type server struct {
	token        string
	instanceID   string
	maxBodyBytes int64
	idleTTL      time.Duration
	clients      map[string]*clientSession
	done         chan struct{}
	closeOnce    sync.Once
	mu           sync.RWMutex
}

func newServer(token string, maxBodyBytes int64, idleTTL time.Duration) *server {
	s := &server{
		token:        token,
		maxBodyBytes: maxBodyBytes,
		idleTTL:      idleTTL,
		clients:      make(map[string]*clientSession),
		done:         make(chan struct{}),
	}
	go s.cleanupLoop()
	return s
}

func (s *server) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		clients := s.clients
		s.clients = make(map[string]*clientSession)
		s.mu.Unlock()
		for _, session := range clients {
			session.close()
		}
	})
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok", ProtocolVersion: protocolVersion, ServerVersion: serverVersion})
	})
	mux.Handle("GET /api/v1/capabilities", s.authenticate(http.HandlerFunc(s.handleCapabilities)))
	mux.Handle("POST /api/v1/clients", s.authenticate(requireJSONContentType(http.HandlerFunc(s.handleCreateClient))))
	mux.Handle("DELETE /api/v1/clients/{clientID}", s.authenticate(http.HandlerFunc(s.handleDeleteClient)))
	mux.Handle("POST /api/v1/clients/{clientID}/requests", s.authenticate(requireJSONContentType(http.HandlerFunc(s.handleRawRequest))))
	if s.instanceID != "" {
		return s.authenticate(mux)
	}
	return mux
}

func requireJSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("Content-Type")
		if value == "" {
			writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{Error: apiError{Code: "UNSUPPORTED_MEDIA_TYPE", Message: "Content-Type must be application/json"}})
			return
		}
		mediaType, _, err := mime.ParseMediaType(value)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: "invalid Content-Type"}})
			return
		}
		if !strings.EqualFold(mediaType, "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{Error: apiError{Code: "UNSUPPORTED_MEDIA_TYPE", Message: "Content-Type must be application/json"}})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.instanceID != "" {
			w.Header().Set(instanceHeader, s.instanceID)
		}
		identityOK := s.instanceID == "" || r.Header.Get(instanceHeader) == s.instanceID
		if identityOK && (s.token == "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.token)) == 1) {
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
		ServerVersion:   serverVersion,
		MaxBodyBytes:    s.maxBodyBytes,
		TLSFingerprints: tlsFingerprints,
	})
}

func (s *server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxClientConfigBytes)
	var input createClientRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		message := "invalid client configuration"
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			message = fmt.Sprintf("client configuration exceeds %d bytes", maxClientConfigBytes)
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: message}})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		message := "invalid client configuration"
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			message = fmt.Sprintf("client configuration exceeds %d bytes", maxClientConfigBytes)
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "INVALID_REQUEST", Message: message}})
		return
	}
	if input.ProtocolVersion != protocolVersion {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "PROTOCOL_MISMATCH", Message: "unsupported protocol version"}})
		return
	}
	if input.SDKVersion != serverVersion {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: "VERSION_MISMATCH", Message: "Python SDK 与 Go 服务端版本不匹配，请执行 pip install --upgrade gohttpx 或从 GitHub Release 下载并升级对应版本的 Go 服务端"}})
		return
	}
	if input.Impersonate == "" {
		input.Impersonate = "none"
	}
	if input.TLSSpec == nil && input.TLSFingerprint == "" && input.Impersonate == "none" && input.HTTPVersion != "http2" {
		input.TLSFingerprint = "android_11_okhttp"
	}
	client, err := buildReqClient(input)
	if err != nil {
		code := "INVALID_REQUEST"
		if errors.Is(err, errUnsupportedTLSFingerprint) {
			code = "UNSUPPORTED_FEATURE"
		}
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: apiError{Code: code, Message: err.Error()}})
		return
	}
	session := &clientSession{client: client, config: input}
	if transport, ok := client.GetClient().Transport.(*quichttp3.Transport); ok {
		session.closer = transport
	}
	clientID, err := newClientID()
	if err != nil {
		session.close()
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{Code: "INTERNAL_ERROR", Message: "failed to create client session"}})
		return
	}
	now := time.Now()
	session.lastUsed = now
	s.mu.Lock()
	s.clients[clientID] = session
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
		session.close()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleRawRequest(w http.ResponseWriter, r *http.Request) {
	requestID, err := newClientID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: apiError{Code: "INTERNAL_ERROR", Message: "failed to create request ID"}})
		return
	}
	writeError := func(httpStatus int, code, message string, retryable bool) {
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
	if validationError != nil {
		writeError(http.StatusBadRequest, validationError.Code, validationError.Message, false)
		return
	}
	if session.config.HTTPVersion == "http3" {
		unsupportedField := ""
		switch {
		case input.Options.ForceChunked:
			unsupportedField = "force_chunked"
		case input.Options.CloseConnection:
			unsupportedField = "close_connection"
		case len(input.Options.HeaderOrder) > 0:
			unsupportedField = "header_order"
		case len(input.Options.PseudoHeaderOrder) > 0:
			unsupportedField = "pseudo_header_order"
		}
		if unsupportedField != "" {
			writeError(http.StatusBadRequest, "INVALID_REQUEST", unsupportedField+" is unsupported with HTTP/3", false)
			return
		}
		if session.config.KeepAlive != nil && !*session.config.KeepAlive {
			defer session.client.GetClient().CloseIdleConnections()
		}
	}

	ctx := r.Context()
	if input.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(input.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	targetReq := session.client.R()
	originalHeaders := make(http.Header)
	automaticOrder := make([]string, 0, len(headers))
	originalHeaderNames := make(map[string]string, len(headers))
	for _, pair := range headers {
		foldedName := strings.ToLower(pair[0])
		name, seen := originalHeaderNames[foldedName]
		if !seen {
			name = pair[0]
			if foldedName == "host" {
				name = "Host"
			}
			originalHeaderNames[foldedName] = name
			automaticOrder = append(automaticOrder, name)
		}
		originalHeaders[name] = append(originalHeaders[name], pair[1])
	}
	if input.Options.CloseConnection {
		originalHeaders.Del("Connection")
	}
	headerOrder := automaticOrder
	if len(input.Options.HeaderOrder) > 0 {
		headerOrder = input.Options.HeaderOrder
	}
	headerState := requestHeaderState{
		headers:           originalHeaders.Clone(),
		headerOrder:       append([]string(nil), headerOrder...),
		pseudoHeaderOrder: append([]string(nil), input.Options.PseudoHeaderOrder...),
	}
	ctx = context.WithValue(ctx, requestHeaderStateKey{}, headerState)
	targetReq.Headers = originalHeaders.Clone()
	targetReq.SetContext(ctx)
	if input.Options.ForceChunked && len(body) > 0 {
		targetReq.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		}
	} else if len(body) > 0 {
		targetReq.SetBodyBytes(body)
	}
	var dump bytes.Buffer
	applyRequestOptions(targetReq, input.Options, &dump)
	targetReq.DisableAutoReadResponse()

	response, err := targetReq.Send(input.Method, input.URL)
	var responseBody []byte
	if err == nil {
		if response.ContentLength > s.maxBodyBytes {
			if response.Body != nil {
				_ = response.Body.Close()
			}
			writeError(http.StatusBadGateway, "UPSTREAM_PROTOCOL_ERROR", "target response body exceeds limit", false)
			return
		}
		if response.Body != nil {
			readLimit := s.maxBodyBytes + 1
			if s.maxBodyBytes == math.MaxInt64 {
				readLimit = math.MaxInt64
			}
			body := response.Body
			response.Body = struct {
				io.Reader
				io.Closer
			}{Reader: io.LimitReader(body, readLimit), Closer: body}
		}
		responseBody, err = response.ToBytes()
	}
	if err != nil {
		if response != nil && response.Response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
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
	if int64(len(responseBody)) > s.maxBodyBytes {
		writeError(http.StatusBadGateway, "UPSTREAM_PROTOCOL_ERROR", "target response body exceeds limit", false)
		return
	}
	if input.Options.Dump && dump.Len() == 0 {
		_, _ = fmt.Fprintf(&dump, "%s %s %s\r\n", input.Method, input.URL, response.Proto)
		for _, pair := range headers {
			_, _ = fmt.Fprintf(&dump, "%s: %s\r\n", pair[0], pair[1])
		}
		_, _ = dump.WriteString("\r\n")
		_, _ = dump.Write(body)
		_, _ = fmt.Fprintf(&dump, "\r\n%s %s\r\n", response.Proto, response.Status)
		for name, values := range response.Header {
			for _, value := range values {
				_, _ = fmt.Fprintf(&dump, "%s: %s\r\n", name, value)
			}
		}
		_, _ = dump.WriteString("\r\n")
		_, _ = dump.Write(responseBody)
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
	var responseDump *string
	if input.Options.Dump {
		value := dump.String()
		responseDump = &value
	}
	writeJSON(w, http.StatusOK, responseEnvelope{
		ProtocolVersion: protocolVersion,
		RequestID:       requestID,
		StatusCode:      response.StatusCode,
		ReasonPhrase:    reasonPhrase,
		Headers:         responseHeaders,
		BodyBase64:      base64.StdEncoding.EncodeToString(responseBody),
		URL:             responseURL,
		HTTPVersion:     response.Proto,
		ElapsedMS:       float64(response.TotalTime()) / float64(time.Millisecond),
		Trace:           trace,
		Dump:            responseDump,
	})
}

func applyRequestOptions(targetReq *req.Request, options requestOptions, dump *bytes.Buffer) {
	if options.Trace {
		targetReq.EnableTrace()
	}
	if options.ForceChunked {
		targetReq.EnableForceChunkedEncoding()
	}
	if options.CloseConnection {
		targetReq.EnableCloseConnection()
	}
	if options.RetryCount != nil {
		targetReq.SetRetryCount(*options.RetryCount)
	}
	if options.Dump {
		targetReq.EnableDumpTo(dump)
	}
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
	if len(input.Method) > 64 || !isHTTPToken(input.Method) {
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
		if !ok || len(name) > 256 || !isHTTPToken(name) {
			return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "invalid header name"}
		}
		value, ok := latin1ToBytes(pair[1])
		if !ok || len(value) > 16384 || !isHTTPHeaderValue(value) {
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
	if input.Options.RetryCount != nil && (*input.Options.RetryCount < 0 || *input.Options.RetryCount > 10) {
		return input, nil, nil, &apiError{Code: "INVALID_REQUEST", Message: "retry_count must be between 0 and 10"}
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

func isHTTPToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		char := value[i]
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(char)) {
			continue
		}
		return false
	}
	return true
}

func isHTTPHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '\t' && (value[i] < ' ' || value[i] == 0x7f) {
			return false
		}
	}
	return true
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
	if err := validateClientConfig(input); err != nil {
		return nil, err
	}
	client := req.C().
		DisableCompression().
		DisableAutoDecompress().
		DisableAutoDecode()
	client.GetClient().Jar = nil
	client.GetClient().CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	client.GetClient().Timeout = 0
	client.WrapRoundTripFunc(func(next req.RoundTripper) req.RoundTripFunc {
		return func(request *req.Request) (*req.Response, error) {
			if state, ok := request.Context().Value(requestHeaderStateKey{}).(requestHeaderState); ok {
				request.Headers = state.headers.Clone()
				if _, canonicalUserAgent := request.Headers["User-Agent"]; !canonicalUserAgent {
					request.Headers["User-Agent"] = nil
				}
				if len(state.headerOrder) > 0 {
					request.Headers[req.HeaderOderKey] = append([]string(nil), state.headerOrder...)
				}
				if len(state.pseudoHeaderOrder) > 0 {
					request.Headers[req.PseudoHeaderOderKey] = append([]string(nil), state.pseudoHeaderOrder...)
				}
			}
			return next.RoundTrip(request)
		}
	})

	verify := true
	if input.Verify != nil {
		verify = *input.Verify
	}
	client.GetTLSClientConfig().InsecureSkipVerify = !verify
	if input.RootCAPEM != "" {
		client.SetRootCertFromString(input.RootCAPEM)
	}
	if input.ClientCertPEM != "" {
		certificate, _ := tls.X509KeyPair([]byte(input.ClientCertPEM), []byte(input.ClientKeyPEM))
		client.SetCerts(certificate)
	}

	if input.TLSSpec != nil {
		setUTLSHandshake(client, utls.HelloCustom, input.TLSSpec)
	} else if input.HTTPVersion != "http3" {
		var clientHelloID utls.ClientHelloID
		switch input.Impersonate {
		case "chrome":
			client.ImpersonateChrome()
			clientHelloID = utls.HelloChrome_Auto
		case "firefox":
			client.ImpersonateFirefox()
			clientHelloID = utls.HelloFirefox_Auto
		case "safari":
			client.ImpersonateSafari()
			clientHelloID = utls.HelloSafari_Auto
		default:
			if input.HTTPVersion != "http2" {
				fingerprint := input.TLSFingerprint
				if fingerprint == "" {
					fingerprint = "android_11_okhttp"
				}
				clientHelloID = fingerprints[fingerprint]
				client.SetTLSFingerprint(clientHelloID)
			}
		}
		if input.ClientCertPEM != "" && input.HTTPVersion != "http2" {
			setUTLSHandshake(client, clientHelloID, nil)
		}
	}
	if input.ProxyURL != "" {
		client.SetProxyURL(input.ProxyURL)
	}
	switch input.HTTPVersion {
	case "http1":
		client.EnableForceHTTP1()
	case "http2":
		client.EnableForceHTTP2()
	case "h2c":
		client.EnableH2C().EnableForceHTTP2()
	case "", "auto":
		client.DisableForceHttpVersion()
	}
	if input.HTTPVersion != "http3" {
		if input.KeepAlive != nil && !*input.KeepAlive {
			client.DisableKeepAlives()
		} else {
			client.EnableKeepAlives()
		}
		if input.Compression {
			client.EnableCompression()
		}
	}
	if input.AllowGetBody != nil && !*input.AllowGetBody {
		client.DisableAllowGetMethodPayload()
	} else {
		client.EnableAllowGetMethodPayload()
	}

	if input.HTTPVersion == "http3" {
		client.GetClient().Transport = &quichttp3.Transport{
			TLSClientConfig: client.GetTLSClientConfig().Clone(),
			QUICConfig: &quic.Config{
				HandshakeIdleTimeout: time.Duration(input.Transport.TLSHandshakeTimeoutMS) * time.Millisecond,
				MaxIdleTimeout:       time.Duration(input.Transport.IdleConnTimeoutMS) * time.Millisecond,
			},
			MaxResponseHeaderBytes: int(input.Transport.MaxResponseHeaderBytes),
			DisableCompression:     !input.Compression,
		}
	} else {
		transport := client.GetTransport()
		if input.Transport.TLSHandshakeTimeoutMS != 0 {
			transport.SetTLSHandshakeTimeout(time.Duration(input.Transport.TLSHandshakeTimeoutMS) * time.Millisecond)
		}
		if input.Transport.ResponseHeaderTimeoutMS != 0 {
			transport.SetResponseHeaderTimeout(time.Duration(input.Transport.ResponseHeaderTimeoutMS) * time.Millisecond)
		}
		if input.Transport.ExpectContinueTimeoutMS != 0 {
			transport.SetExpectContinueTimeout(time.Duration(input.Transport.ExpectContinueTimeoutMS) * time.Millisecond)
		}
		if input.Transport.IdleConnTimeoutMS != 0 {
			transport.SetIdleConnTimeout(time.Duration(input.Transport.IdleConnTimeoutMS) * time.Millisecond)
		}
		if input.Transport.MaxIdleConns != 0 {
			transport.SetMaxIdleConns(input.Transport.MaxIdleConns)
		}
		if input.Transport.MaxIdleConnsPerHost != 0 {
			transport.MaxIdleConnsPerHost = input.Transport.MaxIdleConnsPerHost
		}
		if input.Transport.MaxConnsPerHost != 0 {
			transport.SetMaxConnsPerHost(input.Transport.MaxConnsPerHost)
		}
		if input.Transport.MaxResponseHeaderBytes != 0 {
			transport.SetMaxResponseHeaderBytes(input.Transport.MaxResponseHeaderBytes)
		}
		if input.Transport.ReadBufferSize != 0 {
			transport.SetReadBufferSize(input.Transport.ReadBufferSize)
		}
		if input.Transport.WriteBufferSize != 0 {
			transport.SetWriteBufferSize(input.Transport.WriteBufferSize)
		}
		if input.Transport.ProxyConnectHeaders != nil {
			transport.SetProxyConnectHeader(http.Header(input.Transport.ProxyConnectHeaders))
		}

		if len(input.HTTP2.Settings) > 0 {
			settings := make([]http2.Setting, len(input.HTTP2.Settings))
			for i, setting := range input.HTTP2.Settings {
				settings[i] = http2.Setting{ID: http2.SettingID(setting.ID), Val: setting.Value}
			}
			client.SetHTTP2SettingsFrame(settings...)
		}
		if input.HTTP2.ConnectionFlow != nil && *input.HTTP2.ConnectionFlow != 0 {
			client.SetHTTP2ConnectionFlow(*input.HTTP2.ConnectionFlow)
		}
		if input.HTTP2.HeaderPriority != nil {
			client.SetHTTP2HeaderPriority(toHTTP2Priority(*input.HTTP2.HeaderPriority))
		}
		if len(input.HTTP2.PriorityFrames) > 0 {
			frames := make([]http2.PriorityFrame, len(input.HTTP2.PriorityFrames))
			for i, frame := range input.HTTP2.PriorityFrames {
				frames[i] = http2.PriorityFrame{StreamID: frame.StreamID, PriorityParam: toHTTP2Priority(frame.Priority)}
			}
			client.SetHTTP2PriorityFrames(frames...)
		}
		if input.HTTP2.MaxHeaderListSize != nil && *input.HTTP2.MaxHeaderListSize != 0 {
			client.SetHTTP2MaxHeaderListSize(*input.HTTP2.MaxHeaderListSize)
		}
		if input.HTTP2.StrictMaxConcurrentStreams {
			client.SetHTTP2StrictMaxConcurrentStreams(true)
		}
		if input.HTTP2.ReadIdleTimeoutMS != 0 {
			client.SetHTTP2ReadIdleTimeout(time.Duration(input.HTTP2.ReadIdleTimeoutMS) * time.Millisecond)
		}
		if input.HTTP2.PingTimeoutMS != 0 {
			client.SetHTTP2PingTimeout(time.Duration(input.HTTP2.PingTimeoutMS) * time.Millisecond)
		}
		if input.HTTP2.WriteByteTimeoutMS != 0 {
			client.SetHTTP2WriteByteTimeout(time.Duration(input.HTTP2.WriteByteTimeoutMS) * time.Millisecond)
		}
	}

	if input.Retry.Count > 0 {
		client.SetCommonRetryCount(input.Retry.Count)
		switch input.Retry.Mode {
		case retryFixed:
			client.SetCommonRetryFixedInterval(time.Duration(input.Retry.FixedIntervalMS) * time.Millisecond)
		case retryBackoff:
			client.SetCommonRetryBackoffInterval(time.Duration(input.Retry.BackoffMinMS)*time.Millisecond, time.Duration(input.Retry.BackoffMaxMS)*time.Millisecond)
		}
		if len(input.Retry.StatusCodes) > 0 {
			statusCodes := make(map[int]struct{}, len(input.Retry.StatusCodes))
			for _, statusCode := range input.Retry.StatusCodes {
				statusCodes[statusCode] = struct{}{}
			}
			client.SetCommonRetryCondition(func(response *req.Response, err error) bool {
				if err != nil {
					return true
				}
				_, ok := statusCodes[response.StatusCode]
				return ok
			})
		}
	}
	return client, nil
}

type utlsConn struct {
	*utls.UConn
}

func (conn *utlsConn) ConnectionState() tls.ConnectionState {
	state := conn.Conn.ConnectionState()
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            state.PeerCertificates,
		VerifiedChains:              state.VerifiedChains,
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func setUTLSHandshake(client *req.Client, clientHelloID utls.ClientHelloID, custom *tlsSpec) {
	// req 的 Spec 接口复用指针且不携带客户端证书；这里同时保留 mTLS 和每连接独立配置。
	client.SetTLSHandshake(func(ctx context.Context, addr string, plainConn net.Conn) (net.Conn, *tls.ConnectionState, error) {
		tlsConfig := client.GetTLSClientConfig()
		serverName := tlsConfig.ServerName
		if serverName == "" {
			serverName = addr
			if host, _, err := net.SplitHostPort(addr); err == nil {
				serverName = host
			}
		}
		certificates := make([]utls.Certificate, len(tlsConfig.Certificates))
		for i, certificate := range tlsConfig.Certificates {
			var signatureAlgorithms []utls.SignatureScheme
			if len(certificate.SupportedSignatureAlgorithms) > 0 {
				signatureAlgorithms = make([]utls.SignatureScheme, len(certificate.SupportedSignatureAlgorithms))
				for j, algorithm := range certificate.SupportedSignatureAlgorithms {
					signatureAlgorithms[j] = utls.SignatureScheme(algorithm)
				}
			}
			certificates[i] = utls.Certificate{
				Certificate:                  certificate.Certificate,
				PrivateKey:                   certificate.PrivateKey,
				SupportedSignatureAlgorithms: signatureAlgorithms,
				OCSPStaple:                   certificate.OCSPStaple,
				SignedCertificateTimestamps:  certificate.SignedCertificateTimestamps,
				Leaf:                         certificate.Leaf,
			}
		}
		config := &utls.Config{
			Rand:                        tlsConfig.Rand,
			Time:                        tlsConfig.Time,
			Certificates:                certificates,
			RootCAs:                     tlsConfig.RootCAs,
			ServerName:                  serverName,
			InsecureSkipVerify:          tlsConfig.InsecureSkipVerify,
			NextProtos:                  append([]string(nil), tlsConfig.NextProtos...),
			CipherSuites:                append([]uint16(nil), tlsConfig.CipherSuites...),
			SessionTicketsDisabled:      tlsConfig.SessionTicketsDisabled,
			MinVersion:                  tlsConfig.MinVersion,
			MaxVersion:                  tlsConfig.MaxVersion,
			DynamicRecordSizingDisabled: tlsConfig.DynamicRecordSizingDisabled,
			KeyLogWriter:                tlsConfig.KeyLogWriter,
			VerifyPeerCertificate:       tlsConfig.VerifyPeerCertificate,
		}
		if len(certificates) > 0 {
			config.GetClientCertificate = func(request *utls.CertificateRequestInfo) (*utls.Certificate, error) {
				if err := request.SupportsCertificate(&certificates[0]); err != nil {
					return nil, fmt.Errorf("configured client certificate is incompatible: %w", err)
				}
				return &certificates[0], nil
			}
		}
		connection := &utlsConn{utls.UClient(plainConn, config, clientHelloID)}
		if custom != nil {
			// 每个连接重新构造扩展及 KeyShare，避免复用前一次握手的可变数据。
			spec, err := custom.clientHelloSpec()
			if err != nil {
				return nil, nil, err
			}
			if err := connection.ApplyPreset(spec); err != nil {
				return nil, nil, err
			}
		}
		if err := connection.HandshakeContext(ctx); err != nil {
			return nil, nil, err
		}
		state := connection.ConnectionState()
		return connection, &state, nil
	})
}

func toHTTP2Priority(input priorityParam) http2.PriorityParam {
	return http2.PriorityParam{StreamDep: input.StreamDependency, Exclusive: input.Exclusive, Weight: uint8(input.Weight)}
}

func validateClientConfig(input createClientRequest) error {
	if input.TLSSpec != nil {
		if input.tlsFingerprintSet || input.TLSFingerprint != "" || input.Impersonate != "" && input.Impersonate != "none" {
			return errors.New("tls_spec, tls_fingerprint and impersonate are mutually exclusive")
		}
		if input.HTTPVersion == "http2" || input.HTTPVersion == "http3" || input.HTTPVersion == "h2c" {
			return errors.New("tls_spec requires auto or http1; forced HTTP/2, HTTP/3 and H2C are unsupported")
		}
		spec, err := input.TLSSpec.clientHelloSpec()
		if err != nil {
			return err
		}
		if input.HTTPVersion == "http1" {
			for _, extension := range spec.Extensions {
				if alpn, ok := extension.(*utls.ALPNExtension); ok {
					for _, protocol := range alpn.AlpnProtocols {
						if protocol != "http/1.1" {
							return errors.New("forced HTTP/1 conflicts with tls_spec ALPN")
						}
					}
				}
			}
		}
	}
	impersonate := input.Impersonate
	if impersonate == "" {
		impersonate = "none"
	}
	if impersonate != "none" && impersonate != "chrome" && impersonate != "firefox" && impersonate != "safari" {
		return fmt.Errorf("invalid impersonate value %q", input.Impersonate)
	}
	if impersonate != "none" && (input.tlsFingerprintSet || input.TLSFingerprint != "") {
		return errors.New("impersonate and TLS fingerprint are mutually exclusive")
	}
	if impersonate == "none" {
		fingerprint := input.TLSFingerprint
		if fingerprint == "" {
			fingerprint = "android_11_okhttp"
		}
		if _, ok := fingerprints[fingerprint]; !ok {
			return fmt.Errorf("%w %q", errUnsupportedTLSFingerprint, fingerprint)
		}
	}
	if input.ProxyURL != "" {
		proxyURL, err := url.Parse(input.ProxyURL)
		if err != nil || proxyURL.Host == "" || proxyURL.Scheme != "http" && proxyURL.Scheme != "https" && proxyURL.Scheme != "socks5" && proxyURL.Scheme != "socks5h" {
			return errors.New("invalid proxy URL")
		}
	}
	if input.RootCAPEM != "" {
		if err := validateRootCAPEM(input.RootCAPEM); err != nil {
			return err
		}
	}
	if (input.ClientCertPEM == "") != (input.ClientKeyPEM == "") {
		return errors.New("client certificate and key must be provided together")
	}
	if input.ClientCertPEM != "" {
		if _, err := tls.X509KeyPair([]byte(input.ClientCertPEM), []byte(input.ClientKeyPEM)); err != nil {
			return errors.New("invalid client certificate or key PEM")
		}
	}
	httpVersion := input.HTTPVersion
	if httpVersion == "" {
		httpVersion = "auto"
	}
	if httpVersion != "auto" && httpVersion != "http1" && httpVersion != "http2" && httpVersion != "http3" && httpVersion != "h2c" {
		return fmt.Errorf("invalid HTTP version %q", input.HTTPVersion)
	}
	if httpVersion == "http2" && (input.tlsFingerprintSet || input.TLSFingerprint != "" || input.Impersonate != "" && input.Impersonate != "none") {
		return errors.New("HTTP/2 cannot be combined with TLS fingerprint or browser impersonate")
	}
	if input.ProxyURL != "" && (httpVersion == "http2" || httpVersion == "http3" || httpVersion == "h2c") {
		return errors.New("proxy_url cannot be combined with forced HTTP/2, HTTP/3, or H2C")
	}
	if httpVersion == "http3" && (input.tlsFingerprintSet || input.TLSFingerprint != "" && input.TLSFingerprint != "android_11_okhttp" || impersonate != "none") {
		return errors.New("HTTP/3 cannot be combined with TLS fingerprint or impersonate")
	}
	if err := validateTransportConfig(input.Transport); err != nil {
		return err
	}
	if err := validateHTTP2Config(input.HTTP2); err != nil {
		return err
	}
	if httpVersion == "http3" {
		if err := validateHTTP3Config(input); err != nil {
			return err
		}
	}
	return validateRetryConfig(input.Retry)
}

func validateHTTP3Config(input createClientRequest) error {
	unsupported := []struct {
		field string
		set   bool
	}{
		{field: "response_header_timeout_ms", set: input.Transport.ResponseHeaderTimeoutMS != 0},
		{field: "expect_continue_timeout_ms", set: input.Transport.ExpectContinueTimeoutMS != 0},
		{field: "max_idle_conns", set: input.Transport.MaxIdleConns != 0},
		{field: "max_idle_conns_per_host", set: input.Transport.MaxIdleConnsPerHost != 0},
		{field: "max_conns_per_host", set: input.Transport.MaxConnsPerHost != 0},
		{field: "read_buffer_size", set: input.Transport.ReadBufferSize != 0},
		{field: "write_buffer_size", set: input.Transport.WriteBufferSize != 0},
		{field: "proxy_connect_headers", set: len(input.Transport.ProxyConnectHeaders) > 0},
		{field: "http2.settings", set: len(input.HTTP2.Settings) > 0},
		{field: "http2.connection_flow", set: input.HTTP2.ConnectionFlow != nil && *input.HTTP2.ConnectionFlow != 0},
		{field: "http2.header_priority", set: input.HTTP2.HeaderPriority != nil},
		{field: "http2.priority_frames", set: len(input.HTTP2.PriorityFrames) > 0},
		{field: "http2.max_header_list_size", set: input.HTTP2.MaxHeaderListSize != nil && *input.HTTP2.MaxHeaderListSize != 0},
		{field: "http2.strict_max_concurrent_streams", set: input.HTTP2.StrictMaxConcurrentStreams},
		{field: "http2.read_idle_timeout_ms", set: input.HTTP2.ReadIdleTimeoutMS != 0},
		{field: "http2.ping_timeout_ms", set: input.HTTP2.PingTimeoutMS != 0},
		{field: "http2.write_byte_timeout_ms", set: input.HTTP2.WriteByteTimeoutMS != 0},
	}
	for _, option := range unsupported {
		if option.set {
			return fmt.Errorf("%s is unsupported with HTTP/3", option.field)
		}
	}
	return nil
}

func validateRootCAPEM(content string) error {
	remaining := bytes.TrimSpace([]byte(content))
	if len(remaining) == 0 {
		return errors.New("invalid root CA PEM")
	}
	for len(remaining) > 0 {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("invalid root CA PEM")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("invalid root CA PEM")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("invalid root CA PEM")
		}
		remaining = bytes.TrimSpace(rest)
	}
	return nil
}

func validateTransportConfig(input transportConfig) error {
	for _, value := range []int64{input.TLSHandshakeTimeoutMS, input.ResponseHeaderTimeoutMS, input.ExpectContinueTimeoutMS, input.IdleConnTimeoutMS} {
		if value < 0 || value > 600000 {
			return errors.New("transport timeout must be between 0 and 600000 milliseconds")
		}
	}
	for _, value := range []int{input.MaxIdleConns, input.MaxIdleConnsPerHost, input.MaxConnsPerHost} {
		if value < 0 || value > 100000 {
			return errors.New("transport connection count must be between 0 and 100000")
		}
	}
	if input.MaxResponseHeaderBytes < 0 || input.MaxResponseHeaderBytes > 16777216 || input.ReadBufferSize < 0 || input.ReadBufferSize > 16777216 || input.WriteBufferSize < 0 || input.WriteBufferSize > 16777216 {
		return errors.New("transport buffer size must be between 0 and 16777216")
	}
	for name, values := range input.ProxyConnectHeaders {
		if !isHTTPToken(name) {
			return errors.New("invalid proxy CONNECT header name")
		}
		for _, value := range values {
			if !isHTTPHeaderValue(value) {
				return errors.New("invalid proxy CONNECT header value")
			}
		}
	}
	return nil
}

func validateHTTP2Config(input http2Config) error {
	seenSettings := make(map[uint16]struct{}, len(input.Settings))
	for _, setting := range input.Settings {
		if setting.ID < 1 || setting.ID > 6 {
			return errors.New("HTTP/2 setting ID must be between 1 and 6")
		}
		if _, ok := seenSettings[setting.ID]; ok {
			return errors.New("duplicate HTTP/2 setting ID")
		}
		seenSettings[setting.ID] = struct{}{}
	}
	if input.HeaderPriority != nil {
		if err := validatePriority(*input.HeaderPriority); err != nil {
			return err
		}
	}
	for _, frame := range input.PriorityFrames {
		if frame.StreamID > math.MaxInt32 {
			return errors.New("HTTP/2 priority stream ID exceeds 31 bits")
		}
		if err := validatePriority(frame.Priority); err != nil {
			return err
		}
	}
	for _, value := range []int64{input.ReadIdleTimeoutMS, input.PingTimeoutMS, input.WriteByteTimeoutMS} {
		if value < 0 || value > 600000 {
			return errors.New("HTTP/2 timeout must be between 0 and 600000 milliseconds")
		}
	}
	return nil
}

func validatePriority(input priorityParam) error {
	if input.StreamDependency > math.MaxInt32 {
		return errors.New("HTTP/2 priority dependency exceeds 31 bits")
	}
	if input.Weight > math.MaxUint8 {
		return errors.New("HTTP/2 priority weight must be between 0 and 255")
	}
	return nil
}

func validateRetryConfig(input retryConfig) error {
	mode := input.Mode
	if mode == "" {
		mode = retryNone
	}
	if input.Count < 0 || input.Count > 10 {
		return errors.New("retry.count must be between 0 and 10")
	}
	if mode != retryNone && mode != retryFixed && mode != retryBackoff {
		return fmt.Errorf("invalid retry.mode %q", input.Mode)
	}
	for _, interval := range []struct {
		field string
		value int64
	}{
		{field: "fixed_interval_ms", value: input.FixedIntervalMS},
		{field: "backoff_min_ms", value: input.BackoffMinMS},
		{field: "backoff_max_ms", value: input.BackoffMaxMS},
	} {
		if interval.value < 0 || interval.value > 600000 {
			return fmt.Errorf("retry.%s must be between 0 and 600000", interval.field)
		}
	}
	if input.Count == 0 && mode != retryNone {
		return errors.New("retry.mode must be none when retry.count is 0")
	}
	if input.Count > 0 && mode == retryNone {
		return errors.New("retry.count requires retry.mode fixed or backoff")
	}
	switch mode {
	case retryNone:
		for _, option := range []struct {
			field string
			set   bool
		}{
			{field: "fixed_interval_ms", set: input.FixedIntervalMS != 0},
			{field: "backoff_min_ms", set: input.BackoffMinMS != 0},
			{field: "backoff_max_ms", set: input.BackoffMaxMS != 0},
			{field: "status_codes", set: len(input.StatusCodes) > 0},
		} {
			if option.set {
				return fmt.Errorf("retry.%s is unused when retry.mode is none", option.field)
			}
		}
	case retryFixed:
		if input.BackoffMinMS != 0 {
			return errors.New("retry.backoff_min_ms is unused when retry.mode is fixed")
		}
		if input.BackoffMaxMS != 0 {
			return errors.New("retry.backoff_max_ms is unused when retry.mode is fixed")
		}
		if input.FixedIntervalMS == 0 {
			return errors.New("retry.fixed_interval_ms must be positive when retry.mode is fixed")
		}
	case retryBackoff:
		if input.FixedIntervalMS != 0 {
			return errors.New("retry.fixed_interval_ms is unused when retry.mode is backoff")
		}
		if input.BackoffMinMS == 0 || input.BackoffMinMS > input.BackoffMaxMS {
			return errors.New("retry.backoff_min_ms and retry.backoff_max_ms must satisfy 0 < min <= max")
		}
	}
	seenStatusCodes := make(map[int]struct{}, len(input.StatusCodes))
	for _, statusCode := range input.StatusCodes {
		if statusCode < 100 || statusCode > 599 {
			return errors.New("retry.status_codes values must be between 100 and 599")
		}
		if _, ok := seenStatusCodes[statusCode]; ok {
			return errors.New("retry.status_codes contains a duplicate value")
		}
		seenStatusCodes[statusCode] = struct{}{}
	}
	return nil
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
	for {
		select {
		case now := <-ticker.C:
			s.cleanupIdleClients(now)
		case <-s.done:
			return
		}
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
		session.close()
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
