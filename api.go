package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

const protocolVersion = 1

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

type server struct {
	token        string
	maxBodyBytes int64
	idleTTL      time.Duration
}

func newServer(token string, maxBodyBytes int64, idleTTL time.Duration) *server {
	return &server{token: token, maxBodyBytes: maxBodyBytes, idleTTL: idleTTL}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok", ProtocolVersion: protocolVersion, ServerVersion: "1.0.0"})
	})
	mux.Handle("GET /api/v1/capabilities", s.authenticate(http.HandlerFunc(s.handleCapabilities)))
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
	writeJSON(w, http.StatusOK, struct {
		ProtocolVersion int    `json:"protocol_version"`
		ServerVersion   string `json:"server_version"`
		MaxBodyBytes    int64  `json:"max_body_bytes"`
	}{
		ProtocolVersion: protocolVersion,
		ServerVersion:   "1.0.0",
		MaxBodyBytes:    s.maxBodyBytes,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("JSON 响应编码失败: %v", err)
	}
}
