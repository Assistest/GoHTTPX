package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

type clientHello struct {
	CipherSuites      []uint16 `json:"cipher_suites"`
	SupportedCurves   []uint16 `json:"curves"`
	SupportedVersions []uint16 `json:"tls_versions"`
	SupportedProtos   []string `json:"alpn"`
}

type target struct {
	mu    sync.RWMutex
	hello clientHello
}

func (t *target) tlsConfig(certificate tls.Certificate, roots *x509.CertPool, requireClientCert bool) *tls.Config {
	config := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1", "h3"},
	}
	if requireClientCert {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = roots
	}
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		t.mu.Lock()
		t.hello = clientHello{
			CipherSuites:      append([]uint16(nil), info.CipherSuites...),
			SupportedCurves:   curveIDs(info.SupportedCurves),
			SupportedVersions: append([]uint16(nil), info.SupportedVersions...),
			SupportedProtos:   append([]string(nil), info.SupportedProtos...),
		}
		t.mu.Unlock()
		clone := config.Clone()
		clone.GetConfigForClient = nil
		return clone, nil
	}
	return config
}

func curveIDs(curves []tls.CurveID) []uint16 {
	values := make([]uint16, len(curves))
	for i, curve := range curves {
		values[i] = uint16(curve)
	}
	return values
}

func (t *target) observe(w http.ResponseWriter, r *http.Request) {
	bodyLength, _ := io.Copy(io.Discard, r.Body)
	t.mu.RLock()
	hello := t.hello
	t.mu.RUnlock()
	payload := map[string]any{
		"method":            r.Method,
		"headers":           r.Header,
		"body_length":       bodyLength,
		"protocol":          r.Proto,
		"tls_version":       uint16(0),
		"cipher_suite":      uint16(0),
		"cipher_suites":     hello.CipherSuites,
		"curves":            hello.SupportedCurves,
		"alpn":              hello.SupportedProtos,
		"tls_versions":      hello.SupportedVersions,
		"peer_cert_present": false,
	}
	if r.TLS != nil {
		payload["tls_version"] = r.TLS.Version
		payload["cipher_suite"] = r.TLS.CipherSuite
		payload["peer_cert_present"] = len(r.TLS.PeerCertificates) > 0
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func serve(server *http.Server, listener net.Listener) {
	go func() {
		if err := server.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
}

func main() {
	var httpPort, httpsPort, h2cPort, http3Port, mtlsPort int
	var certPath, keyPath, caPath string
	flag.IntVar(&httpPort, "http-port", 0, "HTTP/1 loopback port")
	flag.IntVar(&httpsPort, "https-port", 0, "HTTPS HTTP/2 loopback port")
	flag.IntVar(&h2cPort, "h2c-port", 0, "h2c loopback port")
	flag.IntVar(&http3Port, "http3-port", 0, "HTTP/3 loopback port")
	flag.IntVar(&mtlsPort, "mtls-port", 0, "mTLS loopback port")
	flag.StringVar(&certPath, "server-cert", "", "server certificate")
	flag.StringVar(&keyPath, "server-key", "", "server private key")
	flag.StringVar(&caPath, "ca-cert", "", "CA certificate")
	flag.Parse()
	if httpPort < 1 || httpsPort < 1 || h2cPort < 1 || http3Port < 1 || mtlsPort < 1 || certPath == "" || keyPath == "" || caPath == "" {
		fmt.Fprintln(os.Stderr, "all ports and certificate paths are required")
		os.Exit(2)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "invalid CA certificate")
		os.Exit(2)
	}
	target := &target{}
	handler := http.HandlerFunc(target.observe)
	listen := func(port int) net.Listener {
		listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		return listener
	}
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go httpServer.Serve(listen(httpPort))
	h2cServer := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{}), ReadHeaderTimeout: 5 * time.Second}
	go h2cServer.Serve(listen(h2cPort))
	httpsServer := &http.Server{Handler: handler, TLSConfig: target.tlsConfig(certificate, roots, false), ReadHeaderTimeout: 5 * time.Second}
	if err := http2.ConfigureServer(httpsServer, &http2.Server{}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	serve(httpsServer, listen(httpsPort))
	mtlsServer := &http.Server{Handler: handler, TLSConfig: target.tlsConfig(certificate, roots, true), ReadHeaderTimeout: 5 * time.Second}
	serve(mtlsServer, listen(mtlsPort))
	h3Server := &http3.Server{Addr: net.JoinHostPort("127.0.0.1", fmt.Sprint(http3Port)), Handler: handler, TLSConfig: target.tlsConfig(certificate, roots, false)}
	go func() {
		if err := h3Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	<-interrupt
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	_ = h2cServer.Shutdown(ctx)
	_ = httpsServer.Shutdown(ctx)
	_ = mtlsServer.Shutdown(ctx)
	_ = h3Server.Close()
}
