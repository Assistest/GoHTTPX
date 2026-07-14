package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/imroc/req/v3"
	utls "github.com/refraction-networking/utls"
)

func TestReqTLSHTTP2Probe(t *testing.T) {
	endpoint, caPath := os.Getenv("GOHTTPX_PROBE_ENDPOINT"), os.Getenv("GOHTTPX_PROBE_CA")
	if endpoint == "" || caPath == "" {
		t.Fatal("GOHTTPX_PROBE_ENDPOINT and GOHTTPX_PROBE_CA are required")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name          string
		android       bool
		expectedError string
	}{
		{name: "default TLS"},
		{name: "force HTTP2"},
		{name: "android force HTTP2", android: true, expectedError: `unexpected ALPN protocol ""; want "h2"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := req.C().SetRootCertFromString(string(caPEM))
			if test.name != "default TLS" {
				client.EnableForceHTTP2()
			}
			if test.android {
				client.SetTLSFingerprint(utls.HelloAndroid_11_OkHttp)
			}
			response, err := client.R().Get(endpoint + "/observe")
			if err != nil {
				t.Logf("error chain: %s", errorChain(err))
				if test.expectedError == "" || !strings.Contains(err.Error(), test.expectedError) {
					t.Fatal(err)
				}
				return
			}
			if test.expectedError != "" {
				t.Fatalf("expected %q, got protocol %s", test.expectedError, response.Proto)
			}
			if response.Proto != "HTTP/2.0" {
				t.Fatalf("protocol = %s", response.Proto)
			}
		})
	}
}

func errorChain(err error) string {
	var messages []string
	for err != nil {
		messages = append(messages, err.Error())
		err = errors.Unwrap(err)
	}
	return strings.Join(messages, " -> ")
}
