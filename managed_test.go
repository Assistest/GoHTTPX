package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagedBootstrapStrictValidation(t *testing.T) {
	valid := managedBootstrap{RuntimeProtocolVersion: 1, InstanceID: strings.Repeat("a", 32), Token: strings.Repeat("b", 64), OwnerPID: 1, SDKVersion: serverVersion}
	data, _ := json.Marshal(valid)
	for _, test := range []struct {
		name, input string
		ok          bool
	}{
		{"valid", string(data) + "\n", true},
		{"duplicate", strings.Replace(string(data), `"owner_pid":1`, `"owner_pid":1,"owner_pid":2`, 1) + "\n", false},
		{"unknown", strings.TrimSuffix(string(data), "}") + `,"extra":1}` + "\n", false},
		{"wrong_version", strings.Replace(string(data), serverVersion, "wrong", 1) + "\n", false},
		{"short_token", strings.Replace(string(data), valid.Token, "short", 1) + "\n", false},
		{"no_newline", string(data), false},
		{"oversized", strings.Repeat("x", 4096) + "\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := readBootstrap(bufio.NewReaderSize(strings.NewReader(test.input), managedMessageLimit))
			if (err == nil) != test.ok {
				t.Fatalf("ok=%v err=%v", test.ok, err)
			}
		})
	}
}

func TestManagedIdentityRejectsBeforeSessionCreation(t *testing.T) {
	s := newServer("secret-a", 1024, time.Hour)
	s.instanceID = "instance-a"
	defer s.Close()
	for _, test := range []struct {
		token, instance string
		want            int
	}{
		{"secret-a", "instance-a", 200},
		{"secret-b", "instance-a", 401},
		{"secret-a", "instance-b", 401},
		{"", "", 401},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		r.Header.Set("Authorization", "Bearer "+test.token)
		r.Header.Set(instanceHeader, test.instance)
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		if w.Code != test.want || w.Header().Get(instanceHeader) != s.instanceID {
			t.Fatalf("status=%d instance=%q", w.Code, w.Header().Get(instanceHeader))
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.routes().ServeHTTP(w, r)
	if w.Code != 401 || len(s.clients) != 0 {
		t.Fatal("wrong instance reached session creation")
	}
}

func TestManagedCLIRejectsExternalConfiguration(t *testing.T) {
	for _, args := range [][]string{{"--managed", "--port", "0"}, {"--managed", "--token", "secret"}, {"--managed", "--insecure-no-auth"}} {
		if _, err := parseCLI(args, "inherited-token"); err == nil {
			t.Fatalf("accepted conflicting arguments %v", args)
		}
	}
	if options, err := parseCLI([]string{"--managed"}, "inherited-token"); err != nil || !options.managed {
		t.Fatalf("managed mode failed: %v", err)
	}
}

func TestManagedReadyAndPipeShutdown(t *testing.T) {
	for _, mode := range []string{"shutdown", "eof", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			input, writer := io.Pipe()
			reader, output := io.Pipe()
			defer input.Close()
			defer writer.Close()
			defer reader.Close()
			options, err := parseCLI([]string{"--managed"}, "")
			if err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				finished <- runManaged(options, input, output)
				_ = output.Close()
			}()
			bootstrap := managedBootstrap{1, strings.Repeat("a", 32), strings.Repeat("b", 64), 1, serverVersion}
			if err := json.NewEncoder(writer).Encode(bootstrap); err != nil {
				t.Fatal(err)
			}
			var ready struct {
				Host       string `json:"host"`
				Port       int    `json:"port"`
				InstanceID string `json:"instance_id"`
			}
			decoded := make(chan error, 1)
			go func() { decoded <- json.NewDecoder(reader).Decode(&ready) }()
			select {
			case err := <-decoded:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ready timed out")
			}
			if ready.Host != "127.0.0.1" || ready.Port <= 0 || ready.InstanceID != bootstrap.InstanceID {
				t.Fatalf("invalid ready: %+v", ready)
			}
			switch mode {
			case "eof":
				_ = writer.Close()
			case "malformed":
				_, _ = writer.Write([]byte("not json\n"))
			default:
				_ = json.NewEncoder(writer).Encode(map[string]any{"runtime_protocol_version": 1, "instance_id": ready.InstanceID, "command": "shutdown"})
			}
			select {
			case err := <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("managed service did not stop")
			}
		})
	}
}
