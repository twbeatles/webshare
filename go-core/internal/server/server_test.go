package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"webshare-core/internal/config"
)

func testServer(t *testing.T, token string) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Folder = t.TempDir()
	return New(cfg, token)
}

func TestHealthz(t *testing.T) {
	s := testServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" || body["backend"] != "go" || body["version"] != Version {
		t.Fatalf("unexpected healthz body: %v", body)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing X-Request-ID")
	}
}

func TestReadyzGatesRuntime(t *testing.T) {
	s := testServer(t, "")
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz before init = %d, want 503", rec.Code)
	}
	s.SetRuntimeInitialized()
	s.listening.Store(true)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz after init = %d, want 200", rec.Code)
	}
}

func TestControlShutdownGuards(t *testing.T) {
	const token = "test-token-123"
	s := testServer(t, token)

	post := func(remoteAddr, given string) int {
		req := httptest.NewRequest(http.MethodPost, "/_control/shutdown", nil)
		req.RemoteAddr = remoteAddr
		if given != "" {
			req.Header.Set("X-Control-Token", given)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}

	if got := post("192.168.1.10:1234", token); got != http.StatusForbidden {
		t.Fatalf("non-loopback = %d, want 403", got)
	}
	if got := post("127.0.0.1:1234", "wrong"); got != http.StatusForbidden {
		t.Fatalf("bad token = %d, want 403", got)
	}
	if got := post("127.0.0.1:1234", ""); got != http.StatusForbidden {
		t.Fatalf("missing token = %d, want 403", got)
	}
	if got := post("127.0.0.1:1234", token); got != http.StatusOK {
		t.Fatalf("valid shutdown = %d, want 200", got)
	}
	select {
	case <-s.shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown signal not raised")
	}
}
