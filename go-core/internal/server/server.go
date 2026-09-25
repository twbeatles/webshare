// Package server implements the Phase 1 Go HTTP skeleton: health/readiness,
// a loopback+token guarded control endpoint, and safe server defaults.
//
// No user file routes are served yet (Milestone A). Sensitive values
// (control token, secret key, passwords) are never logged or returned.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"webshare-core/pkg/api"

	"webshare-core/internal/config"
)

// Version is the skeleton version reported by /healthz and `version`.
const Version = "0.1.0"

// Server holds listener readiness state for /readyz.
type Server struct {
	cfg       config.Config
	control   string // WEBSHARE_CONTROL_TOKEN; empty disables control endpoint
	mux       *http.ServeMux
	http      *http.Server
	ready     atomic.Bool
	listening atomic.Bool
	shutdown  chan struct{}
}

// New builds the router. Only skeleton endpoints are registered.
func New(cfg config.Config, controlToken string) *Server {
	s := &Server{cfg: cfg, control: controlToken, shutdown: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/_control/shutdown", s.handleControlShutdown)
	s.mux = mux
	s.http = &http.Server{
		Handler:           s.withMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// NOTE: no short global WriteTimeout — large downloads/uploads
		// need endpoint-scoped policies (Phase 7+).
		MaxHeaderBytes: 1 << 20, // 1 MiB
	}
	return s
}

// SetRuntimeInitialized marks runtime init done (readiness gate).
func (s *Server) SetRuntimeInitialized() { s.ready.Store(true) }

// RegisterUserRoutes mounts Milestone C+ user routes on the same mux
// (covered by the request-ID/recovery/logging chain).
func (s *Server) RegisterUserRoutes(register func(mux *http.ServeMux)) {
	register(s.mux)
}

// Handler returns the full middleware chain (request ID, recovery, logging).
func (s *Server) Handler() http.Handler { return s.http.Handler }

// Serve binds addr and serves until ctx is cancelled or control shutdown.
func (s *Server) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listening.Store(true)
	defer s.listening.Store(false)
	go func() {
		select {
		case <-ctx.Done():
		case <-s.shutdown:
		}
		shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.http.Shutdown(shCtx)
	}()
	err = s.http.Serve(ln)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"backend": "go",
		"version": Version,
	})
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() || !s.listening.Load() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not-ready",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleControlShutdown implements POST /_control/shutdown guarded by
// loopback-only + constant-time control token comparison (Phase 2-1).
// The token is never logged.
func (s *Server) handleControlShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody(r, "METHOD_NOT_ALLOWED", "method not allowed"))
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if !ip.IsLoopback() {
		writeJSON(w, http.StatusForbidden, errorBody(r, "FORBIDDEN", "forbidden"))
		return
	}
	if s.control == "" {
		writeJSON(w, http.StatusForbidden, errorBody(r, "FORBIDDEN", "forbidden"))
		return
	}
	given := r.Header.Get("X-Control-Token")
	if subtle.ConstantTimeCompare([]byte(given), []byte(s.control)) != 1 {
		writeJSON(w, http.StatusForbidden, errorBody(r, "FORBIDDEN", "forbidden"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	// Delay the shutdown signal so the 200 response is flushed before
	// the listener starts draining.
	go func() {
		time.Sleep(300 * time.Millisecond)
		select {
		case <-s.shutdown:
		default:
			close(s.shutdown)
		}
	}()
}

// errorBody matches the Python JSON error contract shape.
func errorBody(r *http.Request, code, message string) map[string]any {
	return api.Normalize(map[string]any{"error": message, "code": code}, statusForCode(code), api.RequestID(r))
}

func statusForCode(code string) int {
	for status, c := range api.CodeByStatus {
		if c == code {
			return status
		}
	}
	return 500
}

// statusRecorder captures the response status for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// withMiddleware adds request ID, recovery (no stack leak), and logging
// without sensitive values.
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		r = r.WithContext(context.WithValue(r.Context(), api.RequestIDKey{}, id))
		w.Header().Set("X-Request-ID", id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if p := recover(); p != nil {
				log.Printf("panic request_id=%s route=%s", id, r.URL.Path)
				rec.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(rec).Encode(
					map[string]any{
						"success": false, "error": "internal error",
						"code": "INTERNAL_ERROR", "message": "internal error",
						"request_id": id,
					})
				return
			}
			log.Printf("request_id=%s method=%s route=%s status=%d latency=%s",
				id, r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(rec, r)
	})
}

// newRequestID mirrors api_request_id: uuid4 hex truncated to 16 chars.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")[:16]
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant
	const hexd = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0xf]
	}
	return string(out[:16])
}
