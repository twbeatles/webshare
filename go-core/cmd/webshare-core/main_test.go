package main

import (
	"testing"

	"webshare-core/internal/config"
)

// ISSUE-002: the use_https+Go combination must be refused (the Go core has
// no TLS listener), never served as plain HTTP with Secure cookies.
func TestRequireNoHTTPS(t *testing.T) {
	plain := config.Defaults()
	plain.UseHTTPS = false
	if err := requireNoHTTPS(plain); err != nil {
		t.Fatalf("plain HTTP config rejected: %v", err)
	}
	secure := config.Defaults()
	secure.UseHTTPS = true
	if err := requireNoHTTPS(secure); err == nil {
		t.Fatal("use_https=true accepted, want refusal")
	}
}

// ISSUE-001: CLI flags must override the config display_host/port so the
// launcher-passed bind address (LAN/0.0.0.0) takes effect.
func TestParseFlagsHostPortOverride(t *testing.T) {
	f := parseFlags([]string{"--host", "0.0.0.0", "--port", "5001"})
	if f.host != "0.0.0.0" {
		t.Fatalf("host = %q, want 0.0.0.0", f.host)
	}
	if f.port != 5001 {
		t.Fatalf("port = %d, want 5001", f.port)
	}
	f = parseFlags(nil)
	if f.host != "" || f.port != 0 {
		t.Fatalf("defaults = %+v, want empty override", f)
	}
}
