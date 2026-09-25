package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileGivesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 5000 || cfg.DisplayHost != "0.0.0.0" || cfg.Language != "ko" {
		t.Fatalf("bad defaults: %+v", cfg)
	}
}

func TestLoadOverlaysAndPreservesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webshare_config.json")
	raw := `{"folder": "C:\\data", "port": 8080, "future_key": "keep-me", "secret_key": "s3cr3t"}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Folder != `C:\data` || cfg.Port != 8080 || cfg.SecretKey != "s3cr3t" {
		t.Fatalf("overlay failed: %+v", cfg)
	}
	if cfg.DisplayHost != "0.0.0.0" {
		t.Fatalf("default lost: %+v", cfg)
	}
	// Round-trip must preserve unknown fields for Python rollback compat.
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back["future_key"] != "keep-me" {
		t.Fatalf("unknown field lost: %v", back)
	}
	if int(back["port"].(float64)) != 8080 {
		t.Fatalf("known field lost: %v", back)
	}
}
