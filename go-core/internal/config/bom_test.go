package config

import (
	"os"
	"path/filepath"
	"testing"
)

// Windows editors (Notepad, PowerShell Set-Content -Encoding utf8) write a
// UTF-8 BOM, which encoding/json rejects. A valid user config with a BOM
// must load instead of killing the server at startup (ISSUE-006).
func TestLoadAcceptsUTF8BOM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webshare_config.json")
	raw := "\xef\xbb\xbf" + `{"folder": "C:\\data", "port": 8080}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("BOM config rejected: %v", err)
	}
	if cfg.Folder != `C:\data` || cfg.Port != 8080 {
		t.Fatalf("overlay failed: %+v", cfg)
	}
}
