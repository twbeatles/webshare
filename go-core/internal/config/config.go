// Package config reads the existing Python ConfigManager JSON schema as-is.
//
// Rule (migration plan Phase 3): Go MUST NOT invent a new config schema.
// Unknown fields are preserved on write so a Python rollback reads the
// same file. Writes use temp file + atomic rename.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Config mirrors webshare_app/core/config/manager.py ConfigManager defaults.
// Pointer-free plain struct: every field is optional on load; missing keys
// fall back to Defaults().
type Config struct {
	Folder                string   `json:"folder"`
	Port                  int      `json:"port"`
	AdminPw               string   `json:"admin_pw"`
	GuestPw               string   `json:"guest_pw"`
	AllowGuestUpload      bool     `json:"allow_guest_upload"`
	DisplayHost           string   `json:"display_host"`
	UseHTTPS              bool     `json:"use_https"`
	SessionTimeout        int      `json:"session_timeout"`
	EnableNotifications   bool     `json:"enable_notifications"`
	EnableVersioning      bool     `json:"enable_versioning"`
	MinimizeToTray        bool     `json:"minimize_to_tray"`
	Language              string   `json:"language"`
	IPWhitelist           []string `json:"ip_whitelist"`
	DailyDownloadLimit    int      `json:"daily_download_limit"`
	DailyBandwidthLimitMB int      `json:"daily_bandwidth_limit_mb"`
	DiskWarningThreshold  int      `json:"disk_warning_threshold"`
	TrashAutoDeleteDays   int      `json:"trash_auto_delete_days"`
	CloseToTray           bool     `json:"close_to_tray"`
	Autostart             bool     `json:"autostart"`
	TrustedProxies        []string `json:"trusted_proxies"`
	TrustedHops           int      `json:"trusted_hops"`
	WebDAVAllowInsecure   bool     `json:"webdav_allow_insecure"`
	SecretKey             string   `json:"secret_key"`

	// raw preserves unknown/extra fields for round-trip preservation.
	raw map[string]any
}

// Defaults matches ConfigManager.__init__ defaults (folder resolved by caller).
func Defaults() Config {
	return Config{
		Port:                 5000,
		DisplayHost:          "0.0.0.0",
		SessionTimeout:       60,
		EnableNotifications:  true,
		EnableVersioning:     true,
		MinimizeToTray:       true,
		Language:             "ko",
		IPWhitelist:          []string{},
		DiskWarningThreshold: 90,
		TrashAutoDeleteDays:  30,
		CloseToTray:          true,
		TrustedProxies:       []string{},
		TrustedHops:          1,
	}
}

// Load reads path if it exists (missing file -> Defaults, nil error) and
// overlays stored keys on top of Defaults. Unknown keys are kept for Save.
func Load(path string) (Config, error) {
	cfg := Defaults()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return cfg, err
	}
	// Re-marshal known shape: decode into struct for typed fields.
	var typed Config
	if err := json.Unmarshal(data, &typed); err != nil {
		return cfg, err
	}
	base, _ := json.Marshal(typed)
	_ = base
	cfg = typed
	if cfg.Port == 0 {
		cfg.Port = 5000
	}
	if cfg.DisplayHost == "" {
		cfg.DisplayHost = "0.0.0.0"
	}
	cfg.raw = raw
	return cfg, nil
}

// SecretKeyFileName mirrors app_paths.SECRET_KEY_FILENAME.
const SecretKeyFileName = "secret_key"

// AppConfigDir mirrors get_app_config_dir (WEBSHARE_CONFIG_DIR override,
// Windows APPDATA, otherwise XDG config).
func AppConfigDir() string {
	if override := os.Getenv("WEBSHARE_CONFIG_DIR"); override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		if base := os.Getenv("APPDATA"); base != "" {
			return filepath.Join(base, "WebSharePro")
		}
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, "AppData", "Roaming", "WebSharePro")
		}
		return filepath.Join(".", "WebSharePro")
	}
	if base := os.Getenv("XDG_CONFIG_HOME"); base != "" {
		return filepath.Join(base, "websharepro")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".config", "websharepro")
	}
	return filepath.Join(".", "websharepro")
}

// GetOrCreateSecretKey mirrors app_paths.get_or_create_secret_key.
func GetOrCreateSecretKey() (string, error) {
	path := filepath.Join(AppConfigDir(), SecretKeyFileName)
	if data, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(data)); key != "" {
			return key, nil
		}
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	key := hex.EncodeToString(b[:])
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".webshare_secret_*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(key); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return key, nil
}

// EnsureSecretKey mirrors ensure_config_secret_key: config value wins,
// otherwise the persisted secret file, generating when needed.
func EnsureSecretKey(cfg *Config) error {
	if strings.TrimSpace(cfg.SecretKey) != "" {
		return nil
	}
	key, err := GetOrCreateSecretKey()
	if err != nil {
		return err
	}
	cfg.SecretKey = key
	return nil
}

// Save writes cfg atomically (temp file in target dir + rename) while
// preserving unknown fields present at Load time.
func Save(path string, cfg Config) error {
	known, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	merged := map[string]any{}
	if err := json.Unmarshal(known, &merged); err != nil {
		return err
	}
	// secret_key empty means "not set": keep as-is for Python compat.
	for k, v := range cfg.raw {
		if _, ok := merged[k]; !ok {
			merged[k] = v
		}
	}
	out, err := json.MarshalIndent(merged, "", "    ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, ".webshare_write_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
