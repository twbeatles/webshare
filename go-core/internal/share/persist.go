package share

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// naiveLayout mirrors datetime.isoformat() for naive datetimes: no zone
// offset, so Python's fromisoformat + naive comparison keep working on
// files written by Go.
const naiveLayout = "2006-01-02T15:04:05.999999999"

func formatNaive(t time.Time) string {
	return t.Format(naiveLayout)
}

// FormatNaive formats a timestamp like naive datetime.isoformat().
func FormatNaive(t time.Time) string { return formatNaive(t) }

func parseNaive(s string) (time.Time, bool) {
	if t, err := time.Parse(naiveLayout, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}

func atomicWriteJSON(path string, payload any) error {
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".webshare_write_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

type persistedLink struct {
	Path          string `json:"path"`
	Expires       string `json:"expires"`
	CreatedBy     string `json:"created_by"`
	IsDir         bool   `json:"is_dir"`
	PasswordHash  string `json:"password_hash"`
	MaxDownloads  int64  `json:"max_downloads"`
	DownloadCount int64  `json:"download_count"`
	CreatedAt     string `json:"created_at"`
}

// SaveLinks mirrors save_share_links: {updated, links:{token:{...}}}.
func (s *Store) SaveLinks() {
	s.mu.Lock()
	links := map[string]persistedLink{}
	for token, link := range s.links {
		pl := persistedLink{
			Path: link.Path, Expires: formatNaive(link.Expires),
			CreatedBy: link.CreatedBy, IsDir: link.IsDir,
			MaxDownloads: link.MaxDownloads, DownloadCount: link.DownloadCount,
			CreatedAt: formatNaive(link.CreatedAt),
		}
		if link.PasswordHash != "" {
			pl.PasswordHash = link.PasswordHash
		}
		links[token] = pl
	}
	s.mu.Unlock()
	payload := map[string]any{
		"updated": formatNaive(s.now()),
		"links":   links,
	}
	_ = atomicWriteJSON(filepath.Join(s.root, LinksFile), payload)
}

// LoadLinks mirrors load_share_links: corrupt entries skipped, expired
// entries dropped.
func (s *Store) LoadLinks() {
	data, err := os.ReadFile(filepath.Join(s.root, LinksFile))
	if err != nil {
		return
	}
	var raw struct {
		Links map[string]json.RawMessage `json:"links"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || raw.Links == nil {
		return
	}
	now := s.now()
	loaded := map[string]*Link{}
	for token, rawLink := range raw.Links {
		var pl persistedLink
		if err := json.Unmarshal(rawLink, &pl); err != nil {
			continue
		}
		expires, ok := parseNaive(pl.Expires)
		if !ok {
			continue
		}
		if !expires.After(now) {
			continue
		}
		createdAt, _ := parseNaive(pl.CreatedAt)
		loaded[token] = &Link{
			Path: pl.Path, Expires: expires, CreatedBy: pl.CreatedBy,
			IsDir: pl.IsDir, PasswordHash: pl.PasswordHash,
			MaxDownloads: pl.MaxDownloads, DownloadCount: pl.DownloadCount,
			CreatedAt: createdAt,
		}
	}
	s.mu.Lock()
	s.links = loaded
	s.mu.Unlock()
}

type persistedAttempt struct {
	Attempts     int    `json:"attempts"`
	LastAttempt  string `json:"last_attempt,omitempty"`
	BlockedUntil string `json:"blocked_until,omitempty"`
}

// saveAttemptsLocked mirrors save_share_password_attempts: keys are
// "ip\ntoken" (must be called with s.mu held).
func (s *Store) saveAttemptsLocked() bool {
	payload := map[string]persistedAttempt{}
	for key, info := range s.attempts {
		pa := persistedAttempt{Attempts: info.Attempts}
		if !info.LastAttempt.IsZero() {
			pa.LastAttempt = formatNaive(info.LastAttempt)
		}
		if !info.BlockedUntil.IsZero() {
			pa.BlockedUntil = formatNaive(info.BlockedUntil)
		}
		payload[key] = pa
	}
	if err := atomicWriteJSON(filepath.Join(s.root, AttemptsFile), payload); err != nil {
		return false
	}
	return true
}

// LoadAttempts mirrors load_share_password_attempts.
func (s *Store) LoadAttempts() {
	data, err := os.ReadFile(filepath.Join(s.root, AttemptsFile))
	if err != nil {
		return
	}
	var payload map[string]persistedAttempt
	if err := json.Unmarshal(data, &payload); err != nil || payload == nil {
		return
	}
	loaded := map[string]*attempt{}
	for key, pa := range payload {
		// Keys without the newline separator are ignored like Python.
		if strings.IndexByte(key, '\n') < 0 {
			continue
		}
		info := &attempt{Attempts: pa.Attempts}
		if info.Attempts < 0 {
			info.Attempts = 0
		}
		if pa.LastAttempt != "" {
			if t, ok := parseNaive(pa.LastAttempt); ok {
				info.LastAttempt = t
			}
		}
		if pa.BlockedUntil != "" {
			if t, ok := parseNaive(pa.BlockedUntil); ok {
				info.BlockedUntil = t
			}
		}
		loaded[key] = info
	}
	s.mu.Lock()
	s.attempts = loaded
	s.mu.Unlock()
}
