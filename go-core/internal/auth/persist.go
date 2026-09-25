package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// LoginAttemptsFile mirrors runtime_state.LOGIN_ATTEMPTS_FILE.
const LoginAttemptsFile = ".webshare_login_attempts.json"

// naiveLayout mirrors datetime.isoformat() for naive datetimes.
const naiveLayout = "2006-01-02T15:04:05.999999999"

type persistedAttempt struct {
	Attempts     int    `json:"attempts"`
	LastAttempt  string `json:"last_attempt,omitempty"`
	BlockedUntil string `json:"blocked_until,omitempty"`
}

// SetPersistence roots the tracker for Save/Load and loads existing state.
// Empty root disables persistence.
func (t *BlockTracker) SetPersistence(root string) {
	t.mu.Lock()
	t.root = root
	t.mu.Unlock()
	if root != "" {
		t.Load()
	}
}

// MarkDirtySave saves immediately when persistence is configured, mirroring
// the synchronous save points (record paths mark dirty; flush points save).
func (t *BlockTracker) saveLocked() {
	if t.root == "" {
		t.dirty = false
		return
	}
	payload := map[string]persistedAttempt{}
	for ip, info := range t.attempts {
		pa := persistedAttempt{Attempts: info.attempts}
		if !info.lastAttempt.IsZero() {
			pa.LastAttempt = info.lastAttempt.Format(naiveLayout)
		}
		if !info.blockedUntil.IsZero() {
			pa.BlockedUntil = info.blockedUntil.Format(naiveLayout)
		}
		payload[ip] = pa
	}
	if err := atomicWriteJSON(filepath.Join(t.root, LoginAttemptsFile), payload); err == nil {
		t.dirty = false
	}
}

// Flush persists when dirty (mirrors save_login_attempts dirty gate).
func (t *BlockTracker) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty {
		return
	}
	t.saveLocked()
}

// Load mirrors load_login_attempts (corrupt → keep current state).
func (t *BlockTracker) Load() {
	if t.root == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(t.root, LoginAttemptsFile))
	if err != nil {
		return
	}
	var payload map[string]persistedAttempt
	if err := json.Unmarshal(data, &payload); err != nil || payload == nil {
		return
	}
	loaded := map[string]*attemptInfo{}
	for ip, pa := range payload {
		info := &attemptInfo{attempts: pa.Attempts}
		if info.attempts < 0 {
			info.attempts = 0
		}
		if pa.LastAttempt != "" {
			if tm, err := time.Parse(naiveLayout, pa.LastAttempt); err == nil {
				info.lastAttempt = tm
			} else if tm, err := time.Parse(time.RFC3339Nano, pa.LastAttempt); err == nil {
				info.lastAttempt = tm
			}
		}
		if pa.BlockedUntil != "" {
			if tm, err := time.Parse(naiveLayout, pa.BlockedUntil); err == nil {
				info.blockedUntil = tm
			} else if tm, err := time.Parse(time.RFC3339Nano, pa.BlockedUntil); err == nil {
				info.blockedUntil = tm
			}
		}
		loaded[ip] = info
	}
	t.mu.Lock()
	t.attempts = loaded
	t.dirty = false
	t.mu.Unlock()
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
