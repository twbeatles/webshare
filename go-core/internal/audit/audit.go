// Package audit ports features/audit_log.py: append-only audit entries,
// in-memory cap, and atomic persistence to .webshare_audit.json.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// isoTimestamp mirrors datetime.now().isoformat(): microseconds always
// 6 digits when nonzero, omitted when zero.
func isoTimestamp(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

// LogFile is the audit persistence filename inside the shared folder.
const LogFile = ".webshare_audit.json"

// MaxEntries mirrors MAX_AUDIT_LOG (0 or negative = unlimited, legacy).
const MaxEntries = 10000

// Entry mirrors one log_audit dict.
type Entry struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	IP        string `json:"ip"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Details   string `json:"details"`
	Result    string `json:"result"`
}

// Log is the audit store.
type Log struct {
	mu      sync.Mutex
	root    string
	entries []Entry
	now     func() time.Time
}

// NewLog builds a store rooted at the shared folder.
func NewLog(root string) *Log {
	return &Log{root: root, now: time.Now}
}

// Add mirrors log_audit (thread-safe append with cap).
func (l *Log) Add(user, action, target, details, result, ip string) {
	if user == "" {
		user = "anonymous"
	}
	if ip == "" {
		ip = "unknown"
	}
	if result == "" {
		result = "success"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, Entry{
		Timestamp: isoTimestamp(l.now()),
		User:      user,
		IP:        ip,
		Action:    action,
		Target:    target,
		Details:   details,
		Result:    result,
	})
	if MaxEntries > 0 && len(l.entries) > MaxEntries {
		l.entries = append([]Entry{}, l.entries[len(l.entries)-MaxEntries:]...)
	}
}

// Entries returns a snapshot.
func (l *Log) Entries() []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Entry{}, l.entries...)
}

// Len returns the entry count.
func (l *Log) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// Save persists entries atomically (mirrors save_audit_log).
func (l *Log) Save() error {
	l.mu.Lock()
	snapshot := append([]Entry{}, l.entries...)
	l.mu.Unlock()
	out, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	dest := filepath.Join(l.root, LogFile)
	tmp, err := os.CreateTemp(l.root, ".webshare_audit_*.tmp")
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
	return os.Rename(tmpName, dest)
}

// Load reads persisted entries (mirrors load_audit_log; corrupt → empty).
func (l *Log) Load() {
	data, err := os.ReadFile(filepath.Join(l.root, LogFile))
	if err != nil {
		return
	}
	var loaded []Entry
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	l.mu.Lock()
	l.entries = loaded
	l.mu.Unlock()
}
