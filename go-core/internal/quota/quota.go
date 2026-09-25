// Package quota ports utils/helpers/download_quota.py: daily per-tracker
// download count and bandwidth limits with atomic reserve/rollback.
package quota

import (
	"strings"
	"sync"
	"time"
)

// Tracker holds daily download counters keyed by tracker key.
type Tracker struct {
	mu      sync.Mutex
	entries map[string]*entry
	now     func() time.Time
	root    string // persistence dir; "" disables
	dirty   bool
}

type entry struct {
	key   string
	count int64
	bytes int64
	date  string
}

// NewTracker builds an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{entries: map[string]*entry{}, now: time.Now}
}

// Key mirrors build_download_tracker_key: session id wins, else IP.
func Key(sessionID, ip string) string {
	if sid := strings.TrimSpace(sessionID); sid != "" {
		return "session:" + sid
	}
	if ip = strings.TrimSpace(ip); ip == "" {
		ip = "unknown"
	}
	return "ip:" + ip
}

// Reservation mirrors the quota reservation dict.
type Reservation struct {
	Key   string
	Count int64
	Bytes int64
	Date  string
}

// Check mirrors check_download_limit (no mutation).
func (t *Tracker) Check(key string, countEvent bool, projectedBytes int64, limitCount int64, limitMB int64) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entryLocked(key)
	if countEvent && limitCount > 0 && e.count >= limitCount {
		return false, sprintfCount(limitCount)
	}
	if limitMB > 0 && e.bytes+max0(projectedBytes) > limitMB*1024*1024 {
		return false, sprintfBytes(limitMB)
	}
	return true, ""
}

// Reserve mirrors reserve_download_quota: check-then-reserve atomically.
func (t *Tracker) Reserve(key string, countEvent bool, projectedBytes int64, limitCount int64, limitMB int64) (bool, string, Reservation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.entryLocked(key)
	if countEvent && limitCount > 0 && e.count >= limitCount {
		return false, sprintfCount(limitCount), Reservation{}
	}
	reservedBytes := max0(projectedBytes)
	if limitMB > 0 && e.bytes+reservedBytes > limitMB*1024*1024 {
		return false, sprintfBytes(limitMB), Reservation{}
	}
	var reservedCount int64
	if countEvent {
		reservedCount = 1
	}
	e.count += reservedCount
	e.bytes += reservedBytes
	t.dirty = true
	return true, "", Reservation{Key: e.key, Count: reservedCount, Bytes: reservedBytes, Date: e.date}
}

// Rollback mirrors rollback_download_quota.
func (t *Tracker) Rollback(r Reservation) {
	if r.Key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[r.Key]
	if !ok {
		return
	}
	e.count = max0(e.count - r.Count)
	e.bytes = max0(e.bytes - r.Bytes)
	t.dirty = true
}

func (t *Tracker) entryLocked(key string) *entry {
	today := t.now().Format("2006-01-02")
	key = strings.TrimSpace(key)
	if key == "" {
		key = "ip:unknown"
	}
	e, ok := t.entries[key]
	if !ok || e.date != today {
		e = &entry{key: key, date: today}
		t.entries[key] = e
	}
	return e
}

func max0(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

func sprintfCount(limit int64) string {
	return "Daily download limit exceeded (" + itoa(limit) + ")"
}

func sprintfBytes(limitMB int64) string {
	return "Daily bandwidth limit exceeded (" + itoa(limitMB) + "MB)"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
