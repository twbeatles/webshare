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

// KeySet mirrors build_quota_key_set: the client's primary key (session
// when present, else ip) followed by its ip key, deduplicated.
func KeySet(sessionID, ip string) []string {
	primary := Key(sessionID, ip)
	ipKey := Key("", ip)
	if ipKey == primary {
		return []string{primary}
	}
	return []string{primary, ipKey}
}

// Reservation mirrors the quota reservation dict. Keys lists every key the
// reservation charged (combined reservations); Key alone is the legacy
// single-key form.
type Reservation struct {
	Key   string
	Keys  []string
	Count int64
	Bytes int64
	Date  string
}

func (r Reservation) keys() []string {
	if len(r.Keys) > 0 {
		return r.Keys
	}
	if r.Key != "" {
		return []string{r.Key}
	}
	return nil
}

// usageLocked returns the client's usage across keys: every combined
// reservation charges all of the client's keys, so the highest key already
// holds the full usage. A fresh session after re-login starts at zero but
// the ip key still carries the day's usage (audit ISSUE-008).
func (t *Tracker) usageLocked(keys []string) (count, bytes int64) {
	for _, k := range keys {
		e := t.entryLocked(k)
		if e.count > count {
			count = e.count
		}
		if e.bytes > bytes {
			bytes = e.bytes
		}
	}
	return count, bytes
}

// CheckClient mirrors check_combined_download_limit (no mutation).
func (t *Tracker) CheckClient(keys []string, countEvent bool, projectedBytes int64, limitCount int64, limitMB int64) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	count, bytes := t.usageLocked(keys)
	if countEvent && limitCount > 0 && count >= limitCount {
		return false, sprintfCount(limitCount)
	}
	if limitMB > 0 && bytes+max0(projectedBytes) > limitMB*1024*1024 {
		return false, sprintfBytes(limitMB)
	}
	return true, ""
}

// ReserveClient mirrors reserve_combined_download_quota: checks the
// client's usage and charges the reservation to every key atomically.
func (t *Tracker) ReserveClient(keys []string, countEvent bool, projectedBytes int64, limitCount int64, limitMB int64) (bool, string, Reservation) {
	if len(keys) == 0 {
		keys = []string{"ip:unknown"}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	count, bytes := t.usageLocked(keys)
	if countEvent && limitCount > 0 && count >= limitCount {
		return false, sprintfCount(limitCount), Reservation{}
	}
	reservedBytes := max0(projectedBytes)
	if limitMB > 0 && bytes+reservedBytes > limitMB*1024*1024 {
		return false, sprintfBytes(limitMB), Reservation{}
	}
	var reservedCount int64
	if countEvent {
		reservedCount = 1
	}
	charged := make([]string, 0, len(keys))
	date := ""
	for _, k := range keys {
		e := t.entryLocked(k)
		e.count += reservedCount
		e.bytes += reservedBytes
		charged = append(charged, e.key)
		date = e.date
	}
	t.dirty = true
	return true, "", Reservation{Key: charged[0], Keys: charged, Count: reservedCount, Bytes: reservedBytes, Date: date}
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

// Settle mirrors settle_download_quota: refund the undelivered remainder
// of a reservation after the stream closes. actualBytes is what reached
// the client (served range length, partial write on abort, 0 for 304/416
// answers with no body). The download count is kept because the request
// happened; only bytes are adjusted, and the settlement never charges
// extra when actual exceeds the projection.
func (t *Tracker) Settle(r Reservation, actualBytes int64) {
	keys := r.keys()
	if len(keys) == 0 {
		return
	}
	if actualBytes < 0 {
		actualBytes = 0
	}
	refund := r.Bytes - actualBytes
	if refund <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if e, ok := t.entries[k]; ok {
			e.bytes = max0(e.bytes - refund)
			t.dirty = true
		}
	}
}

// Rollback mirrors rollback_download_quota.
func (t *Tracker) Rollback(r Reservation) {
	keys := r.keys()
	if len(keys) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, k := range keys {
		if e, ok := t.entries[k]; ok {
			e.count = max0(e.count - r.Count)
			e.bytes = max0(e.bytes - r.Bytes)
			t.dirty = true
		}
	}
}

// PurgeStale mirrors cleanup_expired_download_trackers: drops entries of
// previous days. Returns the removed count.
func (t *Tracker) PurgeStale() int {
	today := t.now().Format("2006-01-02")
	t.mu.Lock()
	defer t.mu.Unlock()
	removed := 0
	for key, e := range t.entries {
		if e.date != today {
			delete(t.entries, key)
			removed++
		}
	}
	if removed > 0 {
		t.dirty = true
	}
	return removed
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
	return "Daily download limit exceeded (" + itoa(limit) + "). " + quotaPolicyNote
}

func sprintfBytes(limitMB int64) string {
	return "Daily bandwidth limit exceeded (" + itoa(limitMB) + "MB). " + quotaPolicyNote
}

// quotaPolicyNote documents the fairness policy wherever a 429 surfaces:
// reservations conservatively hold the full projected size up front, and
// the reservation is settled down to actual delivered bytes on stream
// close, so only delivered bytes count toward the quota.
const quotaPolicyNote = "Interrupted downloads are settled by actual bytes transferred;" +
	" only delivered bytes count toward the quota."

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
