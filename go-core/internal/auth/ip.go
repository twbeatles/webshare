package auth

import (
	"strings"
	"sync"
	"time"
)

// IP policy (parity with webshare_app/security/ip_blocker.py and
// utils/file_utils.py get_real_ip / _extract_client_ip_from_xff).
//
// Limits: DefaultMaxAttempts=5 failures trigger a DefaultBlockMinutes=15
// minute block. Remaining minutes use round-half-up; Python uses
// round-half-even — values landing exactly on .5 differ in theory but never
// occur from second-resolution timestamps in practice.

// DefaultMaxAttempts mirrors config.MAX_LOGIN_ATTEMPTS.
const DefaultMaxAttempts = 5

// DefaultBlockMinutes mirrors config.LOGIN_BLOCK_MINUTES.
const DefaultBlockMinutes = 15

// ExtractClientIP picks the client IP from X-Forwarded-For given trusted hops.
// Right-most entries are proxies; index = len(parts) - hops - 1, floored at 0.
func ExtractClientIP(xff string, trustedHops int) string {
	var parts []string
	for _, p := range strings.Split(xff, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	hops := trustedHops
	if hops < 1 {
		hops = 1
	}
	index := len(parts) - hops - 1
	if index < 0 {
		index = 0
	}
	return parts[index]
}

// RealIP mirrors get_real_ip: X-Forwarded-For (then X-Real-IP) is trusted
// only when the direct peer is a configured trusted proxy.
func RealIP(remoteAddr, xff, xRealIP string, trustedProxies []string, trustedHops int) string {
	trusted := false
	for _, p := range trustedProxies {
		if p == remoteAddr {
			trusted = true
			break
		}
	}
	if trusted {
		if candidate := ExtractClientIP(xff, trustedHops); candidate != "" {
			return candidate
		}
		if xRealIP != "" {
			return xRealIP
		}
	}
	return remoteAddr
}

// Whitelisted mirrors check_ip_whitelist: empty list allows all, and the
// literal "127.0.0.1" always bypasses (note: "::1" does NOT bypass).
func Whitelisted(ip string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true
	}
	for _, w := range whitelist {
		if w == ip {
			return true
		}
	}
	return ip == "127.0.0.1"
}

type attemptInfo struct {
	attempts     int
	lastAttempt  time.Time
	blockedUntil time.Time
}

// BlockTracker mirrors LOGIN_ATTEMPTS + ip_blocker record/check/unblock.
type BlockTracker struct {
	mu           sync.Mutex
	attempts     map[string]*attemptInfo
	maxAttempts  int
	blockMinutes int
	now          func() time.Time
	root         string // persistence dir; "" disables
	dirty        bool
}

// NewBlockTracker builds a tracker with production defaults.
func NewBlockTracker() *BlockTracker {
	return &BlockTracker{
		attempts:     map[string]*attemptInfo{},
		maxAttempts:  DefaultMaxAttempts,
		blockMinutes: DefaultBlockMinutes,
		now:          time.Now,
	}
}

// Record logs a login attempt; success clears the IP record.
// Mutations persist synchronously when a root is set (failed logins are
// rare; blocks must survive restarts for the guard to hold).
func (t *BlockTracker) Record(ip string, success bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	if success {
		if _, ok := t.attempts[ip]; ok {
			delete(t.attempts, ip)
			changed = true
		}
	} else {
		info, ok := t.attempts[ip]
		if !ok {
			info = &attemptInfo{}
			t.attempts[ip] = info
		}
		info.attempts++
		info.lastAttempt = t.now()
		if info.attempts >= t.maxAttempts {
			info.blockedUntil = t.now().Add(time.Duration(t.blockMinutes) * time.Minute)
		}
		changed = true
	}
	if changed {
		t.dirty = true
		t.saveLocked()
	}
}

// Blocked mirrors check_ip_blocked: expired blocks are dropped (false, 0).
func (t *BlockTracker) Blocked(ip string) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.attempts[ip]
	if !ok {
		return false, 0
	}
	if info.blockedUntil.IsZero() {
		return false, 0
	}
	now := t.now()
	if now.Before(info.blockedUntil) {
		remaining := info.blockedUntil.Sub(now).Minutes()
		return true, int(remaining + 0.5)
	}
	delete(t.attempts, ip)
	t.dirty = true
	t.saveLocked()
	return false, 0
}

// Unblock clears an IP record, reporting whether one existed.
func (t *BlockTracker) Unblock(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.attempts[ip]; !ok {
		return false
	}
	delete(t.attempts, ip)
	t.dirty = true
	t.saveLocked()
	return true
}

// BlockedIP describes one active block (mirrors get_blocked_ips).
type BlockedIP struct {
	IP               string
	BlockedUntil     time.Time
	RemainingMinutes int
}

// BlockedList lists currently blocked IPs.
func (t *BlockTracker) BlockedList() []BlockedIP {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	var out []BlockedIP
	for ip, info := range t.attempts {
		if !info.blockedUntil.IsZero() && info.blockedUntil.After(now) {
			out = append(out, BlockedIP{
				IP:               ip,
				BlockedUntil:     info.blockedUntil,
				RemainingMinutes: int(info.blockedUntil.Sub(now).Minutes() + 0.5),
			})
		}
	}
	return out
}

// Cleanup drops expired blocks and stale (>maxAgeHours) records, mirroring
// cleanup_expired_login_attempts.
func (t *BlockTracker) Cleanup(maxAgeHours int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	removed := 0
	for ip, info := range t.attempts {
		if !info.blockedUntil.IsZero() && !info.blockedUntil.After(now) {
			delete(t.attempts, ip)
			removed++
			continue
		}
		if info.blockedUntil.IsZero() {
			if info.lastAttempt.IsZero() || now.Sub(info.lastAttempt).Hours() > float64(maxAgeHours) {
				delete(t.attempts, ip)
				removed++
			}
		}
	}
	if removed > 0 {
		t.dirty = true
		t.saveLocked()
	}
	return removed
}
