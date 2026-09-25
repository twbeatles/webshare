package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Server-side active sessions (parity with config.ACTIVE_SESSIONS).
// Request authentication itself is cookie-based exactly like Flask; this
// store exists for presence display, logout invalidation, and last-active
// tracking.

// CookieName is Flask's default session cookie name.
const CookieName = "session"

// ActiveSession mirrors one ACTIVE_SESSIONS entry.
type ActiveSession struct {
	IP        string
	Role      string
	LoginTime time.Time
	LastSeen  time.Time
}

// SessionStore is the in-memory active-session table.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*ActiveSession
	now      func() time.Time
}

// NewSessionStore builds an empty store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]*ActiveSession{}, now: time.Now}
}

// NewSessionID mirrors os.urandom(16).hex() at login.
func NewSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Add registers a login.
func (s *SessionStore) Add(sid, ip, role string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sessions[sid] = &ActiveSession{IP: ip, Role: role, LoginTime: now, LastSeen: now}
}

// Remove drops a session, reporting whether one existed.
func (s *SessionStore) Remove(sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[sid]; !ok {
		return false
	}
	delete(s.sessions, sid)
	return true
}

// Touch refreshes last-active; absence is fine (cookie is authoritative,
// exactly like the Flask factory which only updates when present).
func (s *SessionStore) Touch(sid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if info, ok := s.sessions[sid]; ok {
		info.LastSeen = s.now()
	}
}

// Count returns the number of tracked sessions.
func (s *SessionStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// SetSessionCookie emits the Flask-compatible session cookie.
// Attributes mirror the factory: HttpOnly, SameSite=Lax, Path=/,
// Secure only under HTTPS. No Max-Age (browser-session cookie).
func SetSessionCookie(w http.ResponseWriter, value string, secure bool) {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	w.Header().Add("Set-Cookie", c.String())
}

// ClearSessionCookie expires the session cookie (parity with session.clear()
// followed by Flask emitting an empty session).
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	c := &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0).UTC(),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	w.Header().Add("Set-Cookie", c.String())
}

// SessionCookie reads the session cookie value, or "".
func SessionCookie(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
