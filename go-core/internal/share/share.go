// Package share ports the share-link subsystem:
// webshare_app/routes/share_routes.py, services/share_service.py,
// features/share_links_store.py and the share-password-attempts half of
// features/runtime_state.py.
package share

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"webshare-core/internal/files"
	"webshare-core/internal/permission"
)

// Persistence filenames inside the shared folder.
const (
	LinksFile    = ".webshare_share_links.json"
	AttemptsFile = ".webshare_share_password_attempts.json"
)

// Brute-force guard mirrors MAX_LOGIN_ATTEMPTS / LOGIN_BLOCK_MINUTES.
const (
	MaxAttempts  = 5
	BlockMinutes = 15
)

// Link mirrors one SHARE_LINKS dict.
type Link struct {
	Path          string    `json:"path"`
	Expires       time.Time `json:"expires"`
	CreatedBy     string    `json:"created_by"`
	IsDir         bool      `json:"is_dir"`
	PasswordHash  string    `json:"password_hash,omitempty"`
	MaxDownloads  int64     `json:"max_downloads"`
	DownloadCount int64     `json:"download_count"`
	CreatedAt     time.Time `json:"created_at"`
}

type attempt struct {
	Attempts     int       `json:"attempts"`
	LastAttempt  time.Time `json:"last_attempt,omitempty"`
	BlockedUntil time.Time `json:"blocked_until,omitempty"`
}

// Store holds links and password-attempt guards.
type Store struct {
	mu            sync.Mutex
	root          string
	links         map[string]*Link
	attempts      map[string]*attempt // key: ip + "\n" + token
	attemptsDirty bool
	now           func() time.Time
}

// NewStore builds a store rooted at the shared folder and loads persisted state.
func NewStore(root string) *Store {
	s := &Store{root: root, links: map[string]*Link{}, attempts: map[string]*attempt{}, now: time.Now}
	s.LoadLinks()
	s.LoadAttempts()
	return s
}

// NewToken mirrors secrets.token_urlsafe(16).
func NewToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Create inserts a link and persists (mirrors create_share_link storage).
func (s *Store) Create(token string, link *Link) {
	s.mu.Lock()
	s.links[token] = link
	s.mu.Unlock()
	s.SaveLinks()
}

// Get returns the link or nil.
func (s *Store) Get(token string) *Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.links[token]
}

// Delete removes a link, reporting its path (mirrors delete_share_link).
func (s *Store) Delete(token string) (string, bool) {
	s.mu.Lock()
	link, ok := s.links[token]
	if ok {
		delete(s.links, token)
	}
	s.mu.Unlock()
	if !ok {
		return "unknown", false
	}
	s.SaveLinks()
	return link.Path, true
}

// ListActive drops expired links (persisting when any were removed) and
// returns the active ones ordered by token for stable output.
func (s *Store) ListActive() []*ActiveLink {
	now := s.now()
	s.mu.Lock()
	var expired []string
	var active []*ActiveLink
	for token, link := range s.links {
		if !now.Before(link.Expires) {
			expired = append(expired, token)
			continue
		}
		active = append(active, &ActiveLink{
			Token:         token,
			Path:          link.Path,
			Expires:       link.Expires,
			IsDir:         link.IsDir,
			DownloadCount: link.DownloadCount,
			MaxDownloads:  link.MaxDownloads,
			HasPassword:   link.PasswordHash != "",
		})
	}
	for _, token := range expired {
		delete(s.links, token)
	}
	removed := len(expired) > 0
	s.mu.Unlock()
	if removed {
		s.SaveLinks()
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Token < active[j].Token })
	return active
}

// ActiveLink is the JSON shape of list_share_links entries.
type ActiveLink struct {
	Token         string    `json:"token"`
	Path          string    `json:"path"`
	Expires       time.Time `json:"expires"`
	IsDir         bool      `json:"is_dir"`
	DownloadCount int64     `json:"download_count"`
	MaxDownloads  int64     `json:"max_downloads"`
	HasPassword   bool      `json:"has_password"`
}

// Snapshot mirrors the locked validation of access_share_link: missing,
// expired (deleted + persisted), or over-limit links fail; otherwise the
// path/is_dir/password-hash snapshot is returned.
type Snapshot struct {
	Path         string
	IsDir        bool
	PasswordHash string
}

// AccessError carries the user message and HTTP status for failed access.
type AccessError struct {
	Msg    string
	Status int
}

func (e *AccessError) Error() string { return e.Msg }

// Access validates a token like the locked section of access_share_link.
func (s *Store) Access(token string) (Snapshot, *AccessError) {
	s.mu.Lock()
	link, ok := s.links[token]
	if !ok {
		s.mu.Unlock()
		return Snapshot{}, &AccessError{Msg: "링크를 찾을 수 없습니다.", Status: 404}
	}
	if !s.now().Before(link.Expires) {
		delete(s.links, token)
		s.mu.Unlock()
		s.SaveLinks()
		return Snapshot{}, &AccessError{Msg: "링크가 만료되었습니다.", Status: 410}
	}
	if link.MaxDownloads > 0 && link.DownloadCount >= link.MaxDownloads {
		s.mu.Unlock()
		return Snapshot{}, &AccessError{Msg: "다운로드 횟수가 초과되었습니다.", Status: 429}
	}
	snap := Snapshot{Path: link.Path, IsDir: link.IsDir, PasswordHash: link.PasswordHash}
	s.mu.Unlock()
	return snap, nil
}

// ReserveDownload mirrors _reserve_share_download: atomically consume one
// download slot and persist.
func (s *Store) ReserveDownload(token string) (bool, string) {
	s.mu.Lock()
	link, ok := s.links[token]
	if !ok {
		s.mu.Unlock()
		return false, "링크를 찾을 수 없습니다."
	}
	if link.MaxDownloads > 0 && link.DownloadCount >= link.MaxDownloads {
		s.mu.Unlock()
		return false, "다운로드 횟수가 초과되었습니다."
	}
	link.DownloadCount++
	s.mu.Unlock()
	s.SaveLinks()
	return true, ""
}

// RollbackDownload mirrors _rollback_reserved_download.
func (s *Store) RollbackDownload(token string) {
	s.mu.Lock()
	if link, ok := s.links[token]; ok && link.DownloadCount > 0 {
		link.DownloadCount--
	}
	s.mu.Unlock()
	s.SaveLinks()
}

// CheckBlocked mirrors check_share_password_blocked: (blocked, remainingMin).
// Expired blocks are dropped and marked dirty.
func (s *Store) CheckBlocked(ip, token string) (bool, int) {
	key := ip + "\n" + token
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.attempts[key]
	if !ok {
		return false, 0
	}
	if !info.BlockedUntil.IsZero() {
		if s.now().Before(info.BlockedUntil) {
			remaining := info.BlockedUntil.Sub(s.now()).Minutes()
			return true, int(remaining + 0.5)
		}
		delete(s.attempts, key)
		s.attemptsDirty = true
		return false, 0
	}
	return false, 0
}

// RecordAttempt mirrors record_share_password_attempt.
func (s *Store) RecordAttempt(ip, token string, success bool) {
	key := ip + "\n" + token
	s.mu.Lock()
	if success {
		if _, ok := s.attempts[key]; ok {
			delete(s.attempts, key)
			s.attemptsDirty = true
		}
		s.mu.Unlock()
		s.flushAttemptsLocked()
		return
	}
	info, ok := s.attempts[key]
	if !ok {
		info = &attempt{}
		s.attempts[key] = info
	}
	info.Attempts++
	info.LastAttempt = s.now()
	if info.Attempts >= MaxAttempts {
		info.BlockedUntil = s.now().Add(BlockMinutes * time.Minute)
	}
	s.attemptsDirty = true
	s.mu.Unlock()
	s.flushAttemptsLocked()
}

// FlushAttempts persists attempts when dirty (mirrors
// flush_share_password_attempts_if_dirty).
func (s *Store) FlushAttempts() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushAttemptsLocked()
}

func (s *Store) flushAttemptsLocked() {
	if !s.attemptsDirty {
		return
	}
	if s.saveAttemptsLocked() {
		s.attemptsDirty = false
	}
}

// CollectZipFiles mirrors _collect_share_zip_files by delegating to the
// shared collector with the root folder name as archive prefix.
func CollectZipFiles(root, rootAbs, rootRel string, canRead func(rel string) bool) []files.ZipItem {
	rootName := filepath.Base(filepath.Clean(rootAbs))
	return files.CollectZipFiles(rootAbs, rootRel, rootName, canRead,
		func(rel string) (string, bool) {
			ok, full, _ := permission.ValidatePath(root, rel)
			return full, ok
		})
}

// EstimateZipBytes mirrors _estimate_zip_transfer_bytes.
func EstimateZipBytes(items []files.ZipItem) int64 {
	return files.EstimateZipBytes(items)
}
