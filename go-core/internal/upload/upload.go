// Package upload ports the upload subsystem: simple multipart upload
// helpers plus the chunk-upload session store from
// webshare_app/services/upload_service.py and
// webshare_app/routes/upload_routes/.
package upload

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"webshare-core/internal/files"
	"webshare-core/internal/permission"
)

// Limits mirror upload_service.py and config defaults.
const (
	DefaultChunkSize = 5 * 1024 * 1024
	MaxChunkSize     = 100 * 1024 * 1024
	MaxChunkUpload   = 10 * 1024 * 1024 * 1024 // MAX_CHUNK_UPLOAD_SIZE 10GB
	MaxActivePerOwner = 5
	MaxPendingPerOwner = 20 * 1024 * 1024 * 1024
	FreeSpaceBuffer  = 100 * 1024 * 1024
	SaveIOChunkSize  = 1024 * 1024
	CompletedTTL     = 30 * time.Minute
	SessionTTL       = 2 * time.Hour
)

// Session statuses.
const (
	StatusActive     = "active"
	StatusCompleting = "completing"
	StatusCompleted  = "completed"
)

// ChunkEntry mirrors one chunks[index] dict.
type ChunkEntry struct {
	Path string
	Size int64
}

// Session mirrors one UPLOAD_SESSIONS dict.
type Session struct {
	Filename       string
	TotalSize      int64
	ChunkSize      int64
	TotalChunks    int64
	TargetDir      string
	TempDir        string
	Chunks         map[int64]ChunkEntry
	UploadedBytes  int64
	RejectedBytes  int64
	Status         string
	Created        time.Time
	UpdatedAt      time.Time
	Expires        time.Time
	OwnerRole      string
	OwnerIP        string
	OwnerSessionID string
	OwnerKey       string
	DiskReservation string
	CommittedName  string
}

// Store is the session + disk-reservation state (explicit locks).
type Store struct {
	mu           sync.Mutex
	sessions     map[string]*Session
	diskMu       sync.Mutex
	diskReserved map[string]diskReservation
	now          func() time.Time
}

type diskReservation struct {
	scope string
	bytes int64
}

// NewStore builds an empty store.
func NewStore() *Store {
	return &Store{
		sessions:     map[string]*Session{},
		diskReserved: map[string]diskReservation{},
		now:          time.Now,
	}
}

// Owner mirrors _get_upload_owner_context.
type Owner struct {
	Role      string
	IP        string
	SessionID string
	Key       string
}

// NewOwner builds the owner context: sid wins, else role:ip.
func NewOwner(role, ip, sid string) Owner {
	if role == "" {
		role = "guest"
	}
	key := sid
	if key == "" {
		key = role + ":" + ip
	}
	return Owner{Role: role, IP: ip, SessionID: sid, Key: key}
}

// IsOwner mirrors _is_upload_session_owner.
func (s *Session) IsOwner(o Owner) bool {
	if s.OwnerSessionID != "" {
		return o.SessionID != "" &&
			subtle.ConstantTimeCompare([]byte(s.OwnerSessionID), []byte(o.SessionID)) == 1 &&
			s.OwnerRole == o.Role
	}
	if s.OwnerKey != "" {
		return subtle.ConstantTimeCompare([]byte(s.OwnerKey), []byte(o.Key)) == 1
	}
	return s.OwnerRole == o.Role && s.OwnerIP == o.IP
}

// NewSessionID mirrors secrets.token_urlsafe(16).
func NewSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ExpiredIDs removes expired sessions, releasing reservations.
// Returns (session_id, temp_dir) pairs like _cleanup_expired_upload_sessions_locked.
func (st *Store) ExpiredIDs() [][2]string {
	now := st.now()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out [][2]string
	for id, s := range st.sessions {
		if now.After(s.Expires) {
			out = append(out, [2]string{id, s.TempDir})
			st.releaseLocked(s.DiskReservation)
			delete(st.sessions, id)
		}
	}
	return out
}

// Cleanup removes one session, its temp dir, and its reservation.
func (st *Store) Cleanup(id, tempDir string) {
	if tempDir != "" {
		os.RemoveAll(tempDir)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.sessions[id]; ok {
		st.releaseLocked(s.DiskReservation)
		delete(st.sessions, id)
	} else if id == "" {
		// No session record: nothing reserved under an id.
	}
}

// Pressure mirrors _get_owner_upload_pressure: active count + pending bytes.
func (st *Store) Pressure(ownerKey string) (active int, pending int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, s := range st.sessions {
		if s.OwnerKey != ownerKey || s.Status == StatusCompleted {
			continue
		}
		active++
		pending += max64(s.TotalSize, s.UploadedBytes)
	}
	return active, pending
}

// Get returns the session or nil.
func (st *Store) Get(id string) *Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.sessions[id]
}

// Put stores a session.
func (st *Store) Put(id string, s *Session) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sessions[id] = s
}

// Update runs fn under the session lock.
func (st *Store) Update(id string, fn func(s *Session)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.sessions[id]; ok {
		fn(s)
	}
}

// Reserve mirrors reserve_upload_disk_space.
func (st *Store) Reserve(directory string, required int64, reservationID string) (bool, string, string) {
	if required < 0 {
		required = 0
	}
	if required == 0 {
		return true, "", ""
	}
	scope := absDir(directory)
	if reservationID == "" {
		id, err := NewSessionID()
		if err != nil {
			return false, "서버 내부 오류가 발생했습니다.", ""
		}
		reservationID = "upload-" + id
	}
	free, err := freeDiskBytes(scope)
	if err != nil {
		return false, "디스크 여유 공간 확인 실패", ""
	}
	st.diskMu.Lock()
	defer st.diskMu.Unlock()
	var reserved int64
	for _, r := range st.diskReserved {
		if r.scope == scope {
			reserved += r.bytes
		}
	}
	if reserved+required+FreeSpaceBuffer > free {
		return false, "디스크 공간이 부족합니다.", ""
	}
	st.diskReserved[reservationID] = diskReservation{scope: scope, bytes: required}
	return true, "", reservationID
}

// Release mirrors release_upload_disk_space.
func (st *Store) Release(reservationID string) {
	if reservationID == "" {
		return
	}
	st.diskMu.Lock()
	defer st.diskMu.Unlock()
	delete(st.diskReserved, reservationID)
}

func (st *Store) releaseLocked(reservationID string) {
	if reservationID == "" {
		return
	}
	st.diskMu.Lock()
	defer st.diskMu.Unlock()
	delete(st.diskReserved, reservationID)
}

func absDir(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir
	}
	return abs
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// SaveUpload mirrors atomic_save_upload: stream through a same-directory
// temp file, then replace.
func SaveUpload(src io.Reader, dst string) error {
	dir := filepath.Dir(dst)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".webshare_upload_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	_, copyErr := io.CopyBuffer(tmp, src, make([]byte, SaveIOChunkSize))
	closeErr := tmp.Close()
	if copyErr != nil {
		os.Remove(tmpName)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(tmpName)
		return closeErr
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// ErrChunkTooLarge and ErrTotalExceeded mirror the ValueError messages of
// _save_chunk_with_limits.
var (
	ErrChunkTooLarge = errors.New("chunk size exceeds declared chunk_size")
	ErrTotalExceeded = errors.New("uploaded bytes exceed declared total_size")
)

// SaveChunk mirrors _save_chunk_with_limits.
func SaveChunk(src io.Reader, chunkPath string, maxChunkSize, maxTotalRemaining int64) (int64, error) {
	out, err := os.OpenFile(chunkPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	var written int64
	buf := make([]byte, SaveIOChunkSize)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxChunkSize {
				out.Close()
				return written, ErrChunkTooLarge
			}
			if written > maxTotalRemaining {
				out.Close()
				return written, ErrTotalExceeded
			}
			if _, werr := out.Write(buf[:n]); werr != nil {
				out.Close()
				return written, werr
			}
		}
		if readErr != nil {
			break
		}
	}
	if err := out.Close(); err != nil {
		return written, err
	}
	return written, nil
}

// ResolveUploadTarget mirrors resolve_folder_upload_target:
// (ok, absPath, relSave, errMsg).
func ResolveUploadTarget(baseDir, folderpath, pathsEntry, filename string) (bool, string, string, string) {
	folderRel := permission.NormalizeRelativePath(folderpath)
	safeName := files.SafeFilename(filename)
	relUnder := safeName
	if pathsEntry != "" {
		normalized := strings.Trim(strings.ReplaceAll(pathsEntry, "\\", "/"), "/")
		for _, segment := range strings.Split(normalized, "/") {
			if segment == ".." {
				return false, "", "", "잘못된 업로드 경로입니다"
			}
		}
		rel := permission.NormalizeRelativePath(normalized)
		if rel != "" {
			parts := []string{}
			for _, part := range strings.Split(rel, "/") {
				if part != "" {
					parts = append(parts, files.SafeFilename(part))
				}
			}
			if len(parts) > 0 {
				if last := files.SafeFilename(parts[len(parts)-1]); last != "" {
					parts[len(parts)-1] = last
				} else {
					parts[len(parts)-1] = safeName
				}
				relUnder = strings.Join(parts, "/")
			} else {
				relUnder = safeName
			}
		} else {
			relUnder = safeName
		}
	}
	relSave := relUnder
	if folderRel != "" {
		relSave = folderRel + "/" + relUnder
	}
	valid, absPath, verr := permission.ValidatePath(baseDir, relSave)
	if !valid {
		if verr == "" {
			verr = "잘못된 업로드 경로입니다"
		}
		return false, "", "", verr
	}
	return true, absPath, relSave, ""
}
