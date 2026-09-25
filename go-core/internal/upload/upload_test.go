package upload

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOwnerMatching(t *testing.T) {
	s := &Session{OwnerRole: "admin", OwnerIP: "1.2.3.4", OwnerSessionID: "sid", OwnerKey: "sid"}
	if !s.IsOwner(NewOwner("admin", "9.9.9.9", "sid")) {
		t.Fatalf("sid owner rejected")
	}
	if s.IsOwner(NewOwner("guest", "1.2.3.4", "sid")) {
		t.Fatalf("role mismatch accepted")
	}
	if s.IsOwner(NewOwner("admin", "1.2.3.4", "other")) {
		t.Fatalf("sid mismatch accepted")
	}
	// Key fallback (no session id): role:ip key.
	k := &Session{OwnerRole: "guest", OwnerIP: "1.2.3.4", OwnerKey: "guest:1.2.3.4"}
	if !k.IsOwner(NewOwner("guest", "1.2.3.4", "")) {
		t.Fatalf("key owner rejected")
	}
	if k.IsOwner(NewOwner("guest", "5.6.7.8", "")) {
		t.Fatalf("key mismatch accepted")
	}
}

func TestReserveRelease(t *testing.T) {
	st := NewStore()
	dir := t.TempDir()
	ok, msg, id := st.Reserve(dir, 1024, "")
	if !ok || id == "" {
		t.Fatalf("reserve = %v %q", ok, msg)
	}
	st.Release(id)
	// Zero requirement needs no id.
	ok, _, id = st.Reserve(dir, 0, "")
	if !ok || id != "" {
		t.Fatalf("zero reserve = %v %q", ok, id)
	}
	// Absurd requirement exceeds disk.
	ok, msg, _ = st.Reserve(dir, 1<<62, "")
	if ok {
		t.Fatalf("absurd reserve accepted")
	}
	if msg == "" {
		t.Fatalf("absurd reserve has no message")
	}
}

func TestSaveChunkLimits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "chunk_00000")
	n, err := SaveChunk(strings.NewReader("0123456789"), path, 10, 10)
	if err != nil || n != 10 {
		t.Fatalf("save = %d %v", n, err)
	}
	if _, err := SaveChunk(strings.NewReader("0123456789A"), path, 10, 100); err != ErrChunkTooLarge {
		t.Fatalf("oversize = %v", err)
	}
	if _, err := SaveChunk(strings.NewReader("0123456789A"), path, 100, 10); err != ErrTotalExceeded {
		t.Fatalf("overtotal = %v", err)
	}
}

func TestResolveUploadTarget(t *testing.T) {
	root := t.TempDir()
	ok, abs, rel, msg := ResolveUploadTarget(root, "sub", "pkg/a.txt", "ignored")
	if !ok || rel != "sub/pkg/a.txt" {
		t.Fatalf("resolve = %v %q %q", ok, rel, msg)
	}
	// Parity with Python validate_path: the returned abs is the RESOLVED
	// path, so expect it under the resolved root — t.TempDir is not
	// guaranteed canonical (case, 8.3 short names, CI runners).
	wantRoot := root
	if real, err := filepath.EvalSymlinks(root); err == nil {
		wantRoot = real
	}
	if abs != filepath.Join(wantRoot, "sub", "pkg", "a.txt") {
		t.Fatalf("abs = %q", abs)
	}
	ok, _, _, msg = ResolveUploadTarget(root, "", "../evil.txt", "x.txt")
	if ok || msg == "" {
		t.Fatalf("traversal accepted: %v %q", ok, msg)
	}
	ok, _, rel, _ = ResolveUploadTarget(root, "", "", "plain.txt")
	if !ok || rel != "plain.txt" {
		t.Fatalf("plain = %v %q", ok, rel)
	}
}

func TestSessionExpiry(t *testing.T) {
	st := NewStore()
	st.now = func() time.Time { return time.Now() }
	st.Put("old", &Session{TempDir: filepath.Join(t.TempDir(), "gone"), Expires: time.Now().Add(-time.Hour)})
	expired := st.ExpiredIDs()
	if len(expired) != 1 || expired[0][0] != "old" {
		t.Fatalf("expired = %v", expired)
	}
	if st.Get("old") != nil {
		t.Fatalf("expired session kept")
	}
	active, pending := st.Pressure("nobody")
	if active != 0 || pending != 0 {
		t.Fatalf("pressure = %d %d", active, pending)
	}
	// Completed sessions do not count as active.
	st.Put("done", &Session{Status: StatusCompleted, TotalSize: 100, OwnerKey: "k"})
	st.Put("live", &Session{Status: StatusActive, TotalSize: 100, UploadedBytes: 40, OwnerKey: "k"})
	active, pending = st.Pressure("k")
	if active != 1 || pending != 100 {
		t.Fatalf("pressure = %d %d", active, pending)
	}
}
