package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlockTrackerPersistence(t *testing.T) {
	root := t.TempDir()
	tr := NewBlockTracker()
	tr.SetPersistence(root)
	tr.Record("9.9.9.9", false)
	tr.Record("9.9.9.9", false)
	if _, err := os.Stat(filepath.Join(root, LoginAttemptsFile)); err != nil {
		t.Fatalf("attempts file missing: %v", err)
	}
	// Fresh tracker loads the record and keeps blocking after max attempts.
	tr2 := NewBlockTracker()
	tr2.SetPersistence(root)
	for i := 0; i < DefaultMaxAttempts; i++ {
		tr2.Record("9.9.9.9", false)
	}
	if blocked, _ := tr2.Blocked("9.9.9.9"); !blocked {
		t.Fatalf("reloaded attempts did not accumulate to a block")
	}
	// Success clears and persists the removal.
	tr2.Record("9.9.9.9", true)
	tr3 := NewBlockTracker()
	tr3.SetPersistence(root)
	if blocked, _ := tr3.Blocked("9.9.9.9"); blocked {
		t.Fatalf("cleared block reloaded")
	}
}
