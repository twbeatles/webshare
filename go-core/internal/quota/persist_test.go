package quota

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrackerPersistence(t *testing.T) {
	root := t.TempDir()
	tr := NewTracker()
	tr.SetPersistence(root)
	ok, _, _ := tr.Reserve("ip:1.2.3.4", true, 1024, 0, 0)
	if !ok {
		t.Fatalf("reserve failed")
	}
	tr.Flush()
	if _, err := os.Stat(filepath.Join(root, TrackerFile)); err != nil {
		t.Fatalf("tracker file missing: %v", err)
	}
	tr2 := NewTracker()
	tr2.SetPersistence(root)
	ok, msg := tr2.Check("ip:1.2.3.4", true, 0, 1, 0)
	if ok {
		t.Fatalf("reloaded count lost")
	}
	if msg == "" {
		t.Fatalf("no limit message")
	}
}
