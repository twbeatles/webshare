package mutate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ISSUE-004: CreateFileVersion reports backup failure so restore can abort.
func TestCreateFileVersionReportsStatus(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	// Disabled versioning and missing files are no-op successes.
	if !CreateFileVersion(root, filepath.Join(root, "missing.txt"), true, now) {
		t.Error("missing source should be a no-op success")
	}
	target := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !CreateFileVersion(root, target, false, now) {
		t.Error("disabled versioning should be a no-op success")
	}
	// A real backup succeeds and lands a version file.
	if !CreateFileVersion(root, target, true, now) {
		t.Fatal("backup should succeed")
	}
	entries, _ := os.ReadDir(filepath.Join(root, VersionDirName))
	if len(entries) != 1 {
		t.Fatalf("versions = %d, want 1", len(entries))
	}
}
// Coarse clocks can repeat the same stamp for back-to-back calls;
// the second backup must not overwrite the first.
func TestCreateFileVersionUniqueWhenStampRepeats(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 9, 29, 2, 27, 37, 188122000, time.UTC)
	target := filepath.Join(root, "frozen.txt")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !CreateFileVersion(root, target, true, now) {
		t.Fatal("first backup should succeed")
	}
	if !CreateFileVersion(root, target, true, now) {
		t.Fatal("second backup with the same stamp should succeed")
	}
	entries, _ := os.ReadDir(filepath.Join(root, VersionDirName))
	matched := 0
	seen := map[string]bool{}
	for _, e := range entries {
		if VersionNameMatchesRelPath(e.Name(), "frozen.txt") {
			matched++
			seen[e.Name()] = true
		}
	}
	if matched != 2 || len(seen) != 2 {
		t.Fatalf("versions = %d, want 2 distinct backups", matched)
	}
}
