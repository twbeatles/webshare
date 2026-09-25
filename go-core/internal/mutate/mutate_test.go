package mutate

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionRoundtrip(t *testing.T) {
	rel := "docs/report final.txt"
	name := BuildVersionFilename(rel, "20260102_030405")
	if !VersionNameMatchesRelPath(name, rel) {
		t.Fatalf("fresh version %q does not match %q", name, rel)
	}
	if VersionNameMatchesRelPath(name, "docs/other.txt") {
		t.Fatalf("version %q matches wrong rel", name)
	}
	// Legacy flat names: {16-char stamp}_{underscored rel}.
	if !VersionNameMatchesRelPath("20260102_030405_docs_report final.txt", "docs/report final.txt") {
		t.Fatalf("legacy version name not matched")
	}
}

func TestCleanupKeepsFive(t *testing.T) {
	dir := t.TempDir()
	rel := "a/b.txt"
	for i := 1; i <= 7; i++ {
		stamp := "2026010" + string(rune('0'+i)) + "_030405_000000"
		name := BuildVersionFilename(rel, stamp)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("v"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	CleanupOldVersions(dir, rel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("kept %d versions: %v", len(entries), names)
	}
	// Newest survives, oldest evicted.
	if _, err := os.Stat(filepath.Join(dir, BuildVersionFilename(rel, "20260107_030405_000000"))); err != nil {
		t.Fatalf("newest evicted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, BuildVersionFilename(rel, "20260101_030405_000000"))); !os.IsNotExist(err) {
		t.Fatalf("oldest kept")
	}
}

func TestConflictPolicy(t *testing.T) {
	if got := NormalizeConflictPolicy("FAIL", "rename"); got != ConflictFail {
		t.Fatalf("normalize = %q", got)
	}
	if got := NormalizeConflictPolicy("bogus", "rename"); got != ConflictRename {
		t.Fatalf("normalize default = %q", got)
	}
	dir := t.TempDir()
	fresh := filepath.Join(dir, "fresh.txt")
	ok, final, msg := ResolveConflictPath(fresh, ConflictRename)
	if !ok || final != fresh || msg != "" {
		t.Fatalf("fresh = %v %q %q", ok, final, msg)
	}
	if err := os.WriteFile(fresh, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, _, msg = ResolveConflictPath(fresh, ConflictFail)
	if ok || msg == "" {
		t.Fatalf("fail = %v %q", ok, msg)
	}
	ok, renamed, _ := ResolveConflictPath(fresh, ConflictRename)
	if !ok || renamed == fresh {
		t.Fatalf("rename = %v %q", ok, renamed)
	}
	ok, same, _ := ResolveConflictPath(fresh, ConflictOverwrite)
	if !ok || same != fresh {
		t.Fatalf("overwrite = %v %q", ok, same)
	}
	ok, _, msg = ResolveConflictPath(fresh, "bogus")
	if ok || msg == "" {
		t.Fatalf("unknown = %v %q", ok, msg)
	}
	if got := NextAvailableDirectoryPath(fresh); got != fresh+"_1" {
		t.Fatalf("next dir = %q", got)
	}
}

func TestTrashAndVersions(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "gone.txt")
	if err := os.WriteFile(victim, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	name, err := MoveToTrash(root, victim, now)
	if err != nil {
		t.Fatalf("trash: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".webshare_trash", name)); err != nil {
		t.Fatalf("trashed file missing: %v", err)
	}
	meta := LoadTrashMetadata(root)
	entry, found := meta.Entries[name]
	if !found || entry.OriginalRelPath != "gone.txt" || entry.IsDir {
		t.Fatalf("metadata = %+v", meta)
	}
	// Version creation + retention no-op on fresh file.
	target := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	CreateFileVersion(root, target, true, now)
	entries, _ := os.ReadDir(filepath.Join(root, ".webshare_versions"))
	if len(entries) != 1 {
		t.Fatalf("versions = %d", len(entries))
	}
	// Disabled versioning and missing files are no-ops.
	CreateFileVersion(root, target, false, now)
	CreateFileVersion(root, filepath.Join(root, "missing.txt"), true, now)
	entries, _ = os.ReadDir(filepath.Join(root, ".webshare_versions"))
	if len(entries) != 1 {
		t.Fatalf("versions after no-ops = %d", len(entries))
	}
}
