package mutate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Concurrent deletes keep one metadata entry per trashed item and every
// item restores to its original sub-folder path (audit ISSUE-004).
func TestMoveToTrashConcurrentKeepsAllMetadata(t *testing.T) {
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 20
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(docs, "f"+itoa(i)+".txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := MoveToTrash(root, filepath.Join(docs, "f"+itoa(i)+".txt"), time.Now()); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("MoveToTrash: %v", err)
	}
	meta := LoadTrashMetadata(root)
	if len(meta.Entries) != n {
		t.Fatalf("metadata entries = %d, want %d", len(meta.Entries), n)
	}
	for name, entry := range meta.Entries {
		if entry.Pending {
			t.Fatalf("%s still pending", name)
		}
		ok, final := RestoreFromTrash(root, name)
		if !ok {
			t.Fatalf("restore %s: %s", name, final)
		}
		rel, _ := filepath.Rel(root, final)
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "docs/f") {
			t.Fatalf("restored to %s, want docs/f*.txt", rel)
		}
	}
	if left := LoadTrashMetadata(root); len(left.Entries) != 0 {
		t.Fatalf("entries left after restore: %d", len(left.Entries))
	}
}

func TestExtractOriginalNameStripsUUID(t *testing.T) {
	cases := map[string]string{
		"20261022_230216_0277624c2d1c4be1b3ef49a2df11a424_report_v2.pdf": "report_v2.pdf",
		"20261022_230216_report.pdf":                                      "report.pdf",
		"plain.txt":                                                       "plain.txt",
	}
	for in, want := range cases {
		if got := ExtractOriginalName(in); got != want {
			t.Errorf("ExtractOriginalName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsoTimeHasFractionSeparator(t *testing.T) {
	got := isoTime(time.Date(2026, 10, 22, 23, 2, 16, 486171000, time.UTC))
	if got != "2026-10-22T23:02:16.486171" {
		t.Fatalf("isoTime = %q", got)
	}
	if got := isoTime(time.Date(2026, 10, 22, 23, 2, 16, 0, time.UTC)); got != "2026-10-22T23:02:16" {
		t.Fatalf("isoTime(zero us) = %q", got)
	}
}

// Items without metadata (lost entry or crash leftover) are re-registered;
// entries without an item are dropped.
func TestSelfHealTrashMetadata(t *testing.T) {
	root := t.TempDir()
	trashDir := filepath.Join(root, TrashDirName)
	if err := os.MkdirAll(trashDir, 0o755); err != nil {
		t.Fatal(err)
	}
	orphanItem := "20261022_230216_0277624c2d1c4be1b3ef49a2df11a424_a.txt"
	if err := os.WriteFile(filepath.Join(trashDir, orphanItem), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := updateTrashMetadata(root, func(meta *TrashMetadata) bool {
		meta.Entries["gone.txt"] = TrashEntry{TrashName: "gone.txt"}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if healed := SelfHealTrashMetadata(root, time.Now()); healed != 1 {
		t.Fatalf("healed = %d", healed)
	}
	meta := LoadTrashMetadata(root)
	if _, ok := meta.Entries["gone.txt"]; ok {
		t.Fatalf("orphan entry kept")
	}
	if e, ok := meta.Entries[orphanItem]; !ok || e.OriginalRelPath != "a.txt" || !e.Healed {
		t.Fatalf("healed entry = %+v", e)
	}
}
