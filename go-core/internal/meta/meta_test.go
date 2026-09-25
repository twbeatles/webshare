package meta

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundtrip(t *testing.T) {
	root := t.TempDir()
	s := NewStore(root)
	s.Tags["a.txt"] = []Tag{{Tag: "t", Color: "#ffffff"}}
	s.Favorites = []Favorite{{Path: "sub", Name: "sub", Added: "2026-01-01T00:00:00"}}
	s.Memos["a.txt"] = Memo{Memo: "hi", Updated: "2026-01-01T00:00:00"}
	s.Bookmarks = []Bookmark{{Path: "b", Name: "b", Added: "2026-01-01T00:00:00"}}
	s.Save()
	if _, err := os.Stat(filepath.Join(root, MetaFile)); err != nil {
		t.Fatalf("meta file missing: %v", err)
	}
	s2 := NewStore(root)
	if len(s2.Tags["a.txt"]) != 1 || s2.Memos["a.txt"].Memo != "hi" {
		t.Fatalf("reloaded = %+v %+v", s2.Tags, s2.Memos)
	}
	if len(s2.Favorites) != 1 || len(s2.Bookmarks) != 1 {
		t.Fatalf("reloaded lists = %+v %+v", s2.Favorites, s2.Bookmarks)
	}
	// Corrupt file keeps current state.
	os.WriteFile(filepath.Join(root, MetaFile), []byte("{bad"), 0o644)
	s2.Tags["z"] = []Tag{{Tag: "z", Color: "#000000"}}
	s2.Load()
	if len(s2.Tags["z"]) != 1 {
		t.Fatalf("corrupt load wiped state")
	}
}
