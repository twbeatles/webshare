package files

import (
	"os"
	"path/filepath"
	"testing"
)

func listingRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"b.txt":          "bb",
		"a.txt":          "a",
		"C.MD":           "c",
		"photo.jpg":      "fakejpg",
		"movie.mp4":      "fakemp4",
		"archive.zip":    "fakezip",
		"sub/inner.txt":  "inner",
		"sub/deep/x.log": "log",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func allowAll(rel, action string) bool { return true }

func TestListPageBasics(t *testing.T) {
	root := listingRoot(t)
	page := ListPage(ListOptions{BaseDir: root, CanRead: allowAll})
	if !page.Success {
		t.Fatal("list failed")
	}
	// Folders first: emptydir, sub, then files sorted by name.
	if len(page.Items) != 8 {
		t.Fatalf("got %d items", len(page.Items))
	}
	if !page.Items[0].IsDir || page.Items[0].Name != "emptydir" {
		t.Errorf("first item = %+v, want emptydir folder", page.Items[0])
	}
	if !page.Items[1].IsDir || page.Items[1].Name != "sub" {
		t.Errorf("second item = %+v, want sub folder", page.Items[1])
	}
	if page.Items[2].Name != "a.txt" {
		t.Errorf("third item = %q, want a.txt", page.Items[2].Name)
	}
	if page.Pagination.TotalCount != 8 || page.Pagination.TotalPages != 1 {
		t.Errorf("pagination = %+v", page.Pagination)
	}
	for _, it := range page.Items {
		if it.Capabilities != nil {
			t.Errorf("capabilities should be absent without resolver: %+v", it)
		}
	}
}

func TestListPageQuerySortPagination(t *testing.T) {
	root := listingRoot(t)
	page := ListPage(ListOptions{BaseDir: root, Query: "TXT", CanRead: allowAll})
	// Query applies to the current dir only: a.txt, b.txt.
	if page.Pagination.TotalCount != 2 {
		t.Fatalf("query txt total = %d", page.Pagination.TotalCount)
	}
	names := []string{}
	for _, it := range page.Items {
		names = append(names, it.Name)
	}
	if names[0] != "a.txt" || names[1] != "b.txt" {
		t.Fatalf("query items = %v", names)
	}
	sub := ListPage(ListOptions{BaseDir: root, Subpath: "sub", SortBy: "size", Order: "desc", CanRead: allowAll})
	// Folders always come first, then files by size desc.
	if len(sub.Items) != 2 || !sub.Items[0].IsDir || sub.Items[1].Name != "inner.txt" {
		t.Errorf("sub size desc = %v", sub.Items)
	}
	paged := ListPage(ListOptions{BaseDir: root, Page: 2, PageSize: 20, CanRead: allowAll})
	_ = paged
	clamped := ListPage(ListOptions{BaseDir: root, Page: 99, PageSize: 20, CanRead: allowAll})
	if clamped.Pagination.Page != clamped.Pagination.TotalPages {
		t.Errorf("page not clamped: %+v", clamped.Pagination)
	}
	small := ListPage(ListOptions{BaseDir: root, PageSize: 5, CanRead: allowAll})
	if small.Pagination.PageSize != 20 {
		t.Errorf("page_size not clamped to 20: %+v", small.Pagination)
	}
	deny := ListPage(ListOptions{BaseDir: root, CanRead: func(rel, action string) bool {
		return rel != "b.txt"
	}})
	for _, it := range deny.Items {
		if it.Name == "b.txt" {
			t.Error("access filter ignored")
		}
	}
	missing := ListPage(ListOptions{BaseDir: root, Subpath: "nope", CanRead: allowAll})
	if missing.Success || missing.Status != 404 {
		t.Errorf("missing dir = %+v", missing)
	}
}

func TestParseRangeCases(t *testing.T) {
	const size = 1000
	cases := []struct {
		header string
		start  int64
		length int64
		status int // 0 full, 206 partial, 416 unsatisfiable, -1 ignore(full)
	}{
		{"", 0, 1000, 0},
		{"bytes=0-99", 0, 100, 206},
		{"bytes=900-", 900, 100, 206},
		{"bytes=-100", 900, 100, 206},
		{"bytes=-5000", 0, 1000, 206},
		{"bytes=0-9999", 0, 1000, 206},
		{"bytes=1000-", 0, 0, 416},
		{"bytes=500-100", 0, 0, 416},
		{"bytes=abc-def", 0, 0, 416},
		{"items=0-10", 0, 1000, 0},
		{"bytes=0-1,3-4", 0, 0, -1},
	}
	for _, c := range cases {
		ranges, ok, unsat := ParseRange(c.header, size)
		switch c.status {
		case 0:
			if unsat || !ok || len(ranges) != 0 {
				t.Errorf("%q: want full, got %v %v %v", c.header, ranges, ok, unsat)
			}
		case 206:
			if unsat || !ok || len(ranges) != 1 || ranges[0].Start != c.start || ranges[0].Length != c.length {
				t.Errorf("%q: want %d+%d, got %v %v %v", c.header, c.start, c.length, ranges, ok, unsat)
			}
		case 416:
			if !unsat {
				t.Errorf("%q: want unsatisfiable", c.header)
			}
		case -1:
			if ok || unsat {
				t.Errorf("%q: want ignore (full with !ok)", c.header)
			}
		}
	}
}
