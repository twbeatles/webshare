package handlers

import (
	"archive/zip"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMkdirRenameDelete(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// mkdir happy path.
	rec := postJSON(t, app, "/mkdir/", map[string]any{"name": "docs"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("mkdir = %d (%s)", rec.Code, rec.Body.String())
	}
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("mkdir body = %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "docs")); err != nil {
		t.Fatalf("mkdir dir missing: %v", err)
	}

	// Duplicate → 400.
	rec = postJSON(t, app, "/mkdir/", map[string]any{"name": "docs"}, cookies, csrf)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "이미 존재하는 폴더입니다") {
		t.Errorf("mkdir dup = %d %s", rec.Code, rec.Body.String())
	}

	// Missing name → 400.
	rec = postJSON(t, app, "/mkdir/", map[string]any{}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("mkdir noname = %d", rec.Code)
	}

	// Guest without upload right → 403.
	guest := loginAs(t, app, "guestpw")
	gcsrf := csrfFor(t, app, guest)
	rec = postJSON(t, app, "/mkdir/", map[string]any{"name": "nope"}, guest, gcsrf)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "업로드/변경 권한이 없습니다") {
		t.Errorf("guest mkdir = %d %s", rec.Code, rec.Body.String())
	}

	// Rename happy path.
	rec = postJSON(t, app, "/rename/hello.txt", map[string]any{"name": "hi.txt"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "hi.txt")); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}

	// Rename conflict → 400.
	rec = postJSON(t, app, "/rename/hi.txt", map[string]any{"name": "docs"}, cookies, csrf)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "동일한 이름이 이미 존재합니다") {
		t.Errorf("rename conflict = %d %s", rec.Code, rec.Body.String())
	}

	// Rename missing → 404.
	rec = postJSON(t, app, "/rename/gone.txt", map[string]any{"name": "x.txt"}, cookies, csrf)
	if rec.Code != http.StatusNotFound {
		t.Errorf("rename missing = %d", rec.Code)
	}

	// old_name variant: filepath is the parent.
	rec = postJSON(t, app, "/rename/sub", map[string]any{"old_name": "nested.md", "name": "deep.md"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("rename old_name = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "sub", "deep.md")); err != nil {
		t.Fatalf("old_name rename missing: %v", err)
	}

	// Delete → trash.
	rec = postJSON(t, app, "/delete/hi.txt", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete = %d (%s)", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "hi.txt")); !os.IsNotExist(err) {
		t.Fatalf("deleted file still present")
	}
	if _, err := os.Stat(filepath.Join(root, ".webshare_trash")); err != nil {
		t.Fatalf("trash dir missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".webshare_trash.json")); err != nil {
		t.Fatalf("trash metadata missing: %v", err)
	}

	// Delete missing → 404.
	rec = postJSON(t, app, "/delete/hi.txt", nil, cookies, csrf)
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete missing = %d", rec.Code)
	}
}

func TestCopyMove(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// Copy twice: fresh target, then rename policy onto the taken name.
	copyDoc := func(dst, policy string) map[string]any {
		rec := postJSON(t, app, "/copy", map[string]any{
			"source": "hello.txt", "destination": dst, "conflict_policy": policy,
		}, cookies, csrf)
		if rec.Code != http.StatusOK && rec.Code != http.StatusConflict {
			t.Fatalf("copy = %d (%s)", rec.Code, rec.Body.String())
		}
		return decodeBody(t, rec)
	}
	doc := copyDoc("copy.txt", "rename")
	if doc["success"] != true || doc["path"] != "copy.txt" {
		t.Fatalf("copy fresh = %s", toJSON(doc))
	}
	doc = copyDoc("copy.txt", "rename")
	if doc["success"] != true || doc["path"] != "copy_1.txt" {
		t.Fatalf("copy rename = %s", toJSON(doc))
	}
	if _, err := os.Stat(filepath.Join(root, "copy_1.txt")); err != nil {
		t.Fatalf("copy target missing: %v", err)
	}

	// Fail policy → 409 DESTINATION_EXISTS.
	rec := postJSON(t, app, "/copy", map[string]any{
		"source": "hello.txt", "destination": "copy_1.txt", "conflict_policy": "fail",
	}, cookies, csrf)
	if rec.Code != http.StatusConflict {
		t.Fatalf("copy fail = %d (%s)", rec.Code, rec.Body.String())
	}
	doc = decodeBody(t, rec)
	if doc["code"] != "DESTINATION_EXISTS" || doc["success"] != false {
		t.Fatalf("copy fail body = %s", toJSON(doc))
	}

	// Overwrite replaces content and keeps a version (versioning on by default).
	if err := os.WriteFile(filepath.Join(root, "copy_1.txt"), []byte("new content"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc = copyDoc("copy_1.txt", "overwrite")
	if doc["success"] != true || doc["path"] != "copy_1.txt" {
		t.Fatalf("copy overwrite = %s", toJSON(doc))
	}
	entries, _ := os.ReadDir(filepath.Join(root, ".webshare_versions"))
	if len(entries) == 0 {
		t.Fatalf("overwrite created no version backup")
	}

	// Self copy → 400.
	rec = postJSON(t, app, "/copy", map[string]any{
		"source": "hello.txt", "destination": "hello.txt",
	}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("self copy = %d", rec.Code)
	}

	// Move into own subtree → 200 success:false.
	rec = postJSON(t, app, "/move", map[string]any{
		"source": "sub", "destination": "sub/inner",
	}, cookies, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "하위 폴더로 이동할 수 없습니다") {
		t.Errorf("self move = %d %s", rec.Code, rec.Body.String())
	}

	// Move happy path.
	rec = postJSON(t, app, "/move", map[string]any{
		"source": "copy_1.txt", "destination": "moved.txt",
	}, cookies, csrf)
	doc = decodeBody(t, rec)
	if rec.Code != http.StatusOK || doc["success"] != true || doc["path"] != "moved.txt" {
		t.Fatalf("move = %d %s", rec.Code, toJSON(doc))
	}
	if _, err := os.Stat(filepath.Join(root, "moved.txt")); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}

	// Missing source → 200 success:false.
	rec = postJSON(t, app, "/move", map[string]any{
		"source": "gone.txt", "destination": "x.txt",
	}, cookies, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "원본을 찾을 수 없습니다") {
		t.Errorf("move missing = %d %s", rec.Code, rec.Body.String())
	}
}

func TestBatchDeleteAndUnzip(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// Batch delete: one present, one missing.
	rec := postJSON(t, app, "/mkdir/", map[string]any{"name": "batch"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("mkdir batch = %d", rec.Code)
	}
	if err := os.WriteFile(filepath.Join(root, "batch", "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, app, "/batch_delete/batch", map[string]any{
		"files": []string{"a.txt", "ghost.txt"},
	}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch = %d (%s)", rec.Code, rec.Body.String())
	}
	doc := decodeBody(t, rec)
	if doc["success"] != true || doc["deleted"] != float64(1) || doc["failed"] != float64(1) {
		t.Fatalf("batch body = %s", toJSON(doc))
	}
	items, _ := doc["failed_items"].([]any)
	if len(items) != 1 {
		t.Fatalf("failed_items = %s", toJSON(doc))
	}

	// Unzip happy path.
	zipPath := filepath.Join(root, "pack.zip")
	makeZip(t, zipPath, map[string]string{"a.txt": "aaa", "d/b.txt": "bbb"})
	rec = postJSON(t, app, "/unzip/pack.zip", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("unzip = %d (%s)", rec.Code, rec.Body.String())
	}
	if data, err := os.ReadFile(filepath.Join(root, "pack", "d", "b.txt")); err != nil || string(data) != "bbb" {
		t.Fatalf("unzipped content = %q, err=%v", data, err)
	}

	// Bad zip → 200 success:false.
	if err := os.WriteFile(filepath.Join(root, "bad.zip"), []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, app, "/unzip/bad.zip", nil, cookies, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "잘못된 ZIP 파일입니다") {
		t.Errorf("bad zip = %d %s", rec.Code, rec.Body.String())
	}

	// Zip slip → 400.
	zipPath2 := filepath.Join(root, "evil.zip")
	makeZip(t, zipPath2, map[string]string{"../escape.txt": "x"})
	rec = postJSON(t, app, "/unzip/evil.zip", nil, cookies, csrf)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "보안 위협 감지") {
		t.Errorf("zip slip = %d %s", rec.Code, rec.Body.String())
	}

	// Audit log persisted (flush throttled in-memory entries first).
	app.FlushState()
	data, err := os.ReadFile(filepath.Join(root, ".webshare_audit.json"))
	if err != nil {
		t.Fatalf("audit file missing: %v", err)
	}
	for _, action := range []string{"batch_delete"} {
		if !strings.Contains(string(data), action) {
			t.Errorf("audit missing %q: %s", action, data)
		}
	}
}

func makeZip(t *testing.T, path string, members map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, content := range members {
		m, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func toJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
