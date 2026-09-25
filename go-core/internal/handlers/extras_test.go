package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrashCycle(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// Move via /trash.
	rec := postJSON(t, app, "/trash", map[string]any{"path": "hello.txt"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("trash move = %d (%s)", rec.Code, rec.Body.String())
	}
	doc := decodeBody(t, rec)
	if doc["success"] != true || doc["trash_name"] == nil {
		t.Fatalf("trash move body = %s", rec.Body.String())
	}
	trashName, _ := doc["trash_name"].(string)

	// List shows it.
	rec = app.do(t, "GET", "/trash/list", nil, nil, cookies)
	doc = decodeBody(t, rec)
	items, _ := doc["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("trash list = %s", rec.Body.String())
	}
	item, _ := items[0].(map[string]any)
	if item["name"] != trashName || item["original_name"] != "hello.txt" || item["original_path"] != "hello.txt" {
		t.Fatalf("trash item = %v", item)
	}

	// Restore.
	rec = postJSON(t, app, "/trash/restore", map[string]any{"name": trashName}, cookies, csrf)
	doc = decodeBody(t, rec)
	if rec.Code != http.StatusOK || doc["success"] != true || doc["restored_name"] != "hello.txt" {
		t.Fatalf("restore = %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "hello.txt")); err != nil {
		t.Fatalf("restored file missing: %v", err)
	}

	// Restore missing → success:false.
	rec = postJSON(t, app, "/trash/restore", map[string]any{"name": "nope"}, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != false {
		t.Fatalf("restore missing = %s", rec.Body.String())
	}

	// Empty with one item.
	if err := os.WriteFile(filepath.Join(root, "bye.txt"), []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec = postJSON(t, app, "/trash", map[string]any{"path": "bye.txt"}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("trash move 2 = %d", rec.Code)
	}
	rec = postJSON(t, app, "/trash/empty", nil, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("empty = %s", rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".webshare_trash")); !os.IsNotExist(err) {
		t.Fatalf("trash dir still present")
	}

	// Cleanup on empty trash.
	rec = postJSON(t, app, "/api/trash/cleanup", nil, cookies, csrf)
	doc = decodeBody(t, rec)
	if doc["success"] != true || doc["deleted"] != float64(0) {
		t.Fatalf("cleanup = %s", rec.Body.String())
	}
}

func TestMetadataCycle(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// Tags.
	rec := postJSON(t, app, "/api/tags", map[string]any{
		"path": "hello.txt", "tag": "important", "color": "#ff0000",
	}, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("tag add = %s", rec.Body.String())
	}
	rec = postJSON(t, app, "/api/tags", map[string]any{
		"path": "hello.txt", "tag": "important",
	}, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != false {
		t.Fatalf("tag dup = %s", rec.Body.String())
	}
	rec = postJSON(t, app, "/api/tags", map[string]any{
		"path": "hello.txt", "tag": "x", "color": "red",
	}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("tag color = %d", rec.Code)
	}
	rec = app.do(t, "GET", "/api/tags?path=hello.txt", nil, nil, cookies)
	doc := decodeBody(t, rec)
	tags, _ := doc["tags"].([]any)
	if len(tags) != 1 {
		t.Fatalf("tags get = %s", rec.Body.String())
	}

	// Favorites + bookmarks.
	for _, route := range []string{"/api/favorites", "/bookmarks"} {
		rec = postJSON(t, app, route, map[string]any{"path": "sub"}, cookies, csrf)
		if doc := decodeBody(t, rec); doc["success"] != true {
			t.Fatalf("%s add = %s", route, rec.Body.String())
		}
		rec = postJSON(t, app, route, map[string]any{"path": "sub"}, cookies, csrf)
		if doc := decodeBody(t, rec); doc["success"] != false {
			t.Fatalf("%s dup = %s", route, rec.Body.String())
		}
	}

	// Memo.
	rec = postJSON(t, app, "/api/memo/hello.txt", map[string]any{"memo": "remember this"}, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("memo set = %s", rec.Body.String())
	}
	rec = app.do(t, "GET", "/api/memo/hello.txt", nil, nil, cookies)
	doc = decodeBody(t, rec)
	if doc["memo"] != "remember this" || doc["updated"] == "" {
		t.Fatalf("memo get = %s", rec.Body.String())
	}

	// Meta persisted.
	data, err := os.ReadFile(filepath.Join(app.Config.Folder, ".webshare_meta.json"))
	if err != nil || !strings.Contains(string(data), "remember this") {
		t.Fatalf("meta file = %v %s", err, data)
	}
}

func TestVersionsAndAuditAndSystem(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// Create a version by overwriting via copy.
	if err := os.WriteFile(filepath.Join(root, "v.txt"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(t, app, "/copy", map[string]any{
		"source": "hello.txt", "destination": "v.txt", "conflict_policy": "overwrite",
	}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("copy overwrite = %d", rec.Code)
	}
	rec = app.do(t, "GET", "/versions/v.txt", nil, nil, cookies)
	doc := decodeBody(t, rec)
	versions, _ := doc["versions"].([]any)
	if len(versions) != 1 {
		t.Fatalf("versions = %s", rec.Body.String())
	}
	vname, _ := versions[0].(map[string]any)["name"].(string)

	// Restore the version.
	rec = postJSON(t, app, "/versions/restore",
		map[string]any{"version": vname, "target": "v.txt"}, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("version restore = %s", rec.Body.String())
	}
	if data, _ := os.ReadFile(filepath.Join(root, "v.txt")); string(data) != "v1" {
		t.Fatalf("restored content = %q", data)
	}

	// Audit log read + filter.
	rec = app.do(t, "GET", "/api/audit_log?action=version_restore", nil, nil, cookies)
	doc = decodeBody(t, rec)
	logs, _ := doc["logs"].([]any)
	if len(logs) == 0 {
		t.Fatalf("audit filter = %s", rec.Body.String())
	}
	rec = app.do(t, "GET", "/api/audit_log?limit=1", nil, nil, cookies)
	doc = decodeBody(t, rec)
	if logs, _ := doc["logs"].([]any); len(logs) != 1 {
		t.Fatalf("audit limit = %s", rec.Body.String())
	}

	// Audit export CSV with BOM.
	rec = app.do(t, "GET", "/api/audit_log/export", nil, nil, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d", rec.Code)
	}
	body := rec.Body.Bytes()
	if len(body) < 3 || body[0] != 0xEF || body[1] != 0xBB || body[2] != 0xBF {
		t.Fatalf("export missing BOM")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Errorf("export ct = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment; filename=audit_log_") {
		t.Errorf("export cd = %q", cd)
	}

	// Capabilities + disk + folder size.
	rec = app.do(t, "GET", "/api/capabilities", nil, nil, cookies)
	doc = decodeBody(t, rec)
	if doc["hls"] != false || doc["webdav"] != false {
		t.Fatalf("capabilities = %s", rec.Body.String())
	}
	rec = app.do(t, "GET", "/api/disk_info", nil, nil, cookies)
	doc = decodeBody(t, rec)
	for _, k := range []string{"total", "used", "free", "percent", "warning", "total_fmt", "used_fmt", "free_fmt"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("disk_info missing %s: %s", k, rec.Body.String())
		}
	}
	rec = app.do(t, "GET", "/api/disk_status", nil, nil, cookies)
	doc = decodeBody(t, rec)
	for _, k := range []string{"percent", "free", "warning", "threshold"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("disk_status missing %s", k)
		}
	}
	rec = app.do(t, "GET", "/api/folder_size/sub", nil, nil, cookies)
	doc = decodeBody(t, rec)
	if doc["path"] != "sub" || doc["size"] == nil || doc["size_fmt"] == nil {
		t.Fatalf("folder_size = %s", rec.Body.String())
	}
	rec = app.do(t, "GET", "/api/folder_size/hello.txt", nil, nil, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("folder_size file = %d", rec.Code)
	}
}
