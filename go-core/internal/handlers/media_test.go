package handlers

import (
	"archive/zip"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTextGetAndSaveContent(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	rec := app.do(t, "GET", "/get_content/hello.txt", nil, nil, cookies)
	if rec.Code != http.StatusOK || decodeBody(t, rec)["content"] != "content of hello.txt" {
		t.Fatalf("get_content = %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, app, "/save_content/hello.txt", map[string]any{"content": "edited"}, cookies, csrf)
	if rec.Code != http.StatusOK || decodeBody(t, rec)["success"] != true {
		t.Fatalf("save_content = %d %s", rec.Code, rec.Body.String())
	}
	if data, _ := os.ReadFile(filepath.Join(root, "hello.txt")); string(data) != "edited" {
		t.Fatalf("saved = %q", data)
	}
	if rec := app.do(t, "GET", "/get_content/nope.txt", nil, nil, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("missing get_content = %d", rec.Code)
	}

	// Guests without allow_guest_upload cannot save.
	guest := loginAs(t, app, "guestpw")
	rec = postJSON(t, app, "/save_content/hello.txt", map[string]any{"content": "x"}, guest, csrfFor(t, app, guest))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("guest save = %d", rec.Code)
	}
}

func TestStreamServesRangesInline(t *testing.T) {
	app, root := testApp(t)
	if err := os.WriteFile(filepath.Join(root, "song.mp3"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	cookies := loginAs(t, app, "adminpw")
	rec := app.do(t, "GET", "/stream/song.mp3", nil, map[string]string{"Range": "bytes=2-5"}, cookies)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "2345" {
		t.Fatalf("range stream = %d %q", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); strings.HasPrefix(cd, "attachment") {
		t.Fatalf("stream is an attachment: %s", cd)
	}
	if rec := app.do(t, "GET", "/stream/hls/song.mp3/index.m3u8", nil, nil, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("hls on go = %d", rec.Code)
	}
}

func TestPlaylistAndGallery(t *testing.T) {
	app, root := testApp(t)
	for _, name := range []string{"sub/b.mp3", "sub/a.flac", "sub/pic.PNG", "sub/notes.txt"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cookies := loginAs(t, app, "adminpw")
	doc := decodeBody(t, app.do(t, "GET", "/playlist/sub", nil, nil, cookies))
	tracks, _ := doc["tracks"].([]any)
	if len(tracks) != 2 || tracks[0].(map[string]any)["path"] != "sub/a.flac" ||
		tracks[0].(map[string]any)["stream_url"] != "/stream/sub/a.flac" {
		t.Fatalf("playlist = %v", doc)
	}
	doc = decodeBody(t, app.do(t, "GET", "/gallery/sub", nil, nil, cookies))
	if images, _ := doc["images"].([]any); len(images) != 1 {
		t.Fatalf("gallery = %v", doc)
	}
	if rec := app.do(t, "GET", "/gallery/missing", nil, nil, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("missing gallery = %d", rec.Code)
	}
}

func TestPreviewCSVAndDocx(t *testing.T) {
	app, root := testApp(t)
	if err := os.WriteFile(filepath.Join(root, "t.csv"), []byte("a,<b>\n1,2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	docxPath := filepath.Join(root, "d.docx")
	f, err := os.Create(docxPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	wr, _ := zw.Create("word/document.xml")
	wr.Write([]byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Hello</w:t></w:r><w:r><w:t> &lt;World&gt;</w:t></w:r></w:p><w:p></w:p></w:body></w:document>`))
	zw.Close()
	f.Close()

	cookies := loginAs(t, app, "adminpw")
	doc := decodeBody(t, app.do(t, "GET", "/preview/t.csv", nil, nil, cookies))
	if doc["type"] != "html" || !strings.Contains(doc["content"].(string), "<td>&lt;b&gt;</td>") {
		t.Fatalf("csv preview = %v", doc)
	}
	doc = decodeBody(t, app.do(t, "GET", "/preview/d.docx", nil, nil, cookies))
	if doc["content"] != "<p>Hello &lt;World&gt;</p>" {
		t.Fatalf("docx preview = %v", doc)
	}
}

func TestRecentFilesClipboardMetricsDisk(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	app.do(t, "GET", "/download/hello.txt", nil, nil, cookies)
	app.do(t, "GET", "/get_content/sub/nested.md", nil, nil, cookies)
	doc := decodeBody(t, app.do(t, "GET", "/recent_files", nil, nil, cookies))
	recent, _ := doc["files"].([]any)
	if len(recent) != 2 || recent[0].(map[string]any)["path"] != "sub/nested.md" {
		t.Fatalf("recent = %v", doc)
	}

	if rec := postJSON(t, app, "/clipboard", map[string]any{"content": "copied"}, cookies, csrf); rec.Code != http.StatusOK {
		t.Fatalf("clipboard post = %d", rec.Code)
	}
	if doc := decodeBody(t, app.do(t, "GET", "/clipboard", nil, nil, cookies)); doc["content"] != "copied" {
		t.Fatalf("clipboard get = %v", doc)
	}
	big := strings.Repeat("x", maxClipboardBytes+1)
	if rec := postJSON(t, app, "/clipboard", map[string]any{"content": big}, cookies, csrf); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized clipboard = %d", rec.Code)
	}

	doc = decodeBody(t, app.do(t, "GET", "/metrics", nil, nil, cookies))
	if _, ok := doc["uptime"].(string); !ok || doc["active_connections"] == nil {
		t.Fatalf("metrics = %v", doc)
	}
	summary := decodeBody(t, app.do(t, "GET", "/api/dashboard/summary", nil, nil, cookies))
	if _, ok := summary["metrics"].(map[string]any); !ok || summary["disk"] == nil {
		t.Fatalf("dashboard summary = %v", summary)
	}
	for _, path := range []string{"/disk_info", "/disk_status"} {
		if doc := decodeBody(t, app.do(t, "GET", path, nil, nil, cookies)); doc["percent"] == nil {
			t.Fatalf("%s = %v", path, doc)
		}
	}
}
