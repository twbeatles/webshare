package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func postMultipart(t *testing.T, app *App, path string, fields map[string]string, files map[string]filePart, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for field, fp := range files {
		fw, err := w.CreateFormFile(field, fp.filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(fp.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"Content-Type": w.FormDataContentType()}
	if csrf != "" {
		headers["X-CSRF-Token"] = csrf
	}
	return app.do(t, "POST", path, &buf, headers, cookies)
}

type filePart struct {
	filename string
	content  []byte
}

func TestSimpleUpload(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	// No file part → 400.
	rec := postMultipart(t, app, "/upload/", nil, nil, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("nofile = %d (%s)", rec.Code, rec.Body.String())
	}

	// Happy path with folder path.
	rec = postMultipart(t, app, "/upload/", map[string]string{"paths": "pkg/a.txt"},
		map[string]filePart{"file": {"../../evil.txt", []byte("hello upload")}}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload = %d (%s)", rec.Code, rec.Body.String())
	}
	doc := decodeBody(t, rec)
	if doc["success"] != true {
		t.Fatalf("upload body = %s", rec.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "pkg", "a.txt"))
	if err != nil || string(data) != "hello upload" {
		t.Fatalf("uploaded = %q, err=%v", data, err)
	}

	// Same name again → renamed, not overwritten.
	rec = postMultipart(t, app, "/upload/", map[string]string{"paths": "pkg/a.txt"},
		map[string]filePart{"file": {"a.txt", []byte("second")}}, cookies, csrf)
	doc = decodeBody(t, rec)
	filesList, _ := doc["files"].([]any)
	if len(filesList) != 1 {
		t.Fatalf("files = %s", rec.Body.String())
	}
	entry, _ := filesList[0].(map[string]any)
	if entry["name"] != "a_1.txt" || entry["success"] != true {
		t.Fatalf("rename entry = %v", entry)
	}

	// Guest denied.
	guest := loginAs(t, app, "guestpw")
	gcsrf := csrfFor(t, app, guest)
	rec = postMultipart(t, app, "/upload/", nil,
		map[string]filePart{"file": {"g.txt", []byte("x")}}, guest, gcsrf)
	if rec.Code != http.StatusForbidden {
		t.Errorf("guest upload = %d", rec.Code)
	}
}

func TestChunkUploadCycle(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	payload := []byte(strings.Repeat("0123456789abcdef", 64)) // 1024 bytes
	total := int64(len(payload))

	// Init validation: missing filename.
	rec := postJSON(t, app, "/upload/chunk/init", map[string]any{"total_size": total}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("init nofilename = %d", rec.Code)
	}

	// Init happy path.
	rec = postJSON(t, app, "/upload/chunk/init", map[string]any{
		"filename": "big.bin", "total_size": total, "chunk_size": 256, "path": "",
	}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("init = %d (%s)", rec.Code, rec.Body.String())
	}
	doc := decodeBody(t, rec)
	sid, _ := doc["session_id"].(string)
	if sid == "" || doc["total_chunks"] != float64(4) {
		t.Fatalf("init body = %s", rec.Body.String())
	}

	// Transfer 4 chunks.
	for i := 0; i < 4; i++ {
		rec = postMultipart(t, app, "/upload/chunk/"+sid,
			map[string]string{"index": itoa(i)},
			map[string]filePart{"chunk": {"c", payload[i*256 : (i+1)*256]}}, cookies, csrf)
		if rec.Code != http.StatusOK {
			t.Fatalf("chunk %d = %d (%s)", i, rec.Code, rec.Body.String())
		}
	}

	// Out-of-range index → 400.
	rec = postMultipart(t, app, "/upload/chunk/"+sid,
		map[string]string{"index": "9"},
		map[string]filePart{"chunk": {"c", []byte("x")}}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oob index = %d", rec.Code)
	}

	// Complete.
	rec = postJSON(t, app, "/upload/chunk/"+sid+"/complete", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete = %d (%s)", rec.Code, rec.Body.String())
	}
	doc = decodeBody(t, rec)
	if doc["success"] != true || doc["filename"] != "big.bin" {
		t.Fatalf("complete body = %s", rec.Body.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "big.bin"))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("merged mismatch: len=%d err=%v", len(data), err)
	}

	// Idempotent re-complete.
	rec = postJSON(t, app, "/upload/chunk/"+sid+"/complete", nil, cookies, csrf)
	doc = decodeBody(t, rec)
	if rec.Code != http.StatusOK || doc["idempotent"] != true {
		t.Fatalf("re-complete = %d %s", rec.Code, rec.Body.String())
	}

	// Unknown session → 400.
	rec = postJSON(t, app, "/upload/chunk/nope/complete", nil, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unknown complete = %d", rec.Code)
	}

	// Cancel unknown → success:true.
	rec = postJSON(t, app, "/upload/chunk/nope/cancel", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Errorf("cancel unknown = %d", rec.Code)
	}

	// Cancel live session removes temp dir.
	rec = postJSON(t, app, "/upload/chunk/init", map[string]any{
		"filename": "tmp.bin", "total_size": 10, "path": "",
	}, cookies, csrf)
	doc = decodeBody(t, rec)
	sid2, _ := doc["session_id"].(string)
	rec = postJSON(t, app, "/upload/chunk/"+sid2+"/cancel", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel = %d", rec.Code)
	}
	rec = postJSON(t, app, "/upload/chunk/"+sid2+"/complete", nil, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("complete-after-cancel = %d", rec.Code)
	}
}
