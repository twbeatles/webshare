package handlers

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createShare(t *testing.T, app *App, cookies []*http.Cookie, csrf string, doc map[string]any) map[string]any {
	t.Helper()
	rec := postJSON(t, app, "/share/create", doc, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("create = %d (%s)", rec.Code, rec.Body.String())
	}
	return decodeBody(t, rec)
}

func TestShareFileCycle(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	created := createShare(t, app, cookies, csrf, map[string]any{
		"path": "hello.txt", "hours": 24,
	})
	token, _ := created["token"].(string)
	if token == "" || created["link"] != "/share/"+token {
		t.Fatalf("create body = %s", toJSON(created))
	}

	// Public access without login.
	rec := app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("access = %d (%s)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "content of hello.txt" {
		t.Fatalf("access body = %q", rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != "attachment; filename=hello.txt" {
		t.Errorf("disposition = %q", cd)
	}

	// Inline preview.
	rec = app.do(t, "GET", "/share/"+token+"?inline=1", nil, nil, nil)
	if !strings.HasPrefix(rec.Header().Get("Content-Disposition"), "inline") {
		t.Errorf("inline disposition = %q", rec.Header().Get("Content-Disposition"))
	}

	// List shows the link.
	rec = app.do(t, "GET", "/share/list", nil, nil, cookies)
	doc := decodeBody(t, rec)
	links, _ := doc["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("list = %s", rec.Body.String())
	}

	// Delete then access fails.
	rec = postJSON(t, app, "/share/delete/"+token, nil, cookies, csrf)
	if doc := decodeBody(t, rec); doc["success"] != true {
		t.Fatalf("delete = %s", rec.Body.String())
	}
	rec = app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("access-after-delete = %d", rec.Code)
	}

	// Create validation.
	rec = postJSON(t, app, "/share/create", map[string]any{"path": "hello.txt", "hours": 0}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("hours=0 = %d", rec.Code)
	}
	rec = postJSON(t, app, "/share/create", map[string]any{"path": "missing.txt"}, cookies, csrf)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing path = %d", rec.Code)
	}
	_ = root
}

func TestSharePasswordAndLimits(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	created := createShare(t, app, cookies, csrf, map[string]any{
		"path": "hello.txt", "hours": 1, "password": "s3cret", "max_downloads": 1,
	})
	token, _ := created["token"].(string)
	if created["has_password"] != true {
		t.Fatalf("has_password = %s", toJSON(created))
	}

	// No password → 401 challenge.
	rec := app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("challenge = %d", rec.Code)
	}

	// Wrong password → 401.
	form := url.Values{"password": {"nope"}}.Encode()
	rec = app.do(t, "POST", "/share/"+token, strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong pw = %d (%s)", rec.Code, rec.Body.String())
	}

	// Correct password downloads.
	form = url.Values{"password": {"s3cret"}}.Encode()
	rec = app.do(t, "POST", "/share/"+token, strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "content of hello.txt" {
		t.Fatalf("correct pw = %d (%s)", rec.Code, rec.Body.String())
	}

	// max_downloads=1 exhausted → 429.
	rec = app.do(t, "POST", "/share/"+token, strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("exhausted = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestShareDirZipAndPersist(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	created := createShare(t, app, cookies, csrf, map[string]any{"path": "sub", "hours": 24})
	token, _ := created["token"].(string)
	rec := app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("dir access = %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("zip content-type = %q", ct)
	}
	if len(rec.Body.Bytes()) == 0 {
		t.Errorf("empty zip body")
	}

	// Links persisted; a fresh store loads them.
	data, err := os.ReadFile(filepath.Join(root, ".webshare_share_links.json"))
	if err != nil {
		t.Fatalf("links file: %v", err)
	}
	if !strings.Contains(string(data), token) {
		t.Fatalf("links file missing token: %s", data)
	}
}
