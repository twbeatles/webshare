package handlers

import (
	"net/http"
	"net/http/httptest"
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

	// No password, plain browser GET → 200 HTML password form (ISSUE-005,
	// parity with share_password.html).
	rec := app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge = %d", rec.Code)
	}
	assertShareHTML(t, rec, "password")

	// No password, explicit JSON caller → 401 need_password shape.
	rec = app.do(t, "GET", "/share/"+token, nil,
		map[string]string{"Accept": "application/json"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("json challenge = %d", rec.Code)
	}
	if doc := decodeBody(t, rec); doc["need_password"] != true {
		t.Fatalf("json challenge body = %s", rec.Body.String())
	}

	// Wrong password via browser form → 200 HTML form with error.
	form := url.Values{"password": {"nope"}}.Encode()
	rec = app.do(t, "POST", "/share/"+token, strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("wrong pw = %d (%s)", rec.Code, rec.Body.String())
	}
	assertShareHTML(t, rec, "password")
	if !strings.Contains(rec.Body.String(), "올바르지 않습니다") {
		t.Errorf("wrong pw page missing error: %s", rec.Body.String())
	}

	// Wrong password via JSON API → 401 JSON error.
	rec = app.do(t, "POST", "/share/"+token, strings.NewReader(`{"password":"nope"}`),
		map[string]string{"Content-Type": "application/json"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("json wrong pw = %d (%s)", rec.Code, rec.Body.String())
	}
	if doc := decodeBody(t, rec); doc["success"] != false {
		t.Fatalf("json wrong pw body = %s", rec.Body.String())
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

// assertShareHTML checks the minimal share HTML page shape (ISSUE-005).
func assertShareHTML(t *testing.T, rec *httptest.ResponseRecorder, form string) {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if form == "password" && !strings.Contains(body, "<form method=\"post\">") {
		t.Fatalf("password page missing form: %.120s", body)
	}
}

// TestShareHTMLNegotiation covers the browser/API split for every
// share-access failure branch (ISSUE-005): browsers get text/html pages,
// API callers (Accept/X-Requested-With/?format=json) keep JSON.
func TestShareHTMLNegotiation(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)

	created := createShare(t, app, cookies, csrf, map[string]any{
		"path": "hello.txt", "hours": 1, "password": "s3cret",
	})
	token, _ := created["token"].(string)

	jsonHeaders := []map[string]string{
		{"Accept": "application/json"},
		{"X-Requested-With": "XMLHttpRequest"},
	}
	for _, h := range jsonHeaders {
		rec := app.do(t, "GET", "/share/"+token, nil, h, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("json challenge %v = %d", h, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("json challenge %v content-type = %q", h, ct)
		}
	}
	// ?format=json also selects JSON.
	rec := app.do(t, "GET", "/share/"+token+"?format=json", nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("format=json challenge = %d", rec.Code)
	}

	// Unknown token: HTML 404 for browsers, JSON 404 for API.
	rec = app.do(t, "GET", "/share/no-such-token", nil, nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing token = %d", rec.Code)
	}
	assertShareHTML(t, rec, "expired")
	rec = app.do(t, "GET", "/share/no-such-token", nil,
		map[string]string{"Accept": "application/json"}, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("json missing token = %d", rec.Code)
	}
	if doc := decodeBody(t, rec); doc["success"] != false {
		t.Fatalf("json missing token body = %s", rec.Body.String())
	}

	// Brute-force block: 5 wrong attempts, then the 6th is blocked.
	// Use JSON callers so the HTML form assertions below stay on a
	// deterministic attempt count.
	badJSON := strings.NewReader(`{"password":"nope"}`)
	for i := 0; i < 5; i++ {
		rec = app.do(t, "POST", "/share/"+token, badJSON,
			map[string]string{"Content-Type": "application/json"}, nil)
		_ = rec
		badJSON = strings.NewReader(`{"password":"nope"}`)
	}
	rec = app.do(t, "GET", "/share/"+token, nil, nil, nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("blocked = %d (%s)", rec.Code, rec.Body.String())
	}
	assertShareHTML(t, rec, "password")
	if !strings.Contains(rec.Body.String(), "차단되었습니다") {
		t.Errorf("blocked page missing message: %.200s", rec.Body.String())
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
