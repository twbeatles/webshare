package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"webshare-core/internal/config"
)

func testApp(t *testing.T) (*App, string) {
	t.Helper()
	root := t.TempDir()
	for _, rel := range []string{"hello.txt", "sub/nested.md"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content of "+rel), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Defaults()
	cfg.Folder = root
	cfg.AdminPw = "adminpw"
	cfg.GuestPw = "guestpw"
	cfg.SecretKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.SessionTimeout = 60
	app := New(cfg, filepath.Join(root, "cfg.json"))
	mux := http.NewServeMux()
	app.RegisterRoutes(mux)
	app.mux = mux
	return app, root
}

func (a *App) do(t *testing.T, method, path string, body io.Reader, headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	a.mux.ServeHTTP(rec, req)
	return rec
}

func loginAs(t *testing.T, app *App, password string) []*http.Cookie {
	t.Helper()
	form := url.Values{"password": {password}}.Encode()
	rec := app.do(t, "POST", "/", strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d (%s)", rec.Code, rec.Body.String())
	}
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie")
	}
	return cookies
}

func TestLoginLogoutFlow(t *testing.T) {
	app, _ := testApp(t)
	// Wrong password.
	rec := app.do(t, "POST", "/", strings.NewReader(url.Values{"password": {"nope"}}.Encode()),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", rec.Code)
	}
	// Admin login then list.
	cookies := loginAs(t, app, "adminpw")
	rec = app.do(t, "GET", "/api/list/", nil, nil, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "hello.txt") {
		t.Errorf("list missing file: %s", rec.Body.String())
	}
	// Logout kills the cookie.
	rec = app.do(t, "GET", "/logout", nil, nil, cookies)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout = %d", rec.Code)
	}
	// Unauthenticated browser request redirects; API request 401s.
	rec = app.do(t, "GET", "/download/hello.txt", nil, nil, nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("anon browser download = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	rec = app.do(t, "GET", "/api/list/", nil, nil, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anon api list = %d", rec.Code)
	}
}

func TestDownloadAndRange(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "guestpw")
	rec := app.do(t, "GET", "/download/hello.txt", nil, nil, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("download = %d", rec.Code)
	}
	if rec.Body.String() != "content of hello.txt" {
		t.Errorf("download body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename=hello.txt` {
		t.Errorf("disposition = %q", cd)
	}
	rec = app.do(t, "GET", "/download/hello.txt", nil, map[string]string{"Range": "bytes=0-6"}, cookies)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "content" {
		t.Errorf("range = %d %q cr=%q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Range"))
	}
	rec = app.do(t, "GET", "/download/hello.txt", nil, map[string]string{"Range": "bytes=99999-"}, cookies)
	if rec.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("bad range = %d", rec.Code)
	}
	rec = app.do(t, "GET", "/download/sub", nil, nil, cookies)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("dir download = %d", rec.Code)
	}
}

func TestQuota429Mapping(t *testing.T) {
	app, _ := testApp(t)
	app.Config.DailyDownloadLimit = 1
	cookies := loginAs(t, app, "adminpw")
	rec := app.do(t, "GET", "/download/hello.txt", nil, nil, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("first download = %d", rec.Code)
	}
	rec = app.do(t, "GET", "/download/hello.txt", nil, nil, cookies)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second download = %d, want 429", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Daily download limit exceeded (1)") {
		t.Errorf("quota body = %s", rec.Body.String())
	}
}

func TestCSRFEnforced(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	// batch_download without token → 403.
	form := url.Values{"files": {`["hello.txt"]`}}.Encode()
	rec := app.do(t, "POST", "/batch_download/", strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, cookies)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-csrf batch = %d", rec.Code)
	}
}
