package handlers

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uiTestApp wires a fake rendered-UI directory (same placeholders as
// webshare_app/server/go_ui.py) and a static dir into a test app.
func uiTestApp(t *testing.T) (*App, string) {
	t.Helper()
	app, root := testApp(t)
	uiDir := t.TempDir()
	staticDir := t.TempDir()
	shell := `<meta name="csrf-token" content="__WS_CSRF__"><script>window.CURRENT_PATH = __WS_PATH_JSON__;</script>VARIANT`
	for _, lang := range []string{"ko", "en"} {
		for _, variant := range []string{"admin", "guest_rw", "guest_ro"} {
			page := strings.Replace(shell, "VARIANT", lang+"/"+variant, 1)
			if err := os.WriteFile(filepath.Join(uiDir, "browse_"+lang+"_"+variant+".html"), []byte(page), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		os.WriteFile(filepath.Join(uiDir, "login_"+lang+".html"), []byte("LOGIN "+lang), 0o644)
		os.WriteFile(filepath.Join(uiDir, "login_"+lang+"_error.html"), []byte("LOGIN-ERROR "+lang), 0o644)
	}
	os.WriteFile(filepath.Join(uiDir, "manifest.json"), []byte(`{"name":"WebShare Pro"}`), 0o644)
	os.MkdirAll(filepath.Join(staticDir, "css"), 0o755)
	os.WriteFile(filepath.Join(staticDir, "css", "app.css"), []byte("body{}"), 0o644)
	app.SetUI(uiDir, staticDir)
	return app, root
}

var browserHTML = map[string]string{"Accept": "text/html"}

func TestUILoginAndBrowseShells(t *testing.T) {
	app, root := uiTestApp(t)
	if rec := app.do(t, "GET", "/", nil, browserHTML, nil); rec.Code != http.StatusOK || rec.Body.String() != "LOGIN ko" {
		t.Fatalf("login page = %d %q", rec.Code, rec.Body.String())
	}
	form := url.Values{"password": {"wrong"}}.Encode()
	rec := app.do(t, "POST", "/", strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html"}, nil)
	if rec.Body.String() != "LOGIN-ERROR ko" {
		t.Fatalf("failed login page = %q", rec.Body.String())
	}

	if err := os.MkdirAll(filepath.Join(root, "C# docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)
	rec = app.do(t, "GET", "/browse/C%23%20docs", nil, browserHTML, cookies)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `window.CURRENT_PATH = "C# docs";`) ||
		!strings.Contains(body, `content="`+csrf+`"`) || !strings.Contains(body, "ko/admin") || strings.Contains(body, "__WS_") {
		t.Fatalf("browse shell = %d %q", rec.Code, body)
	}

	guest := loginAs(t, app, "guestpw")
	if body := app.do(t, "GET", "/browse/", nil, browserHTML, guest).Body.String(); !strings.Contains(body, "ko/guest_ro") {
		t.Fatalf("guest shell = %q", body)
	}
}

// A folder name cannot break out of the script literal.
func TestUIBrowseShellEscapesPath(t *testing.T) {
	app, root := uiTestApp(t)
	// Legal on every OS: & must be JSON-escaped (&) inside <script>.
	if err := os.MkdirAll(filepath.Join(root, "a&b"), 0o755); err != nil {
		t.Fatal(err)
	}
	admin := loginAs(t, app, "adminpw")
	if body := app.do(t, "GET", "/browse/a%26b", nil, browserHTML, admin).Body.String(); !strings.Contains(body, `"a` + string(rune(92)) + `u0026b"`) {
		t.Fatalf("ampersand not escaped: %q", body)
	}
	name := "x</script><b>"
	if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
		t.Skipf("filesystem rejects %q: %v", name, err)
	}
	cookies := loginAs(t, app, "adminpw")
	body := app.do(t, "GET", "/browse/"+url.PathEscape(name), nil, browserHTML, cookies).Body.String()
	if strings.Contains(body, "</script><b>") {
		t.Fatalf("unescaped path in shell: %q", body)
	}
}

func TestUIBrowseShellErrorsAndFileRedirect(t *testing.T) {
	app, _ := uiTestApp(t)
	cookies := loginAs(t, app, "adminpw")
	if rec := app.do(t, "GET", "/browse/missing", nil, browserHTML, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("missing folder = %d", rec.Code)
	}
	rec := app.do(t, "GET", "/browse/hello.txt", nil, browserHTML, cookies)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/download/hello.txt" {
		t.Fatalf("file browse = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := app.do(t, "GET", "/browse/../../etc", nil, browserHTML, cookies); rec.Code == http.StatusOK {
		t.Fatalf("traversal served a shell")
	}
}

func TestUIStaticAndPWAFiles(t *testing.T) {
	app, _ := uiTestApp(t)
	if rec := app.do(t, "GET", "/static/css/app.css", nil, nil, nil); rec.Code != http.StatusOK || rec.Body.String() != "body{}" {
		t.Fatalf("static = %d %q", rec.Code, rec.Body.String())
	}
	if rec := app.do(t, "GET", "/static/css/", nil, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("static dir listing = %d", rec.Code)
	}
	if rec := app.do(t, "GET", "/manifest.json", nil, nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("manifest = %d", rec.Code)
	}
	if rec := app.do(t, "GET", "/sw.js", nil, nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("missing sw.js = %d", rec.Code)
	}
}

// Without SetUI the minimal standalone pages remain the fallback.
func TestUIFallbackWithoutRenderedShells(t *testing.T) {
	app, _ := testApp(t)
	body := app.do(t, "GET", "/", nil, browserHTML, nil).Body.String()
	if !strings.Contains(body, `<form method="post" action="/">`) {
		t.Fatalf("fallback login = %q", body)
	}
}
