package handlers

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Real-browser navigation Accept header (curl/fetch send */* or
// application/json and must keep the JSON contract).
const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func TestRootBrowserGetsLoginHTML(t *testing.T) {
	app, _ := testApp(t)
	// API-style callers keep the exact 401 JSON contract.
	apiCases := map[string]map[string]string{
		"bare":        nil,
		"json-accept": {"Accept": "application/json"},
		"xhr":         {"Accept": browserAccept, "X-Requested-With": "XMLHttpRequest"},
	}
	for name, headers := range apiCases {
		rec := app.do(t, "GET", "/", nil, headers, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: GET / = %d, want 401", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"code":"UNAUTHORIZED"`) {
			t.Fatalf("%s: body lost JSON shape: %s", name, rec.Body.String())
		}
	}
	// Browser navigation gets the login form (ISSUE-006).
	rec := app.do(t, "GET", "/", nil, map[string]string{"Accept": browserAccept}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("browser GET / = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `<form method="post" action="/">`) || !strings.Contains(body, `name="password"`) {
		t.Fatalf("login form missing: %.120s", body)
	}
	// A logged-in browser still redirects to the file browser.
	cookies := loginAs(t, app, "adminpw")
	rec = app.do(t, "GET", "/", nil, map[string]string{"Accept": browserAccept}, cookies)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/browse/" {
		t.Fatalf("authed GET / = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestBrowserLoginFailureRerendersForm(t *testing.T) {
	app, _ := testApp(t)
	form := strings.NewReader(url.Values{"password": {"nope"}}.Encode())
	rec := app.do(t, "POST", "/", form, map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       browserAccept,
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("browser bad login = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "비밀번호가 올바르지 않습니다") || !strings.Contains(body, `<form method="post" action="/">`) {
		t.Fatalf("error form missing: %.160s", body)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("failed login must not set a session cookie")
	}
}

func TestBrowseShellAndAnonHandling(t *testing.T) {
	app, _ := testApp(t)
	browser := map[string]string{"Accept": browserAccept}
	jsonAPI := map[string]string{"X-Requested-With": "XMLHttpRequest"}

	// Anonymous browser navigation redirects to login (Python parity).
	rec := app.do(t, "GET", "/browse/", nil, browser, nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("anon browser browse = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// Anonymous API callers keep 401 JSON.
	rec = app.do(t, "GET", "/browse/", nil, jsonAPI, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon api browse = %d, want 401", rec.Code)
	}
	cookies := loginAs(t, app, "adminpw")
	// Missing trailing slash redirects like Flask strict_slashes.
	rec = app.do(t, "GET", "/browse", nil, nil, cookies)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/browse/" {
		t.Fatalf("bare /browse = %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	// Authenticated browsers get the shell wired to the list API.
	rec = app.do(t, "GET", "/browse/sub", nil, browser, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed browse = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`/api/list/`, `"sub":"sub"`, `"role":"admin"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("browse shell missing %q", want)
		}
	}
	// A hostile subpath must not break out of the bootstrap script block:
	// encoding/json escapes < to \u003c, so no literal </script> from data
	// may appear (the <\/ belt-and-braces replace in writeBrowseHTML stays
	// as defense if escaping is ever disabled).
	rec = app.do(t, "GET", "/browse/a%3C/script%3E", nil, browser, cookies)
	body = rec.Body.String()
	if !strings.Contains(body, `a\u003c/script\u003e`) {
		t.Fatalf("script escape missing: %.200s", body)
	}
	if n := strings.Count(body, "</script>"); n != 2 {
		t.Fatalf("</script> count = %d, want 2 (boot close + page script close)", n)
	}
}
