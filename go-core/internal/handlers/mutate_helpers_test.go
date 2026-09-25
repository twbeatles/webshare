package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"webshare-core/internal/auth"
)

// csrfFor decodes the session cookie to fetch the CSRF token like a browser
// holding the login session would.
func csrfFor(t *testing.T, app *App, cookies []*http.Cookie) string {
	t.Helper()
	raw := ""
	for _, c := range cookies {
		if c.Name == auth.CookieName {
			raw = c.Value
		}
	}
	if raw == "" {
		t.Fatal("no session cookie")
	}
	perm := auth.FlaskPermanentLifetime
	payload, err := app.Codec.Verify(raw, &perm, time.Now())
	if err != nil {
		t.Fatalf("verify session: %v", err)
	}
	token, _ := payload["_csrf_token"].(string)
	if token == "" {
		t.Fatal("no csrf token in session")
	}
	return token
}

func postJSON(t *testing.T, app *App, path string, doc map[string]any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var body strings.Reader
	if doc != nil {
		raw, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		body = *strings.NewReader(string(raw))
	} else {
		body = *strings.NewReader("")
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if csrf != "" {
		headers["X-CSRF-Token"] = csrf
	}
	return app.do(t, "POST", path, &body, headers, cookies)
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("bad json %q: %v", rec.Body.String(), err)
	}
	return doc
}
