package handlers

// Full web UI for the Go backend (audit ISSUE-003).
//
// The launcher renders the Jinja templates into static shells
// (webshare_app/server/go_ui.py) and passes their directory (--ui-dir)
// plus the static assets (--static-dir). This file serves them:
//
//   - GET /              → login_<lang>[_error].html
//   - GET /browse/<sub>  → browse_<lang>_<variant>.html with the request's
//     CSRF token and folder substituted; rows load from /api/list
//   - /static/*, /manifest.json, /sw.js, /offline.html
//
// Without --ui-dir the minimal pages in pages.go remain the fallback.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"webshare-core/pkg/api"
)

const (
	uiCSRFPlaceholder = "__WS_CSRF__"
	uiPathPlaceholder = "__WS_PATH_JSON__"
)

type uiAssets struct {
	uiDir     string
	staticDir string
	mu        sync.Mutex
	cache     map[string][]byte
}

// SetUI enables the full web UI. Empty directories keep the fallback.
func (a *App) SetUI(uiDir, staticDir string) {
	a.ui = &uiAssets{uiDir: uiDir, staticDir: staticDir, cache: map[string][]byte{}}
}

// uiFile returns a rendered UI file (cached for the process lifetime: the
// launcher renders before the child starts).
func (a *App) uiFile(name string) ([]byte, bool) {
	ui := a.ui
	if ui == nil || ui.uiDir == "" {
		return nil, false
	}
	ui.mu.Lock()
	defer ui.mu.Unlock()
	if data, ok := ui.cache[name]; ok {
		return data, true
	}
	data, err := os.ReadFile(filepath.Join(ui.uiDir, name))
	if err != nil {
		return nil, false
	}
	ui.cache[name] = data
	return data, true
}

// uiLanguage picks the shell language: session choice, then config.
func (a *App) uiLanguage(s session) string {
	for _, lang := range []string{s.language, a.conf().Language} {
		if lang == "ko" || lang == "en" {
			return lang
		}
	}
	return "ko"
}

func writeHTML(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// serveLoginShell writes the full login page when available.
func (a *App) serveLoginShell(w http.ResponseWriter, s session, failed bool) bool {
	name := "login_" + a.uiLanguage(s)
	if failed {
		name += "_error"
	}
	page, ok := a.uiFile(name + ".html")
	if !ok {
		return false
	}
	writeHTML(w, http.StatusOK, page)
	return true
}

// serveBrowseShell writes the full file-browser page for sub, mirroring
// main.browse: 403/400/404 JSON on access/path errors, files redirect to
// /download/. Returns false when no shell is available.
func (a *App) serveBrowseShell(w http.ResponseWriter, r *http.Request, s session, sub string) bool {
	variant := "guest_ro"
	switch {
	case s.role == "admin":
		variant = "admin"
	case a.conf().AllowGuestUpload:
		variant = "guest_rw"
	}
	page, ok := a.uiFile("browse_" + a.uiLanguage(s) + "_" + variant + ".html")
	if !ok {
		return false
	}
	rel := strings.Trim(sub, "/")
	if !a.checkAccess(w, r, rel, "read") {
		return true
	}
	full, valid := a.validate(w, r, rel)
	if !valid {
		return true
	}
	st, err := os.Stat(full)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "경로를 찾을 수 없습니다"})
		return true
	}
	if !st.IsDir() {
		http.Redirect(w, r, "/download/"+(&url.URL{Path: rel}).EscapedPath(), http.StatusFound)
		return true
	}
	// json.Marshal escapes <, >, & and U+2028/9, so the literal is safe
	// inside the <script> block.
	pathJSON, _ := json.Marshal(rel)
	page = bytes.Replace(page, []byte(uiPathPlaceholder), pathJSON, 1)
	page = bytes.ReplaceAll(page, []byte(uiCSRFPlaceholder), []byte(htmlAttrSafe(s.csrf)))
	writeHTML(w, http.StatusOK, page)
	return true
}

// htmlAttrSafe keeps only token characters (hex/urlsafe) so a token can
// never break out of the attribute it is substituted into.
func htmlAttrSafe(token string) string {
	var sb strings.Builder
	for _, c := range token {
		if c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// noDirFS hides directory listings from the static file server.
type noDirFS struct{ fs http.FileSystem }

func (n noDirFS) Open(name string) (http.File, error) {
	f, err := n.fs.Open(name)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.IsDir() {
		f.Close()
		return nil, os.ErrNotExist
	}
	return f, nil
}

func (a *App) registerUIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/static/", a.handleStatic)
	mux.HandleFunc("/manifest.json", a.uiFileHandler("manifest.json", "application/manifest+json", ""))
	mux.HandleFunc("/sw.js", a.uiFileHandler("sw.js", "application/javascript", "no-cache, no-store, must-revalidate"))
	mux.HandleFunc("/offline.html", a.uiFileHandler("offline.html", "text/html; charset=utf-8", "public, max-age=86400"))
}

// handleStatic serves --static-dir publicly like Flask's static route.
func (a *App) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, r)
		return
	}
	if a.ui == nil || a.ui.staticDir == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	http.StripPrefix("/static/", http.FileServer(noDirFS{http.Dir(a.ui.staticDir)})).ServeHTTP(w, r)
}

func (a *App) uiFileHandler(name, contentType, cacheControl string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, r)
			return
		}
		data, ok := a.uiFile(name)
		if !ok {
			api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
			return
		}
		w.Header().Set("Content-Type", contentType)
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	}
}
