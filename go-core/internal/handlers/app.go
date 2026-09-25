// Package handlers implements Milestone C user routes: login/logout,
// language, directory listing, file info, download with ranges, ZIP,
// batch download, ZIP preview, and bounded fallback search.
//
// Every route mirrors its Flask counterpart's status codes, JSON shapes,
// and header contract. HTML page routes (/, /browse/) are deferred to the
// template port: GET / redirects authenticated browsers like Python and
// answers 401 JSON otherwise; failed logins answer 401 JSON instead of the
// re-rendered login page.
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"webshare-core/internal/audit"
	"webshare-core/internal/auth"
	"webshare-core/internal/config"
	"webshare-core/internal/permission"
	"webshare-core/internal/meta"
	"webshare-core/internal/quota"
	"webshare-core/internal/share"
	"webshare-core/internal/upload"
	"webshare-core/pkg/api"
)

// App holds all request-scoped state (explicit lock scopes per structure,
// never one global mutex).
type App struct {
	Config     config.Config
	ConfigPath string
	Codec      auth.FlaskCodec
	Perms      *permission.Store
	Sessions   *auth.SessionStore
	Blocks     *auth.BlockTracker
	Quota      *quota.Tracker
	Audit      *audit.Log
	Uploads    *upload.Store
	Shares     *share.Store
	Meta       *meta.Store
	mu         sync.Mutex // guards Config mutation (password rehash)
	auditMu    sync.Mutex // guards auditLastFlush
	now        func() time.Time
	auditLastFlush time.Time
	mux        *http.ServeMux // set by RegisterRoutes caller in tests
}

// New builds the app. The codec secret must already be ensured by the caller.
func New(cfg config.Config, cfgPath string) *App {
	// Canonicalize once: every validated request path is in EvalSymlinks
	// form, so the stored root must be too — otherwise the lexical
	// filepath.Rel(root, validated) calls in trash/versions/copy/batch/
	// upload handlers produce ".."-laden garbage on machines where the
	// configured string differs from the on-disk form (CI runners).
	cfg.Folder = permission.CanonicalRoot(cfg.Folder)
	auditLog := audit.NewLog(cfg.Folder)
	auditLog.Load()
	blocks := auth.NewBlockTracker()
	blocks.SetPersistence(cfg.Folder)
	tracker := quota.NewTracker()
	tracker.SetPersistence(cfg.Folder)
	return &App{
		Config:     cfg,
		ConfigPath: cfgPath,
		Codec:      auth.FlaskCodec{Secret: cfg.SecretKey, Salt: auth.SessionCookieSalt},
		Perms:      permission.NewStore(cfg.Folder),
		Sessions:   auth.NewSessionStore(),
		Blocks:     blocks,
		Quota:      tracker,
		Audit:      auditLog,
		Uploads:    upload.NewStore(),
		Shares:     share.NewStore(cfg.Folder),
		Meta:       meta.NewStore(cfg.Folder),
		now:        time.Now,
	}
}

// FlushState persists dirty runtime state at shutdown (mirrors
// flush_runtime_state_if_dirty(force=True) plus audit/share flushes).
func (a *App) FlushState() {
	if a.Blocks != nil {
		a.Blocks.Flush()
	}
	if a.Quota != nil {
		a.Quota.Flush()
	}
	if a.Shares != nil {
		a.Shares.FlushAttempts()
	}
	if a.Audit != nil {
		_ = a.Audit.Save()
	}
}

// audit mirrors log_audit: in-memory append plus throttled persistence
// (flush_audit_log_if_dirty, min 5s interval).
func (a *App) audit(user, action, target, details string, r *http.Request) {
	if a.Audit == nil {
		return
	}
	a.Audit.Add(user, action, target, details, "success", a.clientIP(r))
	a.auditMu.Lock()
	defer a.auditMu.Unlock()
	if a.now().Sub(a.auditLastFlush) < 5*time.Second {
		return
	}
	if err := a.Audit.Save(); err == nil {
		a.auditLastFlush = a.now()
	}
}

// session holds the authenticated request identity.
type session struct {
	loggedIn   bool
	expired    bool
	role       string
	sid        string
	lastActive float64
	language   string
	csrf       string
	payload    map[string]any
}

type ctxKey struct{}

// SessionOf returns the request session (anonymous when absent).
func SessionOf(r *http.Request) session {
	s, _ := r.Context().Value(ctxKey{}).(session)
	return s
}

func withSession(r *http.Request, s session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, s))
}

// readAndRestoreBody reads a JSON body for CSRF inspection and restores it
// for the downstream handler.
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

// RegisterRoutes mounts user routes on mux.
func (a *App) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleRoot)
	mux.HandleFunc("/logout", a.requireAuth(a.handleLogout, false))
	mux.HandleFunc("/set_language", a.requireAuth(a.handleSetLanguage, false))
	mux.HandleFunc("/set_language/", a.handleSetLanguageLegacy)
	mux.HandleFunc("/api/list/", a.requireAuth(a.handleList, false))
	mux.HandleFunc("/api/list", a.requireAuth(a.handleList, false))
	mux.HandleFunc("/file_info/", a.requireAuth(a.handleFileInfo, false))
	mux.HandleFunc("/download/", a.requireAuth(a.handleDownload, false))
	mux.HandleFunc("/zip/", a.requireAuth(a.handleZip, false))
	mux.HandleFunc("/batch_download/", a.requireAuth(a.handleBatchDownload, false))
	mux.HandleFunc("/api/zip_preview/", a.requireAuth(a.handleZipPreview, false))
	mux.HandleFunc("/search", a.requireAuth(a.handleSearch, false))
	a.registerMutationRoutes(mux)
	a.registerUploadRoutes(mux)
	a.registerShareRoutes(mux)
	a.registerExtrasRoutes(mux)
}

// gate runs IP policy for every wrapped request.
func (a *App) gate(w http.ResponseWriter, r *http.Request) (remoteIP string, ok bool) {
	remoteIP = a.clientIP(r)
	if !auth.Whitelisted(remoteIP, a.Config.IPWhitelist) {
		api.Error(w, r, http.StatusForbidden, "ip_blocked")
		return "", false
	}
	if blocked, remaining := a.Blocks.Blocked(remoteIP); blocked {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(api.Normalize(map[string]any{
			"error": "IP 차단됨 (남은 시간: " + itoa(remaining) + "분)",
			"code":  "IP_BLOCKED",
		}, http.StatusForbidden, api.RequestID(r)))
		return "", false
	}
	return remoteIP, true
}

// loadSession verifies the cookie and enforces the idle timeout.
func (a *App) loadSession(w http.ResponseWriter, r *http.Request) session {
	var s session
	raw := auth.SessionCookie(r)
	if raw == "" {
		return s
	}
	perm := auth.FlaskPermanentLifetime
	payload, err := a.Codec.Verify(raw, &perm, a.now())
	if err != nil {
		return s
	}
	loggedIn, _ := payload["logged_in"].(bool)
	if !loggedIn {
		return s
	}
	role, _ := payload["role"].(string)
	sid, _ := payload["session_id"].(string)
	lastActive, _ := payload["last_active"].(float64)
	lang, _ := payload["language"].(string)
	csrf, _ := payload["_csrf_token"].(string)
	if lang == "" {
		lang = a.Config.Language
	}
	// Parity with factory: no last_active yet (fresh login) skips the check.
	if lastActive > 0 && auth.SessionExpired(lastActive, a.Config.SessionTimeout, float64(a.now().Unix())) {
		// Drop server record, clear cookie, force login.
		if sid != "" {
			a.Sessions.Remove(sid)
		}
		auth.ClearSessionCookie(w, a.Config.UseHTTPS)
		s.expired = true
		return s
	}
	s = session{loggedIn: true, role: role, sid: sid, lastActive: lastActive, language: lang, csrf: csrf, payload: payload}
	return s
}

// refreshSession bumps last_active and re-emits the cookie (Flask marks the
// session modified on every authenticated request).
func (a *App) refreshSession(w http.ResponseWriter, s *session) {
	payload := map[string]any{}
	for k, v := range s.payload {
		payload[k] = v
	}
	payload["last_active"] = float64(a.now().Unix())
	if s.sid != "" {
		a.Sessions.Touch(s.sid)
	}
	if cookie, err := a.Codec.Sign(payload); err == nil {
		auth.SetSessionCookie(w, cookie, a.Config.UseHTTPS)
	}
	s.payload = payload
}

// requireAuth wraps handlers with IP gates, session load/timeout,
// login-required (401 JSON for API/AJAX, redirect otherwise), optional
// admin role, and CSRF for state-changing methods.
func (a *App) requireAuth(next func(http.ResponseWriter, *http.Request), adminOnly bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		remoteIP, ok := a.gate(w, r)
		if !ok {
			return
		}
		_ = remoteIP
		s := a.loadSession(w, r)
		if s.expired {
			a.denyUnauthenticated(w, r)
			return
		}
		if !s.loggedIn {
			a.denyUnauthenticated(w, r)
			return
		}
		if adminOnly && s.role != "admin" {
			if isAPIRequest(r) {
				api.Error(w, r, http.StatusForbidden, "관리자 권한이 필요합니다")
				return
			}
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if isStateChanging(r.Method) && !csrfExempt(r.URL.Path) {
			if !a.checkCSRF(w, r, &s) {
				return
			}
		}
		a.refreshSession(w, &s)
		r = withSession(r, s)
		next(w, r)
	}
}

// checkCSRF validates form/header/JSON tokens like validate_csrf_token.
func (a *App) checkCSRF(w http.ResponseWriter, r *http.Request, s *session) bool {
	var formVal, headerVal, jsonVal string
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		_ = r.ParseMultipartForm(32 << 20)
		if r.MultipartForm != nil {
			formVal = firstFormValue(r.MultipartForm.Value, "csrf_token")
		}
		if formVal == "" && r.PostForm != nil {
			formVal = r.PostForm.Get("csrf_token")
		}
	}
	headerVal = r.Header.Get("X-CSRF-Token")
	if formVal == "" && headerVal == "" && isJSONBody(r) {
		body, err := readAndRestoreBody(r)
		if err == nil {
			var doc map[string]any
			if json.Unmarshal(body, &doc) == nil {
				jsonVal, _ = doc["csrf_token"].(string)
			}
		}
	}
	if !auth.ValidateCSRFToken(s.csrf, formVal, headerVal, jsonVal) {
		api.Error(w, r, http.StatusForbidden, "CSRF 토큰 검증 실패")
		return false
	}
	return true
}

func (a *App) denyUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if isAPIRequest(r) {
		api.Error(w, r, http.StatusUnauthorized, "로그인이 필요합니다")
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// isAPIRequest mirrors login_required's AJAX/API detection.
func isAPIRequest(r *http.Request) bool {
	if isJSONBody(r) {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	return r.Header.Get("X-Requested-With") == "XMLHttpRequest"
}

func isJSONBody(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.TrimSpace(strings.ToLower(ct)) == "application/json"
}

func isStateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// csrfExempt mirrors the factory exemptions: login POST and share-link
// password POST (share routes land in a later milestone).
func csrfExempt(path string) bool {
	return path == "/"
}

// clientIP mirrors get_real_ip with trusted-proxy handling.
func (a *App) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	return auth.RealIP(remote, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"), a.Config.TrustedProxies, a.Config.TrustedHops)
}

func firstFormValue(values map[string][]string, key string) string {
	if v, ok := values[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
