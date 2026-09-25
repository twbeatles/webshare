package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"webshare-core/internal/auth"
	"webshare-core/pkg/api"
)

// handleRoot serves POST / (login) and GET / (redirect when logged in,
// 401 JSON otherwise — the login HTML page is deferred to the template port).
func (a *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if r.Method == http.MethodGet {
		remoteIP, ok := a.gate(w, r)
		if !ok {
			return
		}
		_ = remoteIP
		s := a.loadSession(w, r)
		if s.loggedIn && !s.expired {
			http.Redirect(w, r, "/browse/", http.StatusFound)
			return
		}
		api.Error(w, r, http.StatusUnauthorized, "로그인이 필요합니다")
		return
	}
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	a.handleLogin(w, r)
}

// handleLogin mirrors main.index POST: admin first, then guest.
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	remoteIP, ok := a.gate(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		api.Error(w, r, http.StatusBadRequest, "BAD_REQUEST")
		return
	}
	password := r.PostForm.Get("password")
	a.mu.Lock()
	adminPw, guestPw := a.Config.AdminPw, a.Config.GuestPw
	a.mu.Unlock()

	role := ""
	if auth.VerifyPassword(adminPw, password) {
		role = "admin"
		a.maybeRehash("admin_pw", adminPw, password)
	} else if auth.VerifyPassword(guestPw, password) {
		role = "guest"
		a.maybeRehash("guest_pw", guestPw, password)
	}
	if role == "" {
		a.Blocks.Record(remoteIP, false)
		api.Error(w, r, http.StatusUnauthorized, "비밀번호가 올바르지 않습니다")
		return
	}
	a.Blocks.Record(remoteIP, true)
	sid, err := auth.NewSessionID()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	csrf, err := auth.GenerateCSRFToken()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	payload := map[string]any{
		"logged_in":   true,
		"role":        role,
		"session_id":  sid,
		"_csrf_token": csrf,
	}
	cookie, err := a.Codec.Sign(payload)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.Sessions.Add(sid, remoteIP, role)
	auth.SetSessionCookie(w, cookie, a.Config.UseHTTPS)
	http.Redirect(w, r, "/browse/", http.StatusFound)
}

// maybeRehash mirrors _migrate_password_if_needed: upgrade legacy/plaintext
// hashes in the shared config file after a successful login.
func (a *App) maybeRehash(key, stored, provided string) {
	if !auth.NeedsRehash(stored) {
		return
	}
	fresh, err := auth.HashPassword(provided)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch key {
	case "admin_pw":
		a.Config.AdminPw = fresh
	case "guest_pw":
		a.Config.GuestPw = fresh
	default:
		return
	}
	_ = saveConfig(a.ConfigPath, a.Config)
}

// handleLogout mirrors logout: drop server record, clear cookie, redirect.
func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	s := SessionOf(r)
	if s.sid != "" {
		a.Sessions.Remove(s.sid)
	}
	auth.ClearSessionCookie(w, a.Config.UseHTTPS)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleSetLanguage mirrors set_language_post (form or JSON lang).
func (a *App) handleSetLanguage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	lang := ""
	if isJSONBody(r) {
		body, err := readAndRestoreBody(r)
		if err == nil {
			var doc map[string]any
			if json.Unmarshal(body, &doc) == nil {
				lang, _ = doc["lang"].(string)
			}
		}
	}
	if lang == "" {
		_ = r.ParseForm()
		lang = r.PostForm.Get("lang")
	}
	a.applyLanguage(w, r, lang, false)
}

// handleSetLanguageLegacy mirrors set_language_legacy with Deprecation/Sunset.
func (a *App) handleSetLanguageLegacy(w http.ResponseWriter, r *http.Request) {
	remoteIP, ok := a.gate(w, r)
	if !ok {
		return
	}
	_ = remoteIP
	lang := strings.TrimPrefix(r.URL.Path, "/set_language/")
	if strings.Contains(lang, "/") {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	a.applyLanguage(w, r, lang, true)
}

func (a *App) applyLanguage(w http.ResponseWriter, r *http.Request, lang string, legacy bool) {
	setHeaders := func() {
		if legacy {
			w.Header().Set("Deprecation", "true")
			w.Header().Set("Sunset", "2026-08-31")
		}
	}
	if lang != "ko" && lang != "en" {
		setHeaders()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(api.Normalize(map[string]any{
			"success": false, "error": "Invalid language",
		}, http.StatusBadRequest, api.RequestID(r)))
		return
	}
	// Persist in the session when present (session scope, like Flask).
	s := SessionOf(r)
	if s.loggedIn {
		payload := map[string]any{}
		for k, v := range s.payload {
			payload[k] = v
		}
		payload["language"] = lang
		payload["last_active"] = float64(a.now().Unix())
		if cookie, err := a.Codec.Sign(payload); err == nil {
			auth.SetSessionCookie(w, cookie, a.Config.UseHTTPS)
		}
	}
	setHeaders()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "language": lang})
}
