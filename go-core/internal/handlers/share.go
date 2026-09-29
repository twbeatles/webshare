package handlers

import (
	"encoding/json"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"webshare-core/internal/auth"
	"webshare-core/internal/files"
	"webshare-core/internal/permission"
	"webshare-core/internal/share"
	"webshare-core/pkg/api"
)

// Share routes mirror webshare_app/routes/share_routes.py: admin
// create/list/delete plus public token access.
//
// Parity (ISSUE-005): the Go core has no template engine, so it renders
// minimal standalone HTML pages mirroring share_password.html /
// share_expired.html for browser callers, keeping the JSON shape for API
// and AJAX callers (see wantsShareJSON). Passwords are accepted as form
// field `password` or JSON `password`.
func (a *App) registerShareRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/share/create", a.requireAuth(a.handleShareCreate, true))
	mux.HandleFunc("/share/list", a.requireAuth(a.handleShareList, true))
	mux.HandleFunc("/share/delete/", a.requireAuth(a.handleShareDelete, true))
	mux.HandleFunc("/share/", a.handleShareAccess)
}

// handleShareCreate mirrors create_share_link (admin).
func (a *App) handleShareCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	fail := func(status int, msg string) {
		writeJSON(w, status, map[string]any{"success": false, "error": msg})
	}
	data := parseJSONBody(r)
	pathStr, _ := data["path"].(string)
	rawHours := data["hours"]
	if rawHours == nil {
		rawHours = float64(24)
	}
	hours, ok := toInt64(rawHours)
	if !ok {
		fail(http.StatusBadRequest, "hours는 정수여야 합니다.")
		return
	}
	rawMax := data["max_downloads"]
	if rawMax == nil {
		rawMax = float64(0)
	}
	maxDownloads, ok := toInt64(rawMax)
	if !ok {
		fail(http.StatusBadRequest, "max_downloads는 정수여야 합니다.")
		return
	}
	password, _ := data["password"].(string)
	if hours < 1 || hours > 24*365 {
		fail(http.StatusBadRequest, "hours는 1~8760 범위여야 합니다.")
		return
	}
	if maxDownloads < 0 || maxDownloads > 1000000 {
		fail(http.StatusBadRequest, "max_downloads는 0~1000000 범위여야 합니다.")
		return
	}
	if permission.IsProtectedSystemPath(pathStr) {
		fail(http.StatusForbidden, "시스템 경로는 공유할 수 없습니다.")
		return
	}
	valid, fullPath, _ := permission.ValidatePath(a.Config.Folder, pathStr)
	if !valid {
		fail(http.StatusBadRequest, "유효하지 않은 경로입니다.")
		return
	}
	if _, err := os.Stat(fullPath); err != nil {
		fail(http.StatusBadRequest, "유효하지 않은 경로입니다.")
		return
	}
	token, err := share.NewToken()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	now := a.now()
	link := &share.Link{
		Path:          pathStr,
		Expires:       now.Add(time.Duration(hours) * time.Hour),
		CreatedBy:     SessionOf(r).role,
		MaxDownloads:  maxDownloads,
		CreatedAt:     now,
	}
	if link.CreatedBy == "" {
		link.CreatedBy = "unknown"
	}
	if st, err := os.Stat(fullPath); err == nil {
		link.IsDir = st.IsDir()
	}
	if password != "" {
		hash, err := auth.HashPassword(password)
		if err != nil {
			api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
			return
		}
		link.PasswordHash = hash
	}
	a.Shares.Create(token, link)
	auditUser := SessionOf(r).role
	if auditUser == "" {
		auditUser = "unknown"
	}
	a.audit(auditUser, "share_create", pathStr, strconv.FormatInt(hours, 10)+"시간, 토큰: "+shortToken(token)+"...", r)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "token": token,
		"expires": share.FormatNaive(link.Expires),
		"link":    "/share/" + token, "has_password": password != "",
		"max_downloads": maxDownloads,
	})
}

func shortToken(token string) string {
	if len(token) > 8 {
		return token[:8]
	}
	return token
}

// handleShareList mirrors list_share_links (admin).
func (a *App) handleShareList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	links := a.Shares.ListActive()
	if links == nil {
		links = []*share.ActiveLink{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": links})
}

// handleShareDelete mirrors delete_share_link (admin).
func (a *App) handleShareDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/share/delete/")
	if token == "" || strings.Contains(token, "/") {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	path, deleted := a.Shares.Delete(token)
	if !deleted {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "링크를 찾을 수 없습니다."})
		return
	}
	auditUser := SessionOf(r).role
	if auditUser == "" {
		auditUser = "unknown"
	}
	a.audit(auditUser, "share_delete", path, "토큰: "+shortToken(token)+"...", r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// wantsShareJSON reports whether the share-access caller expects the JSON
// API shape. Plain browser navigation and HTML form POSTs get minimal HTML
// pages mirroring share_password.html / share_expired.html (ISSUE-005);
// API and AJAX callers (Accept/Content-Type application/json,
// X-Requested-With: XMLHttpRequest, ?format=json) keep the JSON shape.
func wantsShareJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Requested-With")), "XMLHttpRequest") {
		return true
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

// shareFail renders an access failure: the expired/blocked HTML page for
// browsers, the JSON error shape for API callers. Status codes match the
// Python share_expired.html branches.
func shareFail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if wantsShareJSON(r) {
		writeJSON(w, status, map[string]any{"success": false, "error": msg})
		return
	}
	writeShareHTML(w, status, "접근 불가 - WebShare Pro", "접근 불가", "<p>"+html.EscapeString(msg)+"</p>")
}

// sharePasswordPage renders the password challenge: the password-form HTML
// page for browsers (status mirrors the Python share_password.html
// branches), the need_password/wrong-password JSON shape for API callers.
func sharePasswordPage(w http.ResponseWriter, r *http.Request, htmlStatus int, errMsg string) {
	if wantsShareJSON(r) {
		if errMsg == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"success": false, "need_password": true,
			})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "error": errMsg})
		return
	}
	errBlock := ""
	if errMsg != "" {
		errBlock = "<div class=\"error\">" + html.EscapeString(errMsg) + "</div>"
	}
	writeShareHTML(w, htmlStatus, "비밀번호 필요 - WebShare Pro", "비밀번호 필요",
		"<p>이 파일에 접근하려면 비밀번호가 필요합니다.</p>"+errBlock+
			"<form method=\"post\">"+
			"<input type=\"password\" name=\"password\" placeholder=\"비밀번호를 입력하세요\" required autofocus>"+
			"<button type=\"submit\">확인</button></form>")
}

// writeShareHTML writes a minimal standalone page (no template engine).
func writeShareHTML(w http.ResponseWriter, status int, title, heading, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte("<!DOCTYPE html><html lang=\"ko\"><head>" +
		"<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" +
		"<title>" + html.EscapeString(title) + "</title>" +
		"<style>*{box-sizing:border-box}body{font-family:sans-serif;background:#f1f5f9;min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0}" +
		".card{background:#fff;padding:40px;border-radius:20px;box-shadow:0 25px 50px rgba(0,0,0,.2);text-align:center;max-width:400px;width:90%}" +
		"h2{color:#1e293b;margin-bottom:10px}p{color:#64748b}" +
		"input{width:100%;padding:15px;border:2px solid #e2e8f0;border-radius:12px;font-size:1rem;margin-bottom:15px}" +
		"button{width:100%;padding:15px;background:#6366f1;color:#fff;border:none;border-radius:12px;font-size:1rem;font-weight:600;cursor:pointer}" +
		".error{color:#ef4444;font-size:.9rem;margin-bottom:15px}</style></head><body>" +
		"<div class=\"card\"><h2>" + html.EscapeString(heading) + "</h2>" + body + "</div></body></html>"))
}

// handleShareAccess mirrors access_share_link (public: no login, no IP gate).
func (a *App) handleShareAccess(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/share/")
	if token == "" || strings.Contains(token, "/") {
		shareFail(w, r, http.StatusNotFound, "링크를 찾을 수 없습니다.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	snap, accessErr := a.Shares.Access(token)
	if accessErr != nil {
		shareFail(w, r, accessErr.Status, accessErr.Msg)
		return
	}
	if permission.IsProtectedSystemPath(snap.Path) {
		shareFail(w, r, http.StatusForbidden, "접근이 허용되지 않는 파일입니다.")
		return
	}
	if ok, _, _ := a.Perms.EnsurePathAccess(snap.Path, "read", "guest"); !ok {
		shareFail(w, r, http.StatusForbidden, "접근 권한이 없습니다.")
		return
	}
	if snap.PasswordHash != "" {
		ip := a.clientIP(r)
		if blocked, remaining := a.Shares.CheckBlocked(ip, token); blocked {
			// Python renders share_password.html with 429 here.
			sharePasswordPage(w, r, http.StatusTooManyRequests,
				"너무 많은 시도로 "+itoa(remaining)+"분간 차단되었습니다.")
			return
		}
		entered := sharePasswordOf(r)
		if entered == "" && r.Method == http.MethodGet {
			// Python renders share_password.html with 200 here.
			sharePasswordPage(w, r, http.StatusOK, "")
			return
		}
		if !auth.VerifyPassword(snap.PasswordHash, entered) {
			a.Shares.RecordAttempt(ip, token, false)
			if blocked, _ := a.Shares.CheckBlocked(ip, token); blocked {
				a.auditSecurity("system", "share_password_blocked",
					shortToken(token)+"...", "공유 비밀번호 시도 누적 차단", r)
			}
			// Python re-renders the form with 200 here.
			sharePasswordPage(w, r, http.StatusOK, "비밀번호가 올바르지 않습니다.")
			return
		}
		a.Shares.RecordAttempt(ip, token, true)
	}
	valid, fullPath, _ := permission.ValidatePath(a.Config.Folder, snap.Path)
	if !valid {
		shareFail(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	if _, err := os.Stat(fullPath); err != nil {
		shareFail(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	clientIP := a.clientIP(r)
	trackerKey := "ip:" + clientIP
	if clientIP == "" {
		trackerKey = "ip:unknown"
	}
	if snap.IsDir {
		a.serveShareDir(w, r, token, snap, fullPath, trackerKey)
		return
	}
	a.serveShareFile(w, r, token, snap, fullPath, trackerKey)
}

// sharePasswordOf reads the password from form or JSON like the share form.
func sharePasswordOf(r *http.Request) string {
	_ = r.ParseMultipartForm(32 << 20)
	if r.MultipartForm != nil {
		if v := firstFormValue(r.MultipartForm.Value, "password"); v != "" {
			return v
		}
	}
	if r.PostForm != nil {
		if v := r.PostForm.Get("password"); v != "" {
			return v
		}
	}
	if isJSONBody(r) {
		if body, err := readAndRestoreBody(r); err == nil {
			var doc map[string]any
			if json.Unmarshal(body, &doc) == nil {
				if pw, _ := doc["password"].(string); pw != "" {
					return pw
				}
			}
		}
	}
	return ""
}

// serveShareFile mirrors the file branch of access_share_link.
func (a *App) serveShareFile(w http.ResponseWriter, r *http.Request, token string, snap share.Snapshot, fullPath, trackerKey string) {
	fileSize := fileSizeOf(fullPath)
	allowed, msg, reservation := a.Quota.Reserve(trackerKey, true, fileSize, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB))
	if !allowed {
		shareFail(w, r, http.StatusTooManyRequests, msg)
		return
	}
	if ok, reserveMsg := a.Shares.ReserveDownload(token); !ok {
		a.Quota.Rollback(reservation)
		shareFail(w, r, http.StatusOK, reserveMsg)
		return
	}
	inline := r.URL.Query().Get("inline") == "1"
	etagPath := filepath.Join(a.Config.Folder, filepath.FromSlash(snap.Path))
	cw := &countingWriter{ResponseWriter: w}
	files.ServeFileEx(cw, r, fullPath, etagPath, filepath.Base(snap.Path), !inline)
	a.Quota.Settle(reservation, cw.written)
}

// serveShareDir mirrors the directory branch of access_share_link.
func (a *App) serveShareDir(w http.ResponseWriter, r *http.Request, token string, snap share.Snapshot, fullPath, trackerKey string) {
	items := share.CollectZipFiles(a.Config.Folder, fullPath, snap.Path, func(rel string) bool {
		ok, _, _ := a.Perms.EnsurePathAccess(rel, "read", "guest")
		return ok
	})
	if len(items) == 0 {
		shareFail(w, r, http.StatusForbidden, "다운로드 가능한 항목이 없습니다.")
		return
	}
	estimated := share.EstimateZipBytes(items)
	if allowed, msg := a.Quota.Check(trackerKey, true, estimated, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB)); !allowed {
		shareFail(w, r, http.StatusTooManyRequests, msg)
		return
	}
	diskOK, diskErr, zipReservation := a.Uploads.Reserve(a.Config.Folder, estimated, "share-zip:"+token)
	if !diskOK {
		shareFail(w, r, http.StatusInsufficientStorage, diskErr)
		return
	}
	temp, err := files.CreateTempZip(items)
	if err != nil {
		a.Uploads.Release(zipReservation)
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	allowed, msg, quotaReservation := a.Quota.Reserve(trackerKey, true, fileSizeOf(temp), int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB))
	if !allowed {
		a.Uploads.Release(zipReservation)
		os.Remove(temp)
		shareFail(w, r, http.StatusTooManyRequests, msg)
		return
	}
	if ok, reserveMsg := a.Shares.ReserveDownload(token); !ok {
		a.Quota.Rollback(quotaReservation)
		a.Uploads.Release(zipReservation)
		os.Remove(temp)
		shareFail(w, r, http.StatusOK, reserveMsg)
		return
	}
	a.Uploads.Release(zipReservation)
	defer os.Remove(temp)
	cw := &countingWriter{ResponseWriter: w}
	serveTempZip(cw, r, temp, filepath.Base(fullPath)+".zip")
	a.Quota.Settle(quotaReservation, cw.written)
}
