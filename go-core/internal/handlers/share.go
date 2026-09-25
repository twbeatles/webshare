package handlers

import (
	"encoding/json"
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
// Divergence (documented): the Flask app renders share_password.html /
// share_expired.html templates; the Go core has no template engine yet, so
// access failures and the password challenge are JSON. Passwords are
// accepted as form field `password` or JSON `password`.
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

// shareFail writes the JSON access-failure shape (template stand-in).
func shareFail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": msg})
}

// handleShareAccess mirrors access_share_link (public: no login, no IP gate).
func (a *App) handleShareAccess(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/share/")
	if token == "" || strings.Contains(token, "/") {
		shareFail(w, http.StatusNotFound, "링크를 찾을 수 없습니다.")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	snap, accessErr := a.Shares.Access(token)
	if accessErr != nil {
		shareFail(w, accessErr.Status, accessErr.Msg)
		return
	}
	if permission.IsProtectedSystemPath(snap.Path) {
		shareFail(w, http.StatusForbidden, "접근이 허용되지 않는 파일입니다.")
		return
	}
	if ok, _, _ := a.Perms.EnsurePathAccess(snap.Path, "read", "guest"); !ok {
		shareFail(w, http.StatusForbidden, "접근 권한이 없습니다.")
		return
	}
	if snap.PasswordHash != "" {
		ip := a.clientIP(r)
		if blocked, remaining := a.Shares.CheckBlocked(ip, token); blocked {
			shareFail(w, http.StatusTooManyRequests,
				"너무 많은 시도로 "+itoa(remaining)+"분간 차단되었습니다.")
			return
		}
		entered := sharePasswordOf(r)
		if entered == "" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"success": false, "need_password": true,
			})
			return
		}
		if !auth.VerifyPassword(snap.PasswordHash, entered) {
			a.Shares.RecordAttempt(ip, token, false)
			shareFail(w, http.StatusUnauthorized, "비밀번호가 올바르지 않습니다.")
			return
		}
		a.Shares.RecordAttempt(ip, token, true)
	}
	valid, fullPath, _ := permission.ValidatePath(a.Config.Folder, snap.Path)
	if !valid {
		shareFail(w, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	if _, err := os.Stat(fullPath); err != nil {
		shareFail(w, http.StatusNotFound, "파일을 찾을 수 없습니다.")
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
		shareFail(w, http.StatusTooManyRequests, msg)
		return
	}
	if ok, reserveMsg := a.Shares.ReserveDownload(token); !ok {
		a.Quota.Rollback(reservation)
		shareFail(w, http.StatusOK, reserveMsg)
		return
	}
	inline := r.URL.Query().Get("inline") == "1"
	etagPath := filepath.Join(a.Config.Folder, filepath.FromSlash(snap.Path))
	files.ServeFileEx(w, r, fullPath, etagPath, filepath.Base(snap.Path), !inline)
}

// serveShareDir mirrors the directory branch of access_share_link.
func (a *App) serveShareDir(w http.ResponseWriter, r *http.Request, token string, snap share.Snapshot, fullPath, trackerKey string) {
	items := share.CollectZipFiles(a.Config.Folder, fullPath, snap.Path, func(rel string) bool {
		ok, _, _ := a.Perms.EnsurePathAccess(rel, "read", "guest")
		return ok
	})
	if len(items) == 0 {
		shareFail(w, http.StatusForbidden, "다운로드 가능한 항목이 없습니다.")
		return
	}
	estimated := share.EstimateZipBytes(items)
	if allowed, msg := a.Quota.Check(trackerKey, true, estimated, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB)); !allowed {
		shareFail(w, http.StatusTooManyRequests, msg)
		return
	}
	diskOK, diskErr, zipReservation := a.Uploads.Reserve(a.Config.Folder, estimated, "share-zip:"+token)
	if !diskOK {
		shareFail(w, http.StatusInsufficientStorage, diskErr)
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
		shareFail(w, http.StatusTooManyRequests, msg)
		return
	}
	if ok, reserveMsg := a.Shares.ReserveDownload(token); !ok {
		a.Quota.Rollback(quotaReservation)
		a.Uploads.Release(zipReservation)
		os.Remove(temp)
		shareFail(w, http.StatusOK, reserveMsg)
		return
	}
	a.Uploads.Release(zipReservation)
	defer os.Remove(temp)
	serveTempZip(w, r, temp, filepath.Base(fullPath)+".zip")
}
