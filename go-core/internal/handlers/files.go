package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"webshare-core/internal/config"
	"webshare-core/internal/files"
	"webshare-core/internal/permission"
	"webshare-core/internal/quota"
	"webshare-core/pkg/api"
)

// saveConfig persists the shared config file atomically.
func saveConfig(path string, cfg config.Config) error {
	return config.Save(path, cfg)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// subpathOf strips the route prefix and URL-unescapes one level.
// Go's ServeMux already decodes %XX in URL.Path (like Werkzeug routing).
func subpathOf(r *http.Request, prefix string) string {
	return strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
}

// checkAccess runs ensure_path_access for the request role.
func (a *App) checkAccess(w http.ResponseWriter, r *http.Request, rel, action string) bool {
	ok, msg, code := a.Perms.EnsurePathAccess(rel, action, SessionOf(r).role)
	if !ok {
		api.Error(w, r, code, msg)
		return false
	}
	return true
}

// validate resolves rel inside the shared folder (400 on escape).
func (a *App) validate(w http.ResponseWriter, r *http.Request, rel string) (string, bool) {
	ok, full, msg := permission.ValidatePath(a.Config.Folder, rel)
	if !ok {
		api.Error(w, r, http.StatusBadRequest, msg)
		return "", false
	}
	return full, true
}

// handleList mirrors api list_directory (GET /api/list/ and /api/list/<sub>).
func (a *App) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	var sub string
	if r.URL.Path != "/api/list" && r.URL.Path != "/api/list/" {
		sub = subpathOf(r, "/api/list/")
	}
	if !a.checkAccess(w, r, sub, "read") {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page == 0 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize == 0 {
		pageSize = files.DefaultPageSize
	}
	s := SessionOf(r)
	role := s.role
	page2 := files.ListPage(files.ListOptions{
		BaseDir:  a.Config.Folder,
		Subpath:  permission.NormalizeRelativePath(sub),
		Page:     page,
		PageSize: pageSize,
		SortBy:   q.Get("sort"),
		Order:    q.Get("order"),
		Query:    q.Get("q"),
		CanRead: func(rel, action string) bool {
			ok, _, _ := a.Perms.EnsurePathAccess(rel, action, role)
			return ok
		},
		Caps: func(rel string, isDir bool, itemType string) map[string]bool {
			caps := a.Perms.BuildCapabilities(rel, role, isDir, itemType, a.Config.AllowGuestUpload)
			return capsMap(caps)
		},
	})
	if !page2.Success {
		api.Error(w, r, page2.Status, page2.Error)
		return
	}
	dirCaps := a.Perms.BuildCapabilities(permission.NormalizeRelativePath(sub), role, true, "folder", a.Config.AllowGuestUpload)
	writeJSON(w, http.StatusOK, map[string]any{
		"success":                true,
		"path":                   page2.Path,
		"items":                  page2.Items,
		"pagination":             page2.Pagination,
		"sort":                   map[string]any{"by": page2.SortBy, "order": page2.Order},
		"query":                  page2.Query,
		"directory_capabilities": capsMap(dirCaps),
	})
}

func capsMap(c permission.Capabilities) map[string]bool {
	return map[string]bool{
		"read": c.Read, "write": c.Write, "delete": c.Delete, "rename": c.Rename,
		"move": c.Move, "copy": c.Copy, "upload": c.Upload, "mkdir": c.Mkdir,
		"edit": c.Edit, "trash": c.Trash, "unzip": c.Unzip,
	}
}

// handleFileInfo mirrors get_file_info.
func (a *App) handleFileInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/file_info/"))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	full, ok := a.validate(w, r, rel)
	if !ok {
		return
	}
	if _, err := os.Stat(full); err != nil {
		api.Error(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	info, err := files.StatFile(rel, full)
	if err != nil {
		api.Error(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

// handleDownload mirrors download with quota reservation.
func (a *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/download/"))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	full, ok := a.validate(w, r, rel)
	if !ok {
		return
	}
	st, err := os.Stat(full)
	if err != nil {
		api.Error(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	if st.IsDir() {
		api.Error(w, r, http.StatusBadRequest, "폴더는 다운로드할 수 없습니다")
		return
	}
	s := SessionOf(r)
	key := quota.Key(s.sid, a.clientIP(r))
	allowed, msg, reservation := a.Quota.Reserve(key, true, st.Size(), int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB))
	if !allowed {
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	_ = reservation
	// ETag source: send_file hashes the validated (resolved) full path.
	files.ServeFile(w, r, full, st.Name())
}

// handleZip mirrors download_zip (temp-file strategy).
func (a *App) handleZip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/zip/"))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	ok, target, msg := permission.ValidatePath(a.Config.Folder, rel)
	if !ok {
		api.Error(w, r, http.StatusForbidden, msg)
		return
	}
	st, err := os.Stat(target)
	if err != nil || !st.IsDir() {
		api.Error(w, r, http.StatusNotFound, "폴더가 아닙니다")
		return
	}
	s := SessionOf(r)
	role := s.role
	items := files.CollectZipFiles(target, rel, "", func(p string) bool {
		ok, _, _ := a.Perms.EnsurePathAccess(p, "read", role)
		return ok
	}, func(p string) (string, bool) {
		ok, full, _ := permission.ValidatePath(a.Config.Folder, p)
		return full, ok
	})
	estimated := files.EstimateZipBytes(items)
	key := quota.Key(s.sid, a.clientIP(r))
	if allowed, msg := a.Quota.Check(key, true, estimated, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB)); !allowed {
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	if len(items) == 0 {
		api.Error(w, r, http.StatusForbidden, "다운로드 가능한 항목이 없습니다")
		return
	}
	temp, err := files.CreateTempZip(items)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	tempSize := fileSizeOf(temp)
	allowed, msg, _ := a.Quota.Reserve(key, true, tempSize, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB))
	if !allowed {
		os.Remove(temp)
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	defer os.Remove(temp)
	serveTempZip(w, r, temp, st.Name()+".zip")
}

// handleBatchDownload mirrors batch_download (POST form files JSON).
func (a *App) handleBatchDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/batch_download/"))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	ok, _, msg := permission.ValidatePath(a.Config.Folder, rel)
	if !ok {
		api.Error(w, r, http.StatusForbidden, msg)
		return
	}
	if err := r.ParseForm(); err != nil {
		api.Error(w, r, http.StatusBadRequest, "잘못된 요청입니다")
		return
	}
	var data []any
	if err := json.Unmarshal([]byte(r.PostForm.Get("files")), &data); err != nil {
		// Mirror Python: json.loads failure → 400. Non-list JSON diverges
		// (documented): Python iterates dict keys, Go rejects.
		api.Error(w, r, http.StatusBadRequest, "잘못된 요청입니다")
		return
	}
	s := SessionOf(r)
	role := s.role
	var items []files.ZipItem
	for _, raw := range data {
		name, isStr := raw.(string)
		if !isStr {
			api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
			return
		}
		safe := files.SafeFilename(name)
		itemRel := permission.NormalizeRelativePath(rel + "/" + safe)
		if ok, _, _ := a.Perms.EnsurePathAccess(itemRel, "read", role); !ok {
			continue
		}
		if permission.IsProtectedSystemPath(itemRel) {
			continue
		}
		ok, abs, _ := permission.ValidatePath(a.Config.Folder, itemRel)
		if !ok {
			continue
		}
		st, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if st.Mode().IsRegular() {
			items = append(items, files.ZipItem{AbsPath: abs, ArcName: safe})
			continue
		}
		if st.IsDir() {
			items = append(items, files.CollectZipFiles(abs, itemRel, safe, func(p string) bool {
				ok, _, _ := a.Perms.EnsurePathAccess(p, "read", role)
				return ok
			}, func(p string) (string, bool) {
				ok, full, _ := permission.ValidatePath(a.Config.Folder, p)
				return full, ok
			})...)
		}
	}
	if len(items) == 0 {
		api.Error(w, r, http.StatusForbidden, "다운로드 가능한 항목이 없습니다")
		return
	}
	estimated := files.EstimateZipBytes(items)
	key := quota.Key(s.sid, a.clientIP(r))
	if allowed, msg := a.Quota.Check(key, true, estimated, int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB)); !allowed {
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	temp, err := files.CreateTempZip(items)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	allowed, msg, _ := a.Quota.Reserve(key, true, fileSizeOf(temp), int64(a.Config.DailyDownloadLimit), int64(a.Config.DailyBandwidthLimitMB))
	if !allowed {
		os.Remove(temp)
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	defer os.Remove(temp)
	serveTempZip(w, r, temp, "batch_download.zip")
}

// handleZipPreview mirrors zip_preview.
func (a *App) handleZipPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/api/zip_preview/"))
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	full, ok := a.validate(w, r, rel)
	if !ok {
		return
	}
	if _, err := os.Stat(full); err != nil {
		api.Error(w, r, http.StatusNotFound, "파일을 찾을 수 없습니다")
		return
	}
	filename, items, totalFiles, totalFolders, err := files.ZipPreview(full)
	if err != nil {
		if files.IsNotZip(err) {
			api.Error(w, r, http.StatusBadRequest, "ZIP 형식 파일만 지원됩니다")
			return
		}
		api.Error(w, r, http.StatusBadRequest, "손상된 ZIP 파일입니다")
		return
	}
	if items == nil {
		items = []files.ZipPreviewItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "filename": filename,
		"total_files": totalFiles, "total_folders": totalFolders, "items": items,
	})
}

// handleSearch mirrors search_files in permanent fallback mode (no index yet).
func (a *App) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len([]rune(query)) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{
			"results": []any{}, "error": "검색어는 2자 이상이어야 합니다.",
			"indexing": false, "search_mode": "index",
		})
		return
	}
	s := SessionOf(r)
	role := s.role
	hits := files.SearchFallback(a.Config.Folder, query, 100, files.DefaultSearchBudget, func(rel string) bool {
		ok, _, _ := a.Perms.EnsurePathAccess(rel, "read", role)
		return ok
	})
	if hits == nil {
		hits = []files.SearchResult{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"results": hits, "count": len(hits), "indexing": false, "search_mode": "fallback",
	})
}

func fileSizeOf(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// serveTempZip streams a finished temp zip with zip headers.
func serveTempZip(w http.ResponseWriter, r *http.Request, temp, downloadName string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", files.ZipContentDisposition(downloadName))
	f, err := os.Open(temp)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}
