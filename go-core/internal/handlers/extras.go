package handlers

import (
	"encoding/csv"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"webshare-core/internal/files"
	"webshare-core/internal/meta"
	"webshare-core/internal/mutate"
	"webshare-core/internal/permission"
	"webshare-core/internal/upload"
	"webshare-core/pkg/api"
)

// Extra routes (Milestone G core set): trash UI, metadata (tags, favorites,
// memos, bookmarks, versions), audit read/export, and system info
// (capabilities, disk, folder size).
func (a *App) registerExtrasRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/trash", a.requireAuth(a.handleTrashMove, false))
	mux.HandleFunc("/trash/", a.requireAuth(a.handleTrashSub, false))
	mux.HandleFunc("/api/trash/cleanup", a.requireAuth(a.handleTrashCleanup, true))
	mux.HandleFunc("/api/tags", a.requireAuth(a.handleTags, false))
	mux.HandleFunc("/api/favorites", a.requireAuth(a.handleFavorites, false))
	mux.HandleFunc("/api/memo/", a.requireAuth(a.handleMemo, false))
	mux.HandleFunc("/bookmarks", a.requireAuth(a.handleBookmarks, false))
	mux.HandleFunc("/versions/restore", a.requireAuth(a.handleVersionRestore, true))
	mux.HandleFunc("/versions/", a.requireAuth(a.handleVersionList, true))
	mux.HandleFunc("/api/audit_log", a.requireAuth(a.handleAuditLog, true))
	mux.HandleFunc("/api/audit_log/export", a.requireAuth(a.handleAuditExport, true))
	mux.HandleFunc("/api/capabilities", a.requireAuth(a.handleCapabilities, false))
	mux.HandleFunc("/api/disk_info", a.requireAuth(a.handleDiskInfo, false))
	mux.HandleFunc("/api/disk_status", a.requireAuth(a.handleDiskStatus, false))
	mux.HandleFunc("/api/folder_size/", a.requireAuth(a.handleFolderSize, false))
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func auditUserOf(r *http.Request) string {
	if role := SessionOf(r).role; role != "" {
		return role
	}
	return "unknown"
}

// ---------- trash ----------

// handleTrashSub dispatches /trash/list, /restore, /empty.
func (a *App) handleTrashSub(w http.ResponseWriter, r *http.Request) {
	switch strings.TrimPrefix(r.URL.Path, "/trash/") {
	case "list":
		a.handleTrashList(w, r)
	case "restore":
		a.handleTrashRestore(w, r)
	case "empty":
		a.handleTrashEmpty(w, r)
	default:
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
	}
}

// handleTrashMove mirrors trash move_to_trash (login, not admin-only).
func (a *App) handleTrashMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	fail := func(status int, msg string) {
		writeJSON(w, status, map[string]any{"success": false, "error": msg})
	}
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		fail(status, msg)
		return
	}
	data := parseJSONBody(r)
	pathStr, _ := data["path"].(string)
	if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "delete", role); !ok {
		fail(code, msg)
		return
	}
	valid, full, _ := permission.ValidatePath(a.Config.Folder, pathStr)
	if !valid {
		fail(http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	if _, err := os.Lstat(full); err != nil {
		fail(http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	trashName, err := mutate.MoveToTrash(a.Config.Folder, full, a.now())
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(auditUserOf(r), "trash_move", pathStr, "Trash name: "+trashName, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "trash_name": trashName})
}

// handleTrashList mirrors list_trash (admin).
func (a *App) handleTrashList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	trashDir := filepath.Join(a.Config.Folder, mutate.TrashDirName)
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []map[string]any{}})
		return
	}
	metadata := mutate.LoadTrashMetadata(a.Config.Folder)
	items := []map[string]any{}
	for _, e := range entries {
		full := filepath.Join(trashDir, e.Name())
		st, err := os.Lstat(full)
		if err != nil {
			continue
		}
		mentry, hasMeta := metadata.Entries[e.Name()]
		originalName := mutate.ExtractOriginalName(e.Name())
		originalPath, id := "", ""
		deletedAt := st.ModTime().Format("2006-01-02T15:04:05.999999")
		if hasMeta {
			if base := filepath.Base(mentry.OriginalRelPath); base != "" {
				originalName = base
			}
			originalPath = mentry.OriginalRelPath
			id = mentry.ID
			deletedAt = mentry.DeletedAt
		}
		items = append(items, map[string]any{
			"name": e.Name(), "original_name": originalName,
			"original_path": originalPath, "id": id, "is_dir": st.IsDir(),
			"size": st.Size(), "deleted_at": deletedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleTrashRestore mirrors restore_from_trash (admin).
func (a *App) handleTrashRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	data := parseJSONBody(r)
	name, _ := data["name"].(string)
	ok, result := mutate.RestoreFromTrash(a.Config.Folder, name)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": result})
		return
	}
	a.audit(auditUserOf(r), "trash_restore", name, "Restored to: "+filepath.Base(result), r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "restored_name": filepath.Base(result)})
}

// handleTrashEmpty mirrors empty_trash (admin).
func (a *App) handleTrashEmpty(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	trashDir := filepath.Join(a.Config.Folder, mutate.TrashDirName)
	if _, err := os.Lstat(trashDir); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}
	count := 0
	if entries, err := os.ReadDir(trashDir); err == nil {
		count = len(entries)
	}
	if err := os.RemoveAll(trashDir); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	os.Remove(filepath.Join(a.Config.Folder, mutate.TrashMetadataFile))
	a.audit(auditUserOf(r), "trash_empty", mutate.TrashDirName,
		itoa(count)+"개 항목 영구 삭제", r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleTrashCleanup mirrors trash_cleanup (admin).
func (a *App) handleTrashCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	deleted := mutate.AutoCleanupTrash(a.Config.Folder, a.Config.TrashAutoDeleteDays)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": deleted})
}

// ---------- metadata ----------

const (
	maxTagLength      = 64
	maxMemoLength     = 10000
	maxMetaNameLength = 200
)

var tagColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func boundedText(value any, maxLen int) (string, bool) {
	text := strings.TrimSpace(strOf(value))
	if len([]rune(text)) > maxLen {
		return "", false
	}
	return text, true
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// handleTags mirrors api_file_tags.
func (a *App) handleTags(w http.ResponseWriter, r *http.Request) {
	s := SessionOf(r)
	switch r.Method {
	case http.MethodGet:
		if pathStr := r.URL.Query().Get("path"); pathStr != "" {
			if !a.checkAccess(w, r, pathStr, "read") {
				return
			}
			tags := a.Meta.Tags[pathStr]
			if tags == nil {
				tags = []meta.Tag{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"tags": tags})
			return
		}
		filtered := map[string][]meta.Tag{}
		for p, tags := range a.Meta.Tags {
			if ok, _, _ := a.Perms.EnsurePathAccess(p, "read", s.role); ok {
				filtered[p] = tags
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"all_tags": filtered})
	case http.MethodPost:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "write", s.role); !ok {
			writeJSON(w, code, map[string]any{"success": false, "error": msg})
			return
		}
		tag, okTag := boundedText(data["tag"], maxTagLength)
		if !okTag {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "value too long (max=64)",
			})
			return
		}
		color := strOf(data["color"])
		if color == "" {
			color = "#6366f1"
		}
		if !tagColorRe.MatchString(color) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "invalid tag color",
			})
			return
		}
		if pathStr == "" || tag == "" {
			writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "경로와 태그가 필요합니다."})
			return
		}
		for _, t := range a.Meta.Tags[pathStr] {
			if t.Tag == tag {
				writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "이미 존재하는 태그입니다."})
				return
			}
		}
		a.Meta.Tags[pathStr] = append(a.Meta.Tags[pathStr], meta.Tag{Tag: tag, Color: color})
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case http.MethodDelete:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		tag, ok := boundedText(data["tag"], maxTagLength)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "value too long (max=64)",
			})
			return
		}
		if existing, present := a.Meta.Tags[pathStr]; present {
			kept := []meta.Tag{}
			for _, t := range existing {
				if t.Tag != tag {
					kept = append(kept, t)
				}
			}
			if len(kept) == 0 {
				delete(a.Meta.Tags, pathStr)
			} else {
				a.Meta.Tags[pathStr] = kept
			}
		}
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w, r)
	}
}

// handleFavorites mirrors api_favorites.
func (a *App) handleFavorites(w http.ResponseWriter, r *http.Request) {
	s := SessionOf(r)
	switch r.Method {
	case http.MethodGet:
		out := []meta.Favorite{}
		for _, f := range a.Meta.Favorites {
			if ok, _, _ := a.Perms.EnsurePathAccess(f.Path, "read", s.role); ok {
				out = append(out, f)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"favorites": out})
	case http.MethodPost:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		name := strOf(data["name"])
		if name == "" && pathStr != "" {
			name = filepath.Base(filepath.FromSlash(pathStr))
		}
		name, ok := boundedText(name, maxMetaNameLength)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "value too long (max=200)",
			})
			return
		}
		if pathStr == "" {
			writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "경로가 필요합니다."})
			return
		}
		if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "read", s.role); !ok {
			writeJSON(w, code, map[string]any{"success": false, "error": msg})
			return
		}
		for _, f := range a.Meta.Favorites {
			if f.Path == pathStr {
				writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "이미 즐겨찾기에 추가되어 있습니다."})
				return
			}
		}
		a.Meta.Favorites = append(a.Meta.Favorites, meta.Favorite{
			Path: pathStr, Name: name, Added: a.Meta.NowISO(),
		})
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case http.MethodDelete:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		if pathStr != "" {
			if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "read", s.role); !ok {
				writeJSON(w, code, map[string]any{"success": false, "error": msg})
				return
			}
		}
		kept := []meta.Favorite{}
		for _, f := range a.Meta.Favorites {
			if f.Path != pathStr {
				kept = append(kept, f)
			}
		}
		a.Meta.Favorites = kept
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w, r)
	}
}

// handleMemo mirrors api_file_memo.
func (a *App) handleMemo(w http.ResponseWriter, r *http.Request) {
	rel := subpathOf(r, "/api/memo/")
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	action := "read"
	if r.Method != http.MethodGet {
		action = "write"
	}
	if ok, msg, code := a.Perms.EnsurePathAccess(rel, action, SessionOf(r).role); !ok {
		if r.Method == http.MethodGet {
			writeJSON(w, code, map[string]any{"error": msg})
		} else {
			writeJSON(w, code, map[string]any{"success": false, "error": msg})
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		m := a.Meta.Memos[rel]
		writeJSON(w, http.StatusOK, map[string]any{"memo": m.Memo, "updated": m.Updated})
	case http.MethodPost:
		data := parseJSONBody(r)
		text, ok := boundedText(data["memo"], maxMemoLength)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "value too long (max=10000)",
			})
			return
		}
		a.Meta.Memos[rel] = meta.Memo{Memo: text, Updated: a.Meta.NowISO()}
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case http.MethodDelete:
		delete(a.Meta.Memos, rel)
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w, r)
	}
}

// handleBookmarks mirrors handle_bookmarks.
func (a *App) handleBookmarks(w http.ResponseWriter, r *http.Request) {
	s := SessionOf(r)
	switch r.Method {
	case http.MethodGet:
		out := []meta.Bookmark{}
		for _, b := range a.Meta.Bookmarks {
			if ok, _, _ := a.Perms.EnsurePathAccess(b.Path, "read", s.role); ok {
				out = append(out, b)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"bookmarks": out})
	case http.MethodPost:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		name := strOf(data["name"])
		if name == "" {
			name = filepath.Base(filepath.FromSlash(pathStr))
		}
		name, ok := boundedText(name, maxMetaNameLength)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"success": false, "error": "value too long (max=200)",
			})
			return
		}
		if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "read", s.role); !ok {
			writeJSON(w, code, map[string]any{"success": false, "error": msg})
			return
		}
		for _, b := range a.Meta.Bookmarks {
			if b.Path == pathStr {
				writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "이미 북마크되어 있습니다."})
				return
			}
		}
		a.Meta.Bookmarks = append(a.Meta.Bookmarks, meta.Bookmark{
			Path: pathStr, Name: name, Added: a.Meta.NowISO(),
		})
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case http.MethodDelete:
		data := parseJSONBody(r)
		pathStr := strOf(data["path"])
		if pathStr != "" {
			if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "read", s.role); !ok {
				writeJSON(w, code, map[string]any{"success": false, "error": msg})
				return
			}
		}
		kept := []meta.Bookmark{}
		for _, b := range a.Meta.Bookmarks {
			if b.Path != pathStr {
				kept = append(kept, b)
			}
		}
		a.Meta.Bookmarks = kept
		a.Meta.Save()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w, r)
	}
}

// handleVersionList mirrors list_versions (admin).
func (a *App) handleVersionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	rel := subpathOf(r, "/versions/")
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	relSlash := strings.ReplaceAll(rel, "\\", "/")
	versionDir := filepath.Join(a.Config.Folder, mutate.VersionDirName)
	entries, err := os.ReadDir(versionDir)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"versions": []map[string]any{}})
		return
	}
	versions := []map[string]any{}
	for _, e := range entries {
		if e.IsDir() || !mutate.VersionNameMatchesRelPath(e.Name(), relSlash) {
			continue
		}
		st, err := os.Lstat(filepath.Join(versionDir, e.Name()))
		if err != nil {
			continue
		}
		stamp := e.Name()
		if len(stamp) > 15 {
			stamp = stamp[:15]
		}
		versions = append(versions, map[string]any{
			"name": e.Name(), "timestamp": stamp, "size": st.Size(),
		})
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i]["timestamp"].(string) > versions[j]["timestamp"].(string)
	})
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

// handleVersionRestore mirrors restore_version (admin).
func (a *App) handleVersionRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	data := parseJSONBody(r)
	versionName := strOf(data["version"])
	targetPath := strOf(data["target"])
	if ok, msg, code := a.Perms.EnsurePathAccess(targetPath, "write", SessionOf(r).role); !ok {
		writeJSON(w, code, map[string]any{"success": false, "error": msg})
		return
	}
	normalized := strings.ReplaceAll(targetPath, "\\", "/")
	if filepath.Base(versionName) != versionName ||
		!mutate.VersionNameMatchesRelPath(versionName, normalized) {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "파일을 찾을 수 없습니다."})
		return
	}
	valid, fullTarget, _ := permission.ValidatePath(a.Config.Folder, targetPath)
	versionPath := filepath.Join(a.Config.Folder, mutate.VersionDirName, versionName)
	if _, err := os.Lstat(versionPath); err != nil || !valid {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "파일을 찾을 수 없습니다."})
		return
	}
	mutate.CreateFileVersion(a.Config.Folder, fullTarget, a.Config.EnableVersioning, a.now())
	// AtomicCopyFile preserves permission bits (copy2 mtime sync is a
	// documented minor difference).
	if err := mutate.AtomicCopyFile(versionPath, fullTarget); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(auditUserOf(r), "version_restore", targetPath, "버전: "+versionName, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// ---------- audit ----------

// handleAuditLog mirrors get_audit_log (admin).
func (a *App) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	if perPage < 1 {
		perPage = 50
	}
	actionFilter := q.Get("action")
	userFilter := q.Get("user")
	dateFrom := q.Get("from")
	dateTo := q.Get("to")
	filtered := []map[string]any{}
	if a.Audit != nil {
		for _, e := range a.Audit.Entries() {
			if actionFilter != "" && e.Action != actionFilter {
				continue
			}
			if userFilter != "" && e.User != userFilter {
				continue
			}
			if dateFrom != "" && e.Timestamp < dateFrom {
				continue
			}
			if dateTo != "" && e.Timestamp > dateTo {
				continue
			}
			filtered = append(filtered, map[string]any{
				"timestamp": e.Timestamp, "user": e.User, "ip": e.IP,
				"action": e.Action, "target": e.Target,
				"details": e.Details, "result": e.Result,
			})
		}
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	if limit > 0 {
		if limit < len(filtered) {
			filtered = filtered[:limit]
		}
		writeJSON(w, http.StatusOK, map[string]any{"logs": filtered})
		return
	}
	total := len(filtered)
	start := (page - 1) * perPage
	if start > total {
		start = total
	}
	end := start + perPage
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"logs": filtered[start:end], "total": total,
		"page": page, "per_page": perPage,
		"total_pages": (total + perPage - 1) / perPage,
	})
}

// handleAuditExport mirrors export_audit_log (admin): BOM CSV download.
func (a *App) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	var rows [][]string
	rows = append(rows, []string{"Timestamp", "User", "IP", "Action", "Target", "Details", "Result"})
	if a.Audit != nil {
		for _, e := range a.Audit.Entries() {
			rows = append(rows, []string{
				e.Timestamp, e.User, e.IP, e.Action, e.Target, e.Details, e.Result,
			})
		}
	}
	var sb strings.Builder
	sb.WriteString("\xEF\xBB\xBF")
	cw := csv.NewWriter(&sb)
	cw.UseCRLF = true
	for _, row := range rows {
		_ = cw.Write(row)
	}
	cw.Flush()
	body := sb.String()
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=audit_log_"+a.now().Format("20060102_150405")+".csv")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

// ---------- system ----------

// handleCapabilities mirrors capabilities. Every optional feature reports
// false: the Go core ships no ffmpeg/WebDAV/UPnP/doc-preview/psutil/qrcode
// integrations (documented Python-only surface).
func (a *App) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hls": false, "webdav": false, "upnp": false,
		"doc_preview": map[string]any{"docx": false, "xlsx": false, "pptx": false},
		"system_stats": false, "qrcode": false,
	})
}

// diskPayload mirrors get_disk_payload.
func (a *App) diskPayload() (map[string]any, error) {
	total, free, err := upload.DiskUsageTotalFree(a.Config.Folder)
	if err != nil {
		return nil, err
	}
	used := total - free
	var percent float64
	if total > 0 {
		percent = float64(used) / float64(total) * 100
		percent = float64(int(percent*10+0.5)) / 10
	}
	threshold := a.Config.DiskWarningThreshold
	return map[string]any{
		"total": total, "used": used, "free": free,
		"percent": percent, "threshold": threshold,
		"warning": percent >= float64(threshold),
		"total_fmt": files.FmtBytes(total), "used_fmt": files.FmtBytes(used),
		"free_fmt": files.FmtBytes(free),
	}, nil
}

// handleDiskInfo mirrors disk_info.
func (a *App) handleDiskInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	disk, err := a.diskPayload()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total": disk["total"], "used": disk["used"], "free": disk["free"],
		"percent": disk["percent"], "warning": disk["warning"],
		"total_fmt": disk["total_fmt"], "used_fmt": disk["used_fmt"],
		"free_fmt": disk["free_fmt"],
	})
}

// handleDiskStatus mirrors disk_status.
func (a *App) handleDiskStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	disk, err := a.diskPayload()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"percent": disk["percent"], "free": disk["free"],
		"warning": disk["warning"], "threshold": disk["threshold"],
	})
}

// handleFolderSize mirrors folder_size.
func (a *App) handleFolderSize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	rel := subpathOf(r, "/api/folder_size/")
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "read") {
		return
	}
	valid, full, verr := permission.ValidatePath(a.Config.Folder, rel)
	if !valid {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": verr})
		return
	}
	st, err := os.Lstat(full)
	if err != nil || !st.IsDir() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "폴더가 아닙니다"})
		return
	}
	var size int64
	_ = filepath.WalkDir(full, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if st, err := os.Lstat(path); err == nil {
			size += st.Size()
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"path": rel, "size": size, "size_fmt": files.FmtBytes(size),
	})
}
