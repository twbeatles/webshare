package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"webshare-core/internal/files"
	"webshare-core/internal/mutate"
	"webshare-core/internal/permission"
	"webshare-core/pkg/api"
)

// Mutation routes mirror routes/file_routes/mutation_handlers.py:
// POST /mkdir/, /delete/, /rename/, /copy, /move, /batch_delete/, /unzip/.
// Success-shaped answers ({success: ...}) are written verbatim like
// jsonify; unexpected failures use the normalized api.Error (api_exception).
func (a *App) registerMutationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/mkdir", a.requireAuth(a.handleMkdir, false))
	mux.HandleFunc("/mkdir/", a.requireAuth(a.handleMkdir, false))
	mux.HandleFunc("/delete/", a.requireAuth(a.handleDelete, false))
	mux.HandleFunc("/rename/", a.requireAuth(a.handleRename, false))
	mux.HandleFunc("/copy", a.requireAuth(a.handleCopy, false))
	mux.HandleFunc("/move", a.requireAuth(a.handleMove, false))
	mux.HandleFunc("/batch_delete/", a.requireAuth(a.handleBatchDelete, false))
	mux.HandleFunc("/unzip/", a.requireAuth(a.handleUnzip, false))
}

// mutationAllowed mirrors ensure_mutation_allowed: admins always, guests only
// with allow_guest_upload.
func (a *App) mutationAllowed(role string) (string, int, bool) {
	if role == "admin" {
		return "", 200, true
	}
	if role != "" && role != "guest" {
		role = "guest"
	}
	if a.Config.AllowGuestUpload {
		return "", 200, true
	}
	return "업로드/변경 권한이 없습니다", http.StatusForbidden, false
}

// denyMutation writes the plain jsonify error shape the mutation routes use.
func denyMutation(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

// successFalse writes the plain {success:false, error} shape (HTTP 200)
// the copy/move routes use for business failures.
func successFalse(w http.ResponseWriter, message string) {
	writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": message})
}

// parseJSONBody mirrors parse_json_body: silent JSON dict or {}.
func parseJSONBody(r *http.Request) map[string]any {
	out := map[string]any{}
	if r.Body == nil {
		return out
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if len(body) == 0 {
		return out
	}
	var doc map[string]any
	if err == nil {
		if json.Unmarshal(body, &doc) == nil && doc != nil {
			return doc
		}
	}
	return out
}

func jsonString(doc map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, _ := doc[k].(string); s != "" {
			return s
		}
	}
	return ""
}

// handleMkdir mirrors mkdir.
func (a *App) handleMkdir(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	s := SessionOf(r)
	if msg, status, ok := a.mutationAllowed(s.role); !ok {
		denyMutation(w, status, msg)
		return
	}
	var folderpath string
	if r.URL.Path != "/mkdir" && r.URL.Path != "/mkdir/" {
		folderpath = subpathOf(r, "/mkdir/")
	}
	if !a.checkAccess(w, r, folderpath, "write") {
		return
	}
	data := parseJSONBody(r)
	folderName := jsonString(data, "name")
	if folderName == "" {
		denyMutation(w, http.StatusBadRequest, "폴더 이름이 필요합니다")
		return
	}
	folderName = files.SafeFilename(folderName)
	parent, ok := a.validate(w, r, folderpath)
	if !ok {
		return
	}
	newRel := strings.ReplaceAll(filepath.Join(folderpath, folderName), "\\", "/")
	if !a.checkAccess(w, r, newRel, "write") {
		return
	}
	newFolder := filepath.Join(parent, folderName)
	if _, err := os.Lstat(newFolder); err == nil {
		denyMutation(w, http.StatusBadRequest, "이미 존재하는 폴더입니다")
		return
	}
	if err := os.MkdirAll(newFolder, 0o755); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(s.role, "mkdir", folderpath+"/"+folderName, "", r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleDelete mirrors delete (trash).
func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		denyMutation(w, status, msg)
		return
	}
	rel := subpathOf(r, "/delete/")
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, rel, "delete") {
		return
	}
	full, ok := a.validate(w, r, rel)
	if !ok {
		return
	}
	if _, err := os.Lstat(full); err != nil {
		denyMutation(w, http.StatusNotFound, "파일을 찾을 수 없습니다")
		return
	}
	trashName, err := mutate.MoveToTrash(a.Config.Folder, full, a.now())
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(role, "delete", rel, "Moved to trash: "+trashName, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleRename mirrors rename.
func (a *App) handleRename(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		denyMutation(w, status, msg)
		return
	}
	filepathRel := subpathOf(r, "/rename/")
	if filepathRel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	data := parseJSONBody(r)
	newName := jsonString(data, "name", "new_name")
	oldName := jsonString(data, "old_name")
	if newName == "" {
		denyMutation(w, http.StatusBadRequest, "새 이름이 필요합니다")
		return
	}
	newName = files.SafeFilename(newName)
	var fullPath, newPath string
	if oldName != "" {
		oldRel := strings.ReplaceAll(filepath.Join(filepathRel, files.SafeFilename(oldName)), "\\", "/")
		if !a.checkAccess(w, r, oldRel, "delete") {
			return
		}
		if !a.checkAccess(w, r, filepathRel, "write") {
			return
		}
		parent, ok := a.validate(w, r, filepathRel)
		if !ok {
			return
		}
		fullPath = filepath.Join(parent, files.SafeFilename(oldName))
		newPath = filepath.Join(parent, newName)
	} else {
		if !a.checkAccess(w, r, filepathRel, "delete") {
			return
		}
		full, ok := a.validate(w, r, filepathRel)
		if !ok {
			return
		}
		fullPath = full
		parentRel := strings.ReplaceAll(filepath.Dir(filepathRel), "\\", "/")
		if !a.checkAccess(w, r, parentRel, "write") {
			return
		}
		newPath = filepath.Join(filepath.Dir(full), newName)
	}
	if _, err := os.Lstat(fullPath); err != nil {
		denyMutation(w, http.StatusNotFound, "파일을 찾을 수 없습니다")
		return
	}
	if _, err := os.Lstat(newPath); err == nil {
		denyMutation(w, http.StatusBadRequest, "동일한 이름이 이미 존재합니다")
		return
	}
	if err := os.Rename(fullPath, newPath); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(role, "rename", filepathRel, "New name: "+newName, r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// copyMoveParams holds the shared JSON params of copy/move.
type copyMoveParams struct {
	src    string
	dst    string
	policy string
}

func parseCopyMove(data map[string]any) copyMoveParams {
	src, _ := data["source"].(string)
	dst, _ := data["destination"].(string)
	policy, _ := data["conflict_policy"].(string)
	return copyMoveParams{
		src:    src,
		dst:    dst,
		policy: mutate.NormalizeConflictPolicy(policy, mutate.ConflictRename),
	}
}

// checkCopyMoveAccess mirrors the shared permission gates of copy/move.
func (a *App) checkCopyMoveAccess(w http.ResponseWriter, r *http.Request, srcAction string, p copyMoveParams) bool {
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		writeJSON(w, status, map[string]any{"success": false, "error": msg})
		return false
	}
	if ok, msg, code := a.Perms.EnsurePathAccess(p.src, srcAction, role); !ok {
		writeJSON(w, code, map[string]any{"success": false, "error": msg})
		return false
	}
	if ok, msg, code := a.Perms.EnsurePathAccess(p.dst, "write", role); !ok {
		writeJSON(w, code, map[string]any{"success": false, "error": msg})
		return false
	}
	if p.policy == mutate.ConflictOverwrite {
		if ok, msg, code := a.Perms.EnsurePathAccess(p.dst, "delete", role); !ok {
			writeJSON(w, code, map[string]any{"success": false, "error": msg})
			return false
		}
	}
	return true
}

// resolveCopyMove mirrors the shared path validation of copy/move.
// op is "copy" or "move" (only used for the self-descendant message).
func (a *App) resolveCopyMove(w http.ResponseWriter, op string, p copyMoveParams) (fullSrc, fullDst string, ok bool) {
	validSrc, src, _ := permission.ValidatePath(a.Config.Folder, p.src)
	validDst, dst, _ := permission.ValidatePath(a.Config.Folder, p.dst)
	if !validSrc || !validDst {
		successFalse(w, "잘못된 경로입니다.")
		return "", "", false
	}
	if _, err := os.Lstat(src); err != nil {
		successFalse(w, "원본을 찾을 수 없습니다.")
		return "", "", false
	}
	if mutate.NormcasePath(src) == mutate.NormcasePath(dst) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error": "원본과 대상 경로가 같습니다."})
		return "", "", false
	}
	if st, err := os.Lstat(src); err == nil && st.IsDir() && mutate.IsDescendantPath(src, dst) {
		if op == "move" {
			successFalse(w, "자기 자신의 하위 폴더로 이동할 수 없습니다.")
		} else {
			successFalse(w, "자기 자신의 하위 폴더로 복사할 수 없습니다.")
		}
		return "", "", false
	}
	return src, dst, true
}

// handleCopy mirrors copy_item.
func (a *App) handleCopy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	p := parseCopyMove(parseJSONBody(r))
	if !a.checkCopyMoveAccess(w, r, "read", p) {
		return
	}
	fullSrc, fullDst, ok := a.resolveCopyMove(w, "copy", p)
	if !ok {
		return
	}
	resolved, finalDst, conflictErr := mutate.ResolveConflictPath(fullDst, p.policy)
	if !resolved {
		writeJSON(w, http.StatusConflict, map[string]any{
			"success": false, "error": conflictErr, "code": "DESTINATION_EXISTS",
		})
		return
	}
	if p.policy == mutate.ConflictOverwrite {
		if err := mutate.CreateOverwriteVersions(a.Config.Folder, finalDst, a.Config.EnableVersioning, a.now(), permission.IsProtectedSystemPath); err != nil {
			api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
			return
		}
	}
	if err := mutate.CopyPath(fullSrc, finalDst); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	finalRel, err := filepath.Rel(a.Config.Folder, finalDst)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	finalRel = strings.ReplaceAll(finalRel, "\\", "/")
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "unknown"
	}
	a.audit(role, "copy", p.src, "To: "+finalRel+", conflict_policy: "+p.policy, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "path": finalRel, "conflict_policy": p.policy,
	})
}

// handleMove mirrors move_item.
func (a *App) handleMove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	p := parseCopyMove(parseJSONBody(r))
	if !a.checkCopyMoveAccess(w, r, "delete", p) {
		return
	}
	fullSrc, fullDst, ok := a.resolveCopyMove(w, "move", p)
	if !ok {
		return
	}
	resolved, finalDst, conflictErr := mutate.ResolveConflictPath(fullDst, p.policy)
	if !resolved {
		writeJSON(w, http.StatusConflict, map[string]any{
			"success": false, "error": conflictErr, "code": "DESTINATION_EXISTS",
		})
		return
	}
	if p.policy == mutate.ConflictOverwrite {
		if err := mutate.CreateOverwriteVersions(a.Config.Folder, finalDst, a.Config.EnableVersioning, a.now(), permission.IsProtectedSystemPath); err != nil {
			api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
			return
		}
		if st, err := os.Lstat(fullSrc); err == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			if err := mutate.MoveDirOverwrite(a.Config.Folder, fullSrc, finalDst, false, a.now(), nil); err != nil {
				api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
				return
			}
		} else if err := mutate.MovePath(fullSrc, finalDst); err != nil {
			api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
			return
		}
	} else if err := mutate.MovePath(fullSrc, finalDst); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	finalRel, err := filepath.Rel(a.Config.Folder, finalDst)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	finalRel = strings.ReplaceAll(finalRel, "\\", "/")
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "unknown"
	}
	a.audit(role, "move", p.src, "To: "+finalRel+", conflict_policy: "+p.policy, r)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "path": finalRel, "conflict_policy": p.policy,
	})
}

// handleBatchDelete mirrors batch_delete.
func (a *App) handleBatchDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		denyMutation(w, status, msg)
		return
	}
	dirRel := subpathOf(r, "/batch_delete/")
	if dirRel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, dirRel, "delete") {
		return
	}
	currentDir, ok := a.validate(w, r, dirRel)
	if !ok {
		return
	}
	data := parseJSONBody(r)
	var names []string
	if raw, present := data["files"]; present {
		if list, isList := raw.([]any); isList {
			for _, item := range list {
				if name, isStr := item.(string); isStr {
					names = append(names, name)
				}
			}
		}
	}
	deleted := []string{}
	failed := []map[string]string{}
	count := 0
	for _, itemName := range names {
		itemPath := filepath.Join(currentDir, files.SafeFilename(itemName))
		itemRel, err := filepath.Rel(a.Config.Folder, itemPath)
		if err != nil {
			failed = append(failed, map[string]string{"name": itemName, "error": "Not found"})
			continue
		}
		itemRel = strings.ReplaceAll(itemRel, "\\", "/")
		if ok, _, _ := a.Perms.EnsurePathAccess(itemRel, "delete", role); !ok {
			failed = append(failed, map[string]string{"name": itemName, "error": "Permission denied"})
			continue
		}
		if _, err := os.Lstat(itemPath); err != nil {
			failed = append(failed, map[string]string{"name": itemName, "error": "Not found"})
			continue
		}
		if _, err := mutate.MoveToTrash(a.Config.Folder, itemPath, a.now()); err != nil {
			failed = append(failed, map[string]string{"name": itemName, "error": err.Error()})
			continue
		}
		deleted = append(deleted, itemName)
		count++
	}
	_ = deleted
	if count > 0 {
		auditRole := s.role
		if auditRole == "" {
			auditRole = "unknown"
		}
		a.audit(auditRole, "batch_delete", dirRel,
			itoa(count)+"개 성공, "+itoa(len(failed))+"개 실패", r)
	}
	if failed == nil {
		failed = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "deleted": count, "failed": len(failed), "failed_items": failed,
	})
}

// handleUnzip mirrors unzip_file.
func (a *App) handleUnzip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
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
	rel := subpathOf(r, "/unzip/")
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if ok, msg, code := a.Perms.EnsurePathAccess(rel, "read", role); !ok {
		fail(code, msg)
		return
	}
	valid, zipPath, verr := permission.ValidatePath(a.Config.Folder, rel)
	if !valid {
		fail(http.StatusBadRequest, verr)
		return
	}
	if _, err := os.Lstat(zipPath); err != nil {
		fail(http.StatusNotFound, "파일을 찾을 수 없습니다.")
		return
	}
	stripExt := zipPath
	if ext := filepath.Ext(zipPath); ext != "" {
		stripExt = strings.TrimSuffix(zipPath, ext)
	}
	extractTo := mutate.NextAvailableDirectoryPath(stripExt)
	extractRel, err := filepath.Rel(a.Config.Folder, extractTo)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	extractRel = strings.ReplaceAll(extractRel, "\\", "/")
	if ok, msg, code := a.Perms.EnsurePathAccess(extractRel, "write", role); !ok {
		fail(code, msg)
		return
	}
	if err := mutate.UnzipArchive(zipPath, extractTo); err != nil {
		var uzErr *mutate.UnzipError
		if errors.As(err, &uzErr) {
			fail(uzErr.Status, uzErr.Msg)
			return
		}
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
