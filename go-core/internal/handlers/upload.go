package handlers

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"webshare-core/internal/files"
	"webshare-core/internal/mutate"
	"webshare-core/internal/permission"
	"webshare-core/internal/upload"
	"webshare-core/pkg/api"
)

// Upload routes mirror mutation_handlers.upload plus the chunk protocol in
// routes/upload_routes/: POST /upload/, /upload/chunk/init,
// /upload/chunk/<id>, /upload/chunk/<id>/complete, /cancel.
func (a *App) registerUploadRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/upload", a.requireAuth(a.handleUpload, false))
	mux.HandleFunc("/upload/", a.requireAuth(a.handleUpload, false))
	mux.HandleFunc("/upload/chunk/init", a.requireAuth(a.handleChunkInit, false))
	mux.HandleFunc("/upload/chunk/", a.requireAuth(a.handleChunkSub, false))
}

// bytesReceived mirrors STATS['bytes_received'].
var bytesReceived atomic.Int64

// handleUpload mirrors upload (multipart, multi-file with folder paths).
func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
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
	if r.URL.Path != "/upload" && r.URL.Path != "/upload/" {
		denyMutation(w, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if !a.checkAccess(w, r, folderpath, "write") {
		return
	}
	if _, ok := a.validate(w, r, folderpath); !ok {
		return
	}
	_ = r.ParseMultipartForm(32 << 20)
	if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) == 0 {
		denyMutation(w, http.StatusBadRequest, "파일이 없습니다")
		return
	}
	uploaded := r.MultipartForm.File["file"]
	paths := r.MultipartForm.Value["paths"]
	results := []map[string]any{}
	var totalSize int64
	for i, fh := range uploaded {
		rawName := fh.Filename
		if rawName == "" {
			continue
		}
		filename := files.SafeFilename(rawName)
		var pathsEntry string
		if len(paths) > i {
			pathsEntry = paths[i]
		}
		ok, filePath, relSave, pathErr := upload.ResolveUploadTarget(a.Config.Folder, folderpath, pathsEntry, filename)
		if !ok {
			if pathErr == "" {
				pathErr = "업로드 경로가 유효하지 않습니다"
			}
			results = append(results, map[string]any{"name": filename, "success": false, "error": pathErr})
			continue
		}
		if parent := filepath.Dir(filePath); parent != "" {
			if err := os.MkdirAll(parent, 0o755); err != nil {
				results = append(results, map[string]any{"name": filename, "success": false, "error": "업로드 경로를 생성할 수 없습니다"})
				continue
			}
		}
		if ok, _, _ := a.Perms.EnsurePathAccess(relSave, "write", s.role); !ok || permission.IsProtectedSystemPath(relSave) {
			results = append(results, map[string]any{"name": filename, "success": false, "error": "업로드 권한이 없습니다"})
			continue
		}
		if _, err := os.Lstat(filePath); err == nil {
			filePath = mutate.NextAvailablePath(filePath)
			filename = filepath.Base(filePath)
		}
		var estimated int64
		if fh.Size > 0 {
			estimated = fh.Size
		}
		diskOK, diskErr, reservation := a.Uploads.Reserve(filepath.Dir(filePath), estimated, "")
		if !diskOK {
			results = append(results, map[string]any{"name": filename, "success": false, "error": diskErr})
			continue
		}
		saveErr := func() error {
			defer a.Uploads.Release(reservation)
			src, err := fh.Open()
			if err != nil {
				return err
			}
			defer src.Close()
			return upload.SaveUpload(src, filePath)
		}()
		if saveErr != nil {
			results = append(results, map[string]any{"name": filename, "success": false, "error": "파일 저장 중 오류가 발생했습니다."})
			continue
		}
		fileSize := fileSizeOf(filePath)
		totalSize += fileSize
		a.audit(s.role, "upload", folderpath+"/"+filename, "Size: "+files.FmtBytes(fileSize), r)
		results = append(results, map[string]any{"name": filename, "success": true})
	}
	bytesReceived.Add(totalSize)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "files": results})
}

// chunkFail writes the {success:false, error} shape chunk routes use.
func chunkFail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"success": false, "error": msg})
}

// ownerOf mirrors _get_upload_owner_context.
func (a *App) ownerOf(r *http.Request) upload.Owner {
	s := SessionOf(r)
	return upload.NewOwner(s.role, a.clientIP(r), s.sid)
}

// handleChunkInit mirrors init_chunk_upload.
func (a *App) handleChunkInit(w http.ResponseWriter, r *http.Request) {
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
		chunkFail(w, status, msg)
		return
	}
	data := parseJSONBody(r)
	filename, _ := data["filename"].(string)
	if filename == "" {
		chunkFail(w, http.StatusBadRequest, "filename is required")
		return
	}
	totalSize, ok := jsonInt(data, "total_size")
	if !ok {
		chunkFail(w, http.StatusBadRequest, "total_size must be an integer")
		return
	}
	if totalSize < 0 {
		chunkFail(w, http.StatusBadRequest, "total_size must be >= 0")
		return
	}
	if totalSize > upload.MaxChunkUpload {
		chunkFail(w, http.StatusBadRequest, "total_size must be <= "+itoa(int(upload.MaxChunkUpload))+" bytes")
		return
	}
	chunkSize := int64(upload.DefaultChunkSize)
	if raw, present := data["chunk_size"]; present {
		var ok bool
		chunkSize, ok = toInt64(raw)
		if !ok {
			chunkFail(w, http.StatusBadRequest, "chunk_size must be an integer")
			return
		}
	}
	if chunkSize <= 0 || chunkSize > upload.MaxChunkSize {
		chunkFail(w, http.StatusBadRequest, "chunk_size must be in 1.."+itoa(upload.MaxChunkSize))
		return
	}
	var totalChunks int64
	if raw, present := data["total_chunks"]; present && raw != nil {
		var ok bool
		totalChunks, ok = toInt64(raw)
		if !ok {
			chunkFail(w, http.StatusBadRequest, "total_chunks must be an integer")
			return
		}
		if totalChunks < 0 {
			chunkFail(w, http.StatusBadRequest, "total_chunks must be >= 0")
			return
		}
	} else if totalSize == 0 {
		totalChunks = 0
	} else {
		totalChunks = (totalSize + chunkSize - 1) / chunkSize
	}
	if totalSize > 0 && totalChunks == 0 {
		chunkFail(w, http.StatusBadRequest, "total_chunks is invalid for non-empty upload")
		return
	}
	pathStr, _ := data["path"].(string)
	if ok, msg, code := a.Perms.EnsurePathAccess(pathStr, "write", role); !ok {
		chunkFail(w, code, msg)
		return
	}
	valid, targetDir, verr := permission.ValidatePath(a.Config.Folder, pathStr)
	if !valid {
		chunkFail(w, http.StatusBadRequest, verr)
		return
	}
	sessionID, err := upload.NewSessionID()
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	owner := upload.NewOwner(role, a.clientIP(r), s.sid)
	now := a.now()
	expired := a.Uploads.ExpiredIDs()
	active, pending := a.Uploads.Pressure(owner.Key)
	if active >= upload.MaxActivePerOwner {
		chunkFail(w, http.StatusTooManyRequests,
			"too many active upload sessions (max="+itoa(upload.MaxActivePerOwner)+")")
		removeTempDirs(expired)
		return
	}
	if pending+totalSize > upload.MaxPendingPerOwner {
		chunkFail(w, http.StatusTooManyRequests,
			"pending upload bytes limit exceeded (max="+itoa(int(upload.MaxPendingPerOwner))+")")
		removeTempDirs(expired)
		return
	}
	diskOK, diskErr, reservation := a.Uploads.Reserve(targetDir, totalSize, "chunk:"+sessionID)
	if !diskOK {
		chunkFail(w, http.StatusInsufficientStorage, diskErr)
		removeTempDirs(expired)
		return
	}
	tempDir := filepath.Join(targetDir, ".upload_temp", sessionID)
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		a.Uploads.Release(reservation)
		removeTempDirs(expired)
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.Uploads.Put(sessionID, &upload.Session{
		Filename:        files.SafeFilename(filename),
		TotalSize:       totalSize,
		ChunkSize:       chunkSize,
		TotalChunks:     totalChunks,
		TargetDir:       targetDir,
		TempDir:         tempDir,
		Chunks:          map[int64]upload.ChunkEntry{},
		Created:         now,
		UpdatedAt:       now,
		Expires:         now.Add(upload.SessionTTL),
		OwnerRole:       owner.Role,
		OwnerIP:         owner.IP,
		OwnerSessionID:  owner.SessionID,
		OwnerKey:        owner.Key,
		DiskReservation: reservation,
	})
	removeTempDirs(expired)
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "session_id": sessionID,
		"chunk_size": chunkSize, "total_chunks": totalChunks,
	})
}

func removeTempDirs(expired [][2]string) {
	for _, pair := range expired {
		if pair[1] != "" {
			os.RemoveAll(pair[1])
		}
	}
}

// handleChunkSub dispatches /upload/chunk/<id>, /complete, /cancel.
func (a *App) handleChunkSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/upload/chunk/")
	if strings.HasSuffix(rest, "/complete") {
		a.handleChunkComplete(w, r, strings.TrimSuffix(rest, "/complete"))
		return
	}
	if strings.HasSuffix(rest, "/cancel") {
		a.handleChunkCancel(w, r, strings.TrimSuffix(rest, "/cancel"))
		return
	}
	if rest == "" || strings.Contains(rest, "/") {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	a.handleChunkTransfer(w, r, rest)
}

// handleChunkTransfer mirrors upload_chunk.
func (a *App) handleChunkTransfer(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	owner := a.ownerOf(r)
	us := a.Uploads.Get(sessionID)
	if us == nil {
		chunkFail(w, http.StatusBadRequest, "invalid upload session")
		return
	}
	if !us.IsOwner(owner) {
		chunkFail(w, http.StatusForbidden, "session ownership mismatch")
		return
	}
	tempDir := us.TempDir
	if a.now().After(us.Expires) {
		a.Uploads.Cleanup(sessionID, us.TempDir)
		chunkFail(w, http.StatusBadRequest, "upload session expired")
		return
	}
	if msg, status, ok := a.mutationAllowed(owner.Role); !ok {
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, status, msg)
		return
	}
	_ = r.ParseMultipartForm(32 << 20)
	var index int64 = -1
	var chunkReader io.Reader
	if r.MultipartForm != nil {
		if vals := r.MultipartForm.Value["index"]; len(vals) > 0 {
			if n, err := strconv.ParseInt(strings.TrimSpace(vals[0]), 10, 64); err == nil {
				index = n
			} else {
				index = -1
			}
		}
		if fhs := r.MultipartForm.File["chunk"]; len(fhs) > 0 {
			fh, err := fhs[0].Open()
			if err == nil {
				defer fh.Close()
				chunkReader = fh
			}
		}
	}
	if index < 0 || chunkReader == nil {
		chunkFail(w, http.StatusBadRequest, "invalid chunk payload")
		return
	}
	// Re-read under lock (parity with the second locked section).
	us = a.Uploads.Get(sessionID)
	if us == nil {
		chunkFail(w, http.StatusBadRequest, "invalid upload session")
		return
	}
	if !us.IsOwner(owner) {
		chunkFail(w, http.StatusForbidden, "session ownership mismatch")
		return
	}
	if us.TotalChunks > 0 && index >= us.TotalChunks {
		chunkFail(w, http.StatusBadRequest, "chunk index out of range")
		return
	}
	existingSize := us.Chunks[index].Size
	limit := us.ChunkSize
	if limit == 0 {
		limit = upload.MaxChunkSize
	}
	declared := us.TotalSize
	already := us.UploadedBytes - existingSize
	if already < 0 {
		already = 0
	}
	remaining := declared - already
	if remaining < 0 {
		remaining = 0
	}
	chunkPath := filepath.Join(tempDir, "chunk_"+zeroPad5(index))
	size, err := upload.SaveChunk(chunkReader, chunkPath, limit, remaining)
	if err != nil {
		os.Remove(chunkPath)
		a.Uploads.Update(sessionID, func(s *upload.Session) {
			// Parity: rejected_bytes += max(0, max_total_remaining + 1).
			if remaining+1 > 0 {
				s.RejectedBytes += remaining + 1
			}
		})
		a.Uploads.Cleanup(sessionID, tempDir)
		msg := "invalid chunk payload"
		switch {
		case err == upload.ErrChunkTooLarge:
			msg = "chunk size exceeds declared chunk_size"
		case err == upload.ErrTotalExceeded:
			msg = "uploaded bytes exceed declared total_size"
		}
		chunkFail(w, http.StatusBadRequest, msg)
		return
	}
	a.Uploads.Update(sessionID, func(s *upload.Session) {
		updated := s.UploadedBytes - existingSize + size
		if updated < 0 {
			updated = 0
		}
		s.UploadedBytes = updated
		s.UpdatedAt = a.now()
		if s.Chunks == nil {
			s.Chunks = map[int64]upload.ChunkEntry{}
		}
		s.Chunks[index] = upload.ChunkEntry{Path: chunkPath, Size: size}
	})
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "index": index})
}

func zeroPad5(n int64) string {
	s := itoa(int(n))
	for len(s) < 5 {
		s = "0" + s
	}
	return s
}

// handleChunkComplete mirrors complete_chunk_upload.
func (a *App) handleChunkComplete(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	owner := a.ownerOf(r)
	us := a.Uploads.Get(sessionID)
	if us == nil {
		chunkFail(w, http.StatusBadRequest, "invalid upload session")
		return
	}
	if !us.IsOwner(owner) {
		chunkFail(w, http.StatusForbidden, "session ownership mismatch")
		return
	}
	status := us.Status
	if status == "" {
		status = upload.StatusActive
	}
	if status == upload.StatusCompleted {
		name := us.CommittedName
		if name == "" {
			name = us.Filename
		}
		writeJSON(w, http.StatusOK, map[string]any{"success": true, "filename": name, "idempotent": true})
		return
	}
	if status == upload.StatusCompleting {
		chunkFail(w, http.StatusConflict, "upload already completing")
		return
	}
	a.Uploads.Update(sessionID, func(s *upload.Session) { s.Status = upload.StatusCompleting })
	// Snapshot under lock.
	us = a.Uploads.Get(sessionID)
	filename, targetDir, tempDir := us.Filename, us.TargetDir, us.TempDir
	totalSize, totalChunks, uploaded := us.TotalSize, us.TotalChunks, us.UploadedBytes
	chunks := map[int64]upload.ChunkEntry{}
	for k, v := range us.Chunks {
		chunks[k] = v
	}

	if msg, status, ok := a.mutationAllowed(owner.Role); !ok {
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, status, msg)
		return
	}
	committed := ""
	mergeTmp := ""
	cleanupFail := func(status int, msg string) {
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, status, msg)
	}
	if totalSize > 0 && len(chunks) == 0 {
		cleanupFail(http.StatusBadRequest, "no uploaded chunks")
		return
	}
	if totalChunks > 0 {
		indexes := make([]int64, 0, len(chunks))
		for k := range chunks {
			indexes = append(indexes, k)
		}
		sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
		if int64(len(indexes)) != totalChunks {
			cleanupFail(http.StatusBadRequest, "chunk set is incomplete or out of order")
			return
		}
		for i, v := range indexes {
			if v != int64(i) {
				cleanupFail(http.StatusBadRequest, "chunk set is incomplete or out of order")
				return
			}
		}
	}
	if uploaded != totalSize {
		cleanupFail(http.StatusBadRequest,
			"uploaded size mismatch (expected="+itoa(int(totalSize))+", uploaded="+itoa(int(uploaded))+")")
		return
	}
	targetPath := filepath.Join(targetDir, filename)
	relTarget, err := filepath.Rel(a.Config.Folder, targetPath)
	if err != nil {
		cleanupFail(http.StatusBadRequest, "잘못된 경로입니다")
		return
	}
	relTarget = strings.ReplaceAll(relTarget, "\\", "/")
	if ok, msg, code := a.Perms.EnsurePathAccess(relTarget, "write", owner.Role); !ok {
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, code, msg)
		return
	}
	if _, err := os.Lstat(targetPath); err == nil {
		name, ext := splitExt(filename)
		for counter := 1; ; counter++ {
			candidate := filepath.Join(targetDir, name+"_"+itoa(counter)+ext)
			if _, err := os.Lstat(candidate); os.IsNotExist(err) {
				targetPath = candidate
				break
			}
		}
	}
	for idx, ce := range chunks {
		if ce.Path == "" {
			cleanupFail(http.StatusBadRequest, "missing chunk file: "+itoa(int(idx)))
			return
		}
		if _, err := os.Stat(ce.Path); err != nil {
			cleanupFail(http.StatusBadRequest, "missing chunk file: "+itoa(int(idx)))
			return
		}
	}
	merge, err := os.CreateTemp(targetDir, ".webshare_merge_*.tmp")
	if err != nil {
		a.reactivate(sessionID)
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, http.StatusInternalServerError, "chunk upload merge failed")
		return
	}
	mergeTmp = merge.Name()
	indexes := make([]int64, 0, len(chunks))
	for k := range chunks {
		indexes = append(indexes, k)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	mergeErr := func() error {
		defer merge.Close()
		buf := make([]byte, upload.SaveIOChunkSize)
		for _, idx := range indexes {
			f, err := os.Open(chunks[idx].Path)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyBuffer(merge, f, buf)
			f.Close()
			if copyErr != nil {
				return copyErr
			}
		}
		return nil
	}()
	if mergeErr != nil {
		os.Remove(mergeTmp)
		a.reactivate(sessionID)
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, http.StatusInternalServerError, "chunk upload merge failed")
		return
	}
	st, err := os.Stat(mergeTmp)
	if err != nil {
		os.Remove(mergeTmp)
		a.reactivate(sessionID)
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, http.StatusInternalServerError, "chunk upload merge failed")
		return
	}
	if st.Size() != totalSize {
		os.Remove(mergeTmp)
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, http.StatusBadRequest,
			"merged size mismatch (expected="+itoa(int(totalSize))+", actual="+itoa(int(st.Size()))+")")
		return
	}
	if err := os.Rename(mergeTmp, targetPath); err != nil {
		os.Remove(mergeTmp)
		a.reactivate(sessionID)
		a.Uploads.Cleanup(sessionID, tempDir)
		chunkFail(w, http.StatusInternalServerError, "chunk upload merge failed")
		return
	}
	committed = filepath.Base(targetPath)
	now := a.now()
	a.Uploads.Update(sessionID, func(s *upload.Session) {
		s.Status = upload.StatusCompleted
		s.CommittedName = committed
		s.Expires = now.Add(upload.CompletedTTL)
		s.Chunks = nil
		s.DiskReservation = ""
	})
	a.Uploads.Release(us.DiskReservation)
	os.RemoveAll(tempDir)
	a.audit(owner.Role, "upload_chunk_complete", committed, "size: "+files.FmtBytes(totalSize), r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "filename": committed})
}

// reactivate resets a completing session to active (parity with the except path).
func (a *App) reactivate(sessionID string) {
	a.Uploads.Update(sessionID, func(s *upload.Session) {
		if s.Status == upload.StatusCompleting {
			s.Status = upload.StatusActive
		}
	})
}

// handleChunkCancel mirrors cancel_chunk_upload.
func (a *App) handleChunkCancel(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		api.Error(w, r, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
		return
	}
	owner := a.ownerOf(r)
	us := a.Uploads.Get(sessionID)
	if us == nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
		return
	}
	if !us.IsOwner(owner) {
		chunkFail(w, http.StatusForbidden, "session ownership mismatch")
		return
	}
	if msg, status, ok := a.mutationAllowed(owner.Role); !ok {
		chunkFail(w, status, msg)
		return
	}
	a.Uploads.Cleanup(sessionID, us.TempDir)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func splitExt(name string) (stem, ext string) {
	ext = filepath.Ext(name)
	return strings.TrimSuffix(name, ext), ext
}

// jsonInt mirrors int(data.get(...)) with strict failure.
func jsonInt(doc map[string]any, key string) (int64, bool) {
	raw, present := doc[key]
	if !present || raw == nil {
		return 0, false
	}
	return toInt64(raw)
}

// toInt64 mirrors Python int() on JSON values: bools → 0/1, floats
// truncate, numeric strings parse, everything else fails.
func toInt64(raw any) (int64, bool) {
	switch v := raw.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case float64:
		return int64(v), true
	case int:
		return int64(v), true
	case int64:
		return v, true
	case string:
		// Parity: int("5") works, int("5.7") fails.
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n, true
		}
		return 0, false
	default:
		return 0, false
	}
}
