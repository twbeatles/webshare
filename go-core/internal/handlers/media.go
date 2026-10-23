package handlers

// Media and convenience routes used by the full web UI (audit ISSUE-003):
// text viewer/editor, range streaming, audio playlist, image gallery,
// document preview, recent files, clipboard, metrics, and the legacy
// /disk_info + /disk_status paths. They mirror media_routes/*.py,
// root_api_routes.py and browse_handlers.clipboard_handler.

import (
	"archive/zip"
	"bytes"
	"container/list"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"webshare-core/internal/files"
	"webshare-core/internal/mutate"
	"webshare-core/internal/permission"
	"webshare-core/internal/quota"
	"webshare-core/pkg/api"
)

// Limits mirror services/media_service.py and file_routes/_common.py.
const (
	maxTextEditSize        = 10 * 1024 * 1024
	maxDocumentPreviewSize = 25 * 1024 * 1024
	maxClipboardEntries    = 200
	maxClipboardBytes      = 256 * 1024
	maxRecentFiles         = 20
)

var (
	audioPlaylistExts = map[string]bool{".mp3": true, ".wav": true, ".ogg": true, ".m4a": true, ".flac": true, ".aac": true, ".wma": true}
	galleryImageExts  = map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".bmp": true, ".svg": true}
)

// mediaState holds the per-owner recent-files and clipboard tables
// (RECENT_FILES / _clipboard_store parity, in memory like Python).
type mediaState struct {
	mu        sync.Mutex
	recent    map[string][]recentFile
	clipboard map[string]*list.Element
	clipOrder *list.List // LRU of clipEntry, front = oldest
	startedAt time.Time
	requests  atomic.Int64
	bytesSent atomic.Int64
}

type recentFile struct {
	Path     string `json:"path"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Accessed string `json:"accessed"`
}

type clipEntry struct {
	owner   string
	content string
}

func newMediaState() *mediaState {
	return &mediaState{
		recent:    map[string][]recentFile{},
		clipboard: map[string]*list.Element{},
		clipOrder: list.New(),
		startedAt: time.Now(),
	}
}

func (a *App) registerMediaRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/get_content/", a.requireAuth(a.handleGetContent, false))
	mux.HandleFunc("/save_content/", a.requireAuth(a.handleSaveContent, false))
	mux.HandleFunc("/stream/", a.requireAuth(a.handleStream, false))
	mux.HandleFunc("/playlist/", a.requireAuth(a.handlePlaylist, false))
	mux.HandleFunc("/gallery/", a.requireAuth(a.handleGallery, false))
	mux.HandleFunc("/preview/", a.requireAuth(a.handlePreview, false))
	mux.HandleFunc("/recent_files", a.requireAuth(a.handleRecentFiles, false))
	mux.HandleFunc("/clipboard", a.requireAuth(a.handleClipboard, false))
	mux.HandleFunc("/metrics", a.requireAuth(a.handleMetrics, false))
	mux.HandleFunc("/api/dashboard/summary", a.requireAuth(a.handleDashboardSummary, false))
	mux.HandleFunc("/disk_info", a.requireAuth(a.handleDiskInfo, false))
	mux.HandleFunc("/disk_status", a.requireAuth(a.handleDiskStatus, false))
}

// recentOwnerKey mirrors build_recent_owner_key.
func (a *App) recentOwnerKey(r *http.Request) string {
	s := SessionOf(r)
	if s.sid != "" {
		return s.sid
	}
	role := s.role
	if role == "" {
		role = "guest"
	}
	return role + ":" + a.clientIP(r)
}

// addRecentFile mirrors add_recent_file (most recent first, max 20).
func (a *App) addRecentFile(r *http.Request, rel, fullPath string) {
	owner := a.recentOwnerKey(r)
	entry := recentFile{
		Path:     rel,
		Name:     filepath.Base(fullPath),
		Type:     files.FileType(filepath.Ext(fullPath)),
		Accessed: isoNow(a.now()),
	}
	m := a.media
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := m.recent[owner]
	out := make([]recentFile, 0, len(entries)+1)
	out = append(out, entry)
	for _, e := range entries {
		if e.Path != rel {
			out = append(out, e)
		}
	}
	if len(out) > maxRecentFiles {
		out = out[:maxRecentFiles]
	}
	m.recent[owner] = out
}

func isoNow(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += "." + zeroPadN(us, 6)
	}
	return s
}

func zeroPadN(n, width int) string {
	s := itoa(n)
	for len(s) < width {
		s = "0" + s
	}
	return s
}

// resolveFile runs access + path validation for a file route; it answers
// the error itself and returns ok=false on failure.
func (a *App) resolveFile(w http.ResponseWriter, r *http.Request, prefix, action string, notFound int) (rel, full string, st os.FileInfo, ok bool) {
	rel = permission.NormalizeRelativePath(subpathOf(r, prefix))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return "", "", nil, false
	}
	if !a.checkAccess(w, r, rel, action) {
		return "", "", nil, false
	}
	valid, full, msg := permission.ValidatePath(a.conf().Folder, rel)
	if !valid {
		api.Error(w, r, http.StatusForbidden, msg)
		return "", "", nil, false
	}
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		writeJSON(w, notFound, map[string]any{"error": "파일을 찾을 수 없습니다."})
		return "", "", nil, false
	}
	return rel, full, st, true
}

// handleGetContent mirrors get_content: UTF-8 text (invalid bytes dropped).
func (a *App) handleGetContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	rel, full, st, ok := a.resolveFile(w, r, "/get_content/", "read", http.StatusNotFound)
	if !ok {
		return
	}
	if st.Size() > maxTextEditSize {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error":     "파일 크기가 너무 큽니다. 최대 " + itoa(maxTextEditSize/(1024*1024)) + "MB까지 편집할 수 있습니다.",
			"max_bytes": maxTextEditSize, "file_size": st.Size(),
		})
		return
	}
	data, err := os.ReadFile(full)
	if err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.addRecentFile(r, rel, full)
	writeJSON(w, http.StatusOK, map[string]any{"content": dropInvalidUTF8(data)})
}

// dropInvalidUTF8 mirrors open(..., errors='ignore').
func dropInvalidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r != utf8.RuneError || size > 1 {
			sb.WriteRune(r)
		}
		b = b[size:]
	}
	return sb.String()
}

// handleSaveContent mirrors save_content: version backup, then atomic write.
func (a *App) handleSaveContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, r)
		return
	}
	s := SessionOf(r)
	role := s.role
	if role == "" {
		role = "guest"
	}
	fail := func(status int, msg string) {
		writeJSON(w, status, map[string]any{"success": false, "error": msg})
	}
	if msg, status, ok := a.mutationAllowed(role); !ok {
		fail(status, msg)
		return
	}
	rel := permission.NormalizeRelativePath(subpathOf(r, "/save_content/"))
	if rel == "" {
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	if ok, msg, code := a.Perms.EnsurePathAccess(rel, "write", role); !ok {
		fail(code, msg)
		return
	}
	valid, full, msg := permission.ValidatePath(a.conf().Folder, rel)
	if !valid {
		fail(http.StatusForbidden, msg)
		return
	}
	data := parseJSONBody(r)
	var content string
	switch v := data["content"].(type) {
	case string:
		content = v
	case nil:
		content = ""
	default:
		raw, _ := json.Marshal(v)
		content = string(raw)
	}
	if len(content) > maxTextEditSize {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"success":   false,
			"error":     "저장할 내용이 너무 큽니다. 최대 " + itoa(maxTextEditSize/(1024*1024)) + "MB까지 저장할 수 있습니다.",
			"max_bytes": maxTextEditSize, "content_size": len(content),
		})
		return
	}
	cfg := a.conf()
	mutate.CreateFileVersion(cfg.Folder, full, cfg.EnableVersioning, a.now())
	if err := mutate.AtomicWriteFile(full, []byte(content)); err != nil {
		api.Error(w, r, http.StatusInternalServerError, "서버 내부 오류가 발생했습니다.")
		return
	}
	a.audit(role, "file_edit", rel, "크기: "+itoa(len(content))+" 바이트", r)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// handleStream mirrors stream_media: inline range streaming. Bytes are
// reserved against the bandwidth quota (no download count) and settled to
// what was actually delivered.
func (a *App) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/stream/hls/") {
		// HLS transcoding needs ffmpeg and stays a Python-backend feature;
		// the UI falls back to direct streaming on the Go backend.
		api.Error(w, r, http.StatusNotFound, "NOT_FOUND")
		return
	}
	rel, full, st, ok := a.resolveFile(w, r, "/stream/", "read", http.StatusNotFound)
	if !ok {
		return
	}
	s := SessionOf(r)
	cfg := a.conf()
	allowed, msg, reservation := a.Quota.ReserveClient(quota.KeySet(s.sid, a.clientIP(r)), false, st.Size(),
		int64(cfg.DailyDownloadLimit), int64(cfg.DailyBandwidthLimitMB))
	if !allowed {
		api.Error(w, r, http.StatusTooManyRequests, msg)
		return
	}
	if rng := r.Header.Get("Range"); rng == "" || strings.HasPrefix(strings.TrimSpace(rng), "bytes=0-") {
		a.addRecentFile(r, rel, full)
	}
	cw := &countingWriter{ResponseWriter: w}
	files.ServeFileWithDisposition(cw, r, full, st.Name(), false)
	a.Quota.Settle(reservation, cw.written)
	a.media.bytesSent.Add(cw.written)
}

// folderListing collects readable entries of a folder route whose
// extension is in exts (playlist / gallery parity).
func (a *App) folderListing(w http.ResponseWriter, r *http.Request, prefix string, exts map[string]bool) (string, []string, bool) {
	rel := permission.NormalizeRelativePath(subpathOf(r, prefix))
	if !a.checkAccess(w, r, rel, "read") {
		return "", nil, false
	}
	valid, full, _ := permission.ValidatePath(a.conf().Folder, rel)
	st, err := os.Stat(full)
	if !valid || err != nil || !st.IsDir() {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "폴더를 찾을 수 없습니다."})
		return "", nil, false
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "폴더를 찾을 수 없습니다."})
		return "", nil, false
	}
	role := SessionOf(r).role
	var out []string
	for _, e := range entries {
		if !exts[strings.ToLower(filepath.Ext(e.Name()))] {
			continue
		}
		itemRel := strings.TrimPrefix(rel+"/"+e.Name(), "/")
		if ok, _, _ := a.Perms.EnsurePathAccess(itemRel, "read", role); !ok {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return rel, out, true
}

func joinRel(folder, name string) string {
	if folder == "" {
		return name
	}
	return folder + "/" + name
}

// handlePlaylist mirrors get_playlist.
func (a *App) handlePlaylist(w http.ResponseWriter, r *http.Request) {
	folder, names, ok := a.folderListing(w, r, "/playlist/", audioPlaylistExts)
	if !ok {
		return
	}
	tracks := make([]map[string]any, 0, len(names))
	for _, name := range names {
		rel := joinRel(folder, name)
		tracks = append(tracks, map[string]any{"name": name, "path": rel, "stream_url": "/stream/" + rel})
	}
	writeJSON(w, http.StatusOK, map[string]any{"folder": folder, "tracks": tracks, "count": len(tracks)})
}

// handleGallery mirrors get_gallery. The Go backend has no thumbnail
// renderer, so the thumbnail URL is the image itself.
func (a *App) handleGallery(w http.ResponseWriter, r *http.Request) {
	folder, names, ok := a.folderListing(w, r, "/gallery/", galleryImageExts)
	if !ok {
		return
	}
	images := make([]map[string]any, 0, len(names))
	for _, name := range names {
		rel := joinRel(folder, name)
		images = append(images, map[string]any{
			"name": name, "path": rel, "url": "/download/" + rel, "thumbnail": "/download/" + rel,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"folder": folder, "images": images, "count": len(images)})
}

// handlePreview mirrors document_preview for the formats the Go backend
// can read without external libraries: CSV, JSON and DOCX paragraphs.
// XLSX/PPTX previews remain Python-backend features.
func (a *App) handlePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	_, full, st, ok := a.resolveFile(w, r, "/preview/", "read", http.StatusNotFound)
	if !ok {
		return
	}
	if st.Size() > maxDocumentPreviewSize {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"success":   false,
			"error":     "미리보기 파일 크기가 너무 큽니다. 최대 " + itoa(maxDocumentPreviewSize/(1024*1024)) + "MB까지 지원합니다.",
			"max_bytes": maxDocumentPreviewSize, "file_size": st.Size(),
		})
		return
	}
	content, previewType, err := buildPreview(full)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "error": "문서 미리보기 오류"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true, "content": content, "type": previewType,
		"filename": filepath.Base(full), "safe_html": previewType == "html",
	})
}

func buildPreview(full string) (string, string, error) {
	switch strings.ToLower(filepath.Ext(full)) {
	case ".csv":
		f, err := os.Open(full)
		if err != nil {
			return "", "", err
		}
		defer f.Close()
		reader := csv.NewReader(f)
		reader.FieldsPerRecord = -1
		reader.LazyQuotes = true
		var rows strings.Builder
		for i := 0; i < 100; i++ {
			rec, err := reader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				continue
			}
			rows.WriteString("<tr>")
			for j, cell := range rec {
				if j >= 20 {
					break
				}
				rows.WriteString("<td>" + html.EscapeString(cell) + "</td>")
			}
			rows.WriteString("</tr>")
		}
		return "<table border='1' style='border-collapse:collapse; width:100%;'>" + rows.String() + "</table>", "html", nil
	case ".json":
		data, err := os.ReadFile(full)
		if err != nil {
			return "", "", err
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			return "", "", err
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return "", "", err
		}
		text := strings.TrimRight(buf.String(), "\n")
		if r := []rune(text); len(r) > 10000 {
			text = string(r[:10000])
		}
		return "<pre>" + html.EscapeString(text) + "</pre>", "html", nil
	case ".docx":
		paragraphs, err := docxParagraphs(full, 100)
		if err != nil {
			return "", "", err
		}
		if len(paragraphs) == 0 {
			return "<p>문서가 비어있습니다.</p>", "html", nil
		}
		var sb strings.Builder
		for i, p := range paragraphs {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString("<p>" + html.EscapeString(p) + "</p>")
		}
		return sb.String(), "html", nil
	case ".xlsx", ".xls", ".pptx":
		return "이 형식의 미리보기는 Python 백엔드에서만 지원됩니다. 파일을 다운로드해 확인하세요.", "text", nil
	default:
		return "지원하지 않는 파일 형식입니다.", "text", nil
	}
}

// docxParagraphs extracts up to limit non-empty paragraph texts from
// word/document.xml (w:p → concatenated w:t).
func docxParagraphs(full string, limit int) ([]string, error) {
	zr, err := zip.OpenReader(full)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var doc *zip.File
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			doc = f
			break
		}
	}
	if doc == nil {
		return nil, nil
	}
	rc, err := doc.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	dec := xml.NewDecoder(io.LimitReader(rc, maxDocumentPreviewSize))
	var out []string
	var cur strings.Builder
	inText := false
	for len(out) < limit {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" {
				inText = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "t":
				inText = false
			case "p":
				if text := strings.TrimSpace(cur.String()); text != "" {
					out = append(out, cur.String())
				}
				cur.Reset()
			}
		case xml.CharData:
			if inText {
				cur.Write(t)
			}
		}
	}
	return out, nil
}

// handleRecentFiles mirrors recent_files (readable entries only).
func (a *App) handleRecentFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	owner := a.recentOwnerKey(r)
	a.media.mu.Lock()
	entries := append([]recentFile(nil), a.media.recent[owner]...)
	a.media.mu.Unlock()
	role := SessionOf(r).role
	out := make([]recentFile, 0, len(entries))
	for _, e := range entries {
		if ok, _, _ := a.Perms.EnsurePathAccess(e.Path, "read", role); ok {
			out = append(out, e)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": out})
}

// handleClipboard mirrors clipboard_handler (per-owner, LRU-bounded).
func (a *App) handleClipboard(w http.ResponseWriter, r *http.Request) {
	s := SessionOf(r)
	owner := s.sid
	if owner == "" {
		role := s.role
		if role == "" {
			role = "guest"
		}
		owner = role + ":" + a.clientIP(r)
	}
	m := a.media
	switch r.Method {
	case http.MethodGet:
		m.mu.Lock()
		content := ""
		if el, ok := m.clipboard[owner]; ok {
			content = el.Value.(*clipEntry).content
		}
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"content": content})
	case http.MethodPost:
		data := parseJSONBody(r)
		content, isString := data["content"].(string)
		if !isString {
			if raw, ok := data["content"]; ok && raw != nil {
				b, _ := json.Marshal(raw)
				content = string(b)
			}
		}
		if len(content) > maxClipboardBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"success": false, "error": "클립보드 내용은 " + itoa(maxClipboardBytes) + "바이트 이하여야 합니다",
			})
			return
		}
		m.mu.Lock()
		if el, ok := m.clipboard[owner]; ok {
			el.Value.(*clipEntry).content = content
			m.clipOrder.MoveToBack(el)
		} else {
			m.clipboard[owner] = m.clipOrder.PushBack(&clipEntry{owner: owner, content: content})
		}
		for m.clipOrder.Len() > maxClipboardEntries {
			oldest := m.clipOrder.Front()
			delete(m.clipboard, oldest.Value.(*clipEntry).owner)
			m.clipOrder.Remove(oldest)
		}
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"success": true})
	default:
		methodNotAllowed(w, r)
	}
}

// metricsPayload mirrors get_metrics_payload plus the legacy short keys
// the metrics route adds (sent/recv/active).
func (a *App) metricsPayload() map[string]any {
	m := a.media
	sent := m.bytesSent.Load()
	recv := bytesReceived.Load()
	active := a.Sessions.Count()
	return map[string]any{
		"uptime":             formatUptime(a.now().Sub(m.startedAt)),
		"requests":           m.requests.Load(),
		"sent":               files.FmtBytes(sent),
		"recv":               files.FmtBytes(recv),
		"bytes_sent":         sent,
		"bytes_received":     recv,
		"bytes_sent_fmt":     files.FmtBytes(sent),
		"bytes_received_fmt": files.FmtBytes(recv),
		"errors":             0,
		"active":             active,
		"active_connections": active,
	}
}

// handleMetrics mirrors metrics for the server-status modal.
func (a *App) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, r)
		return
	}
	writeJSON(w, http.StatusOK, a.metricsPayload())
}

// handleDashboardSummary mirrors dashboard_summary (metrics + disk) used
// by the page footer and status widgets.
func (a *App) handleDashboardSummary(w http.ResponseWriter, r *http.Request) {
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
		"timestamp": isoNow(a.now()),
		"metrics":   a.metricsPayload(),
		"disk":      disk,
	})
}

// formatUptime mirrors _uptime_string ("{h}h {m}m {s}s").
func formatUptime(d time.Duration) string {
	total := int(d.Seconds())
	h, m, s := total/3600, (total%3600)/60, total%60
	return itoa(h) + "h " + itoa(m) + "m " + itoa(s) + "s"
}
