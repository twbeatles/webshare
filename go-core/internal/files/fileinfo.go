package files

import (
	"crypto/md5"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FileInfo mirrors get_file_info payload.
type FileInfo struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	IsDir       bool   `json:"is_dir"`
	Size        int64  `json:"size"`
	SizeFmt     string `json:"size_fmt"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	Accessed    string `json:"accessed"`
	MD5         string `json:"md5,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
	FileCount   *int   `json:"file_count,omitempty"`
	FolderCount *int   `json:"folder_count,omitempty"`
}

// MaxMD5Size mirrors the 10MB hash cutoff.
const MaxMD5Size = 10 * 1024 * 1024

// StatFile builds the file_info payload for an already-validated abs path.
// Timestamps use local time ISO format without offset (parity with
// datetime.fromtimestamp(...).isoformat()).
func StatFile(rel, abs string) (*FileInfo, error) {
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	isDir := st.IsDir()
	info := &FileInfo{
		Name:     filepath.Base(abs),
		Path:     rel,
		IsDir:    isDir,
		Size:     st.Size(),
		SizeFmt:  FmtBytes(st.Size()),
		Created:  isoLocal(creationTime(abs, st)),
		Modified: isoLocal(st.ModTime()),
		Accessed: isoLocal(accessTime(abs, st)),
	}
	if !isDir {
		if st.Size() < MaxMD5Size {
			if sum, err := md5File(abs); err == nil {
				info.MD5 = sum
			}
		}
		info.MimeType = mimeTypeOf(abs)
	} else {
		entries, err := os.ReadDir(abs)
		if err == nil {
			files, folders := 0, 0
			for _, e := range entries {
				if e.IsDir() {
					folders++
				} else {
					files++
				}
			}
			info.FileCount = &files
			info.FolderCount = &folders
		}
	}
	return info, nil
}

func isoLocal(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	t = t.In(time.Local)
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s
}

func md5File(abs string) (string, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// mimeTypeOf guesses the content type with Go's extension table,
// defaulting to application/octet-stream like Python's fallback.
func mimeTypeOf(abs string) string {
	ext := strings.ToLower(filepath.Ext(abs))
	if ext != "" {
		if typ := mime.TypeByExtension(ext); typ != "" {
			// Werkzeug send_file attachments carry no charset parameter.
			if i := strings.Index(typ, ";"); i >= 0 {
				typ = strings.TrimSpace(typ[:i])
			}
			return typ
		}
	}
	// Small parity shims where Go's table is known to differ from the
	// Python mimetypes result observed in contract runs.
	switch ext {
	case ".md":
		return "text/markdown"
	case ".opus":
		return "audio/ogg"
	}
	return "application/octet-stream"
}
