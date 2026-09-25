package files

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ZipItem is one collected file: absolute path + archive name.
type ZipItem struct {
	AbsPath string
	ArcName string
}

// CollectZipFiles mirrors _collect_allowed_zip_files: sorted walk, protected
// skip, per-file read check + validate + isfile, arcnames with prefix.
func CollectZipFiles(rootAbs, rootRel, arcPrefix string, canRead func(relPath string) bool, valid func(relPath string) (string, bool)) []ZipItem {
	rootRel = strings.Trim(strings.ReplaceAll(rootRel, "\\", "/"), "/")
	arcPrefix = strings.Trim(strings.ReplaceAll(arcPrefix, "\\", "/"), "/")
	var items []ZipItem
	var walk func(dirAbs, dirRel string)
	walk = func(dirAbs, dirRel string) {
		entries, err := os.ReadDir(dirAbs)
		if err != nil {
			return
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			rel := joinRel(rootRel, dirRel, e.Name())
			if IsProtectedRel(rel) {
				continue
			}
			if e.IsDir() {
				if canRead != nil && !canRead(rel) {
					continue
				}
				walk(filepath.Join(dirAbs, e.Name()), joinRel(dirRel, e.Name()))
				continue
			}
			if canRead != nil && !canRead(rel) {
				continue
			}
			abs, ok := valid(rel)
			if !ok {
				continue
			}
			st, err := os.Stat(abs)
			if err != nil || !st.Mode().IsRegular() {
				continue
			}
			arcRel, err := filepath.Rel(rootAbs, abs)
			if err != nil {
				continue
			}
			arcRel = filepath.ToSlash(arcRel)
			arc := arcRel
			if arcPrefix != "" {
				arc = arcPrefix + "/" + arcRel
			}
			items = append(items, ZipItem{AbsPath: abs, ArcName: arc})
		}
	}
	walk(rootAbs, "")
	return items
}

func joinRel(parts ...string) string {
	var kept []string
	for _, p := range parts {
		if p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "/")
}

// IsProtectedRel reports protected status for a slash-separated rel path.
// (Set by the handlers package to permission.IsProtectedSystemPath to avoid
// an import cycle: permission does not import files, handlers wires both.)
var IsProtectedRel = func(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

// EstimateZipBytes mirrors _estimate_zip_transfer_bytes.
func EstimateZipBytes(items []ZipItem) int64 {
	var total int64
	for _, it := range items {
		if st, err := os.Stat(it.AbsPath); err == nil {
			total += st.Size()
		}
	}
	return total
}

// CreateTempZip mirrors create_temp_zip_from_items into a temp .zip file.
// Files use per-extension compression like _compress_type_for.
func CreateTempZip(items []ZipItem) (string, error) {
	tmp, err := os.CreateTemp("", ".webshare_zip_*.zip")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	zw := zip.NewWriter(tmp)
	var werr error
	for _, it := range items {
		if werr != nil {
			break
		}
		werr = addFileToZip(zw, it)
	}
	cerr := zw.Close()
	terr := tmp.Close()
	if werr != nil {
		os.Remove(tmpName)
		return "", werr
	}
	if cerr != nil {
		os.Remove(tmpName)
		return "", cerr
	}
	if terr != nil {
		os.Remove(tmpName)
		return "", terr
	}
	return tmpName, nil
}

func addFileToZip(zw *zip.Writer, it ZipItem) error {
	f, err := os.Open(it.AbsPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	method := zip.Deflate
	if !ShouldCompress(it.AbsPath) {
		method = zip.Store
	}
	hdr := &zip.FileHeader{
		Name:   it.ArcName,
		Method: method,
	}
	hdr.SetModTime(st.ModTime())
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, f)
	return err
}

// ZipPreviewItem mirrors one zip_preview entry.
type ZipPreviewItem struct {
	Name           string  `json:"name"`
	Size           uint64  `json:"size"`
	CompressedSize uint64  `json:"compressed_size"`
	IsDir          bool    `json:"is_dir"`
	Date           *string `json:"date"`
}

// ZipPreview mirrors the /api/zip_preview logic. Only these extensions are
// accepted (case-insensitive).
func ZipPreview(abs string) (filename string, items []ZipPreviewItem, totalFiles, totalFolders int, err error) {
	ext := strings.ToLower(filepath.Ext(abs))
	switch ext {
	case ".zip", ".jar", ".war", ".apk":
	default:
		return "", nil, 0, 0, errNotZip
	}
	zr, err := zip.OpenReader(abs)
	if err != nil {
		return "", nil, 0, 0, errBadZip
	}
	defer zr.Close()
	for _, f := range zr.File {
		isDir := f.FileInfo().IsDir()
		var date *string
		if !f.Modified.IsZero() {
			s := f.Modified.Format("2006-01-02T15:04:05")
			date = &s
		}
		items = append(items, ZipPreviewItem{
			Name: f.Name, Size: f.UncompressedSize64,
			CompressedSize: f.CompressedSize64, IsDir: isDir, Date: date,
		})
		if isDir {
			totalFolders++
		} else {
			totalFiles++
		}
		if len(items) >= 500 {
			break
		}
	}
	return filepath.Base(abs), items, totalFiles, totalFolders, nil
}

// Preview errors (compared by kind in handlers).
var (
	errNotZip = errKind("not_zip")
	errBadZip = errKind("bad_zip")
)

type errKind string

func (e errKind) Error() string { return string(e) }

// IsNotZip reports the extension rejection.
func IsNotZip(err error) bool { return err == errNotZip }

// IsBadZip reports unreadable archives.
func IsBadZip(err error) bool { return err == errBadZip }
