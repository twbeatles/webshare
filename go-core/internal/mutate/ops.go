package mutate

import (
	"archive/zip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Conflict policies mirror COPY_MOVE_CONFLICT_POLICIES.
const (
	ConflictRename    = "rename"
	ConflictFail      = "fail"
	ConflictOverwrite = "overwrite"
)

// NormalizeConflictPolicy mirrors _normalize_conflict_policy: falsy values
// fall back to def, unknown values fall back to def.
func NormalizeConflictPolicy(value, def string) string {
	if def == "" {
		def = ConflictRename
	}
	policy := strings.ToLower(strings.TrimSpace(value))
	if policy == "" {
		policy = def
	}
	switch policy {
	case ConflictRename, ConflictFail, ConflictOverwrite:
		return policy
	default:
		return def
	}
}

// ResolveConflictPath mirrors _resolve_conflict_path: (resolved, final, errMsg).
func ResolveConflictPath(path, policy string) (bool, string, string) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return true, path, ""
	}
	switch policy {
	case ConflictFail:
		return false, path, "대상이 이미 존재합니다."
	case ConflictRename:
		return true, nextAvailablePath(path), ""
	case ConflictOverwrite:
		return true, path, ""
	default:
		return false, path, "지원하지 않는 충돌 정책입니다."
	}
}

// NextAvailableDirectoryPath mirrors _next_available_directory_path:
// base, base_1, base_2, ...
func NextAvailableDirectoryPath(base string) string {
	candidate := base
	for counter := 1; ; counter++ {
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate
		}
		candidate = base + "_" + itoa(counter)
	}
}

// NormcasePath mirrors _normcase_path.
func NormcasePath(path string) string {
	cleaned := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		cleaned = strings.ToLower(cleaned)
	}
	return cleaned
}

// IsDescendantPath mirrors _is_descendant_path.
func IsDescendantPath(parent, child string) bool {
	parentKey := NormcasePath(parent)
	childKey := NormcasePath(child)
	if parentKey == childKey {
		return false
	}
	rel, err := filepath.Rel(parentKey, childKey)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// CopyDirToStaging mirrors _copy_directory_to_staging: temp dir in the
// destination parent, removed first so copyTree creates it.
func CopyDirToStaging(src, dst string) (string, error) {
	parent := filepath.Dir(dst)
	if parent == "" {
		parent = "."
	}
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".webshare_copydir_")
	if err != nil {
		return "", err
	}
	os.RemoveAll(staging)
	if err := copyTree(src, staging); err != nil {
		os.RemoveAll(staging)
		return "", err
	}
	return staging, nil
}

// ReplaceWithStaging mirrors _replace_with_staging: existing dst moves to a
// backup name first; on failure the backup is restored only when dst is gone.
func ReplaceWithStaging(staging, dst string) error {
	parent := filepath.Dir(dst)
	if parent == "" {
		parent = "."
	}
	backup := ""
	if _, err := os.Lstat(dst); err == nil {
		tmp, err := os.MkdirTemp(parent, ".webshare_backup_")
		if err != nil {
			return err
		}
		os.RemoveAll(tmp)
		backup = tmp
		if err := os.Rename(dst, backup); err != nil {
			os.RemoveAll(tmp)
			return err
		}
	}
	if err := os.Rename(staging, dst); err != nil {
		if backup != "" {
			if _, statErr := os.Lstat(dst); os.IsNotExist(statErr) {
				if rbErr := os.Rename(backup, dst); rbErr != nil {
					return errors.Join(err, rbErr)
				}
			}
		}
		return err
	}
	if backup != "" {
		os.RemoveAll(backup)
	}
	return nil
}

// copyTree mirrors shutil.copytree(symlinks=False): dst is created.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFileMode(path, target)
	})
}

// CopyPath mirrors the non-overwrite copy branches: files via atomic copy,
// directories via staging swap (equivalent to copytree onto a fresh path).
func CopyPath(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		staging, err := CopyDirToStaging(src, dst)
		if err != nil {
			return err
		}
		return ReplaceWithStaging(staging, dst)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return AtomicCopyFile(src, dst)
}

// MovePath mirrors shutil.move for validated same-volume paths with a
// copy+remove fallback.
func MovePath(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		if err := copyTree(src, dst); err != nil {
			return err
		}
		return os.RemoveAll(src)
	}
	if err := copyFileMode(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

// CopyDirOverwrite mirrors the overwrite branch of copy_item for directories:
// version existing files, copy to staging, swap, and return final rel path.
func CopyDirOverwrite(root, src, dst string, versioning bool, now time.Time, protected func(relSlash string) bool) error {
	if err := CreateOverwriteVersions(root, dst, versioning, now, protected); err != nil {
		return err
	}
	staging, err := CopyDirToStaging(src, dst)
	if err != nil {
		return err
	}
	return ReplaceWithStaging(staging, dst)
}

// MoveDirOverwrite mirrors the overwrite branch of move_item for directories.
func MoveDirOverwrite(root, src, dst string, versioning bool, now time.Time, protected func(relSlash string) bool) error {
	if err := CopyDirOverwrite(root, src, dst, versioning, now, protected); err != nil {
		return err
	}
	return os.RemoveAll(src)
}

// CreateOverwriteVersions mirrors _create_overwrite_versions_if_needed.
func CreateOverwriteVersions(root, dst string, versioning bool, now time.Time, protected func(relSlash string) bool) error {
	st, err := os.Lstat(dst)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		if st.Mode()&os.ModeSymlink == 0 {
			CreateFileVersion(root, dst, versioning, now)
		}
		return nil
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	return filepath.WalkDir(dst, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != dst && protected != nil {
				if rel, relErr := filepath.Rel(root, path); relErr == nil {
					if protected(filepath.ToSlash(rel)) {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if protected != nil {
			if rel, relErr := filepath.Rel(root, path); relErr == nil {
				if protected(filepath.ToSlash(rel)) {
					return nil
				}
			}
		}
		CreateFileVersion(root, path, versioning, now)
		return nil
	})
}

// Unzip limits mirror unzip_file.
const (
	MaxUnzipBytes = 50 * 1024 * 1024 * 1024 // 50GB
	MaxZipRatio   = 100
	MinRatioBytes = 10 * 1024 * 1024 // ratio checked only above 10MB
)

// UnzipError carries the user-facing message and HTTP status.
type UnzipError struct {
	Msg    string
	Status int
}

func (e *UnzipError) Error() string { return e.Msg }

// UnzipArchive mirrors unzip_file: pre-scans every member for Zip Slip and
// Zip Bomb, then extractall into a fresh next-available directory.
func UnzipArchive(zipPath, extractTo string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		// Parity: BadZipFile answers success:false with HTTP 200.
		return &UnzipError{Msg: "잘못된 ZIP 파일입니다.", Status: 200}
	}
	defer zr.Close()
	extractAbs, err := filepath.Abs(extractTo)
	if err != nil {
		return &UnzipError{Msg: "압축해제 오류", Status: 500}
	}
	var total int64
	for _, f := range zr.File {
		memberPath := filepath.Clean(filepath.Join(extractTo, filepath.FromSlash(f.Name)))
		memberAbs, err := filepath.Abs(memberPath)
		if err != nil || (memberAbs != extractAbs && !strings.HasPrefix(memberAbs, extractAbs+string(filepath.Separator))) {
			return &UnzipError{Msg: "보안 위협 감지: 잘못된 경로 \"" + f.Name + "\"", Status: 400}
		}
		if f.UncompressedSize64 > 0 {
			total += int64(f.UncompressedSize64)
			if total > MaxUnzipBytes {
				return &UnzipError{Msg: "Zip Bomb 감지: 압축 해제 용량 초과", Status: 400}
			}
			if f.CompressedSize64 > 0 {
				ratio := float64(f.UncompressedSize64) / float64(f.CompressedSize64)
				if ratio > MaxZipRatio && f.UncompressedSize64 > MinRatioBytes {
					return &UnzipError{Msg: "Zip Bomb 감지: 압축률이 너무 높습니다", Status: 400}
				}
			}
		}
	}
	for _, f := range zr.File {
		target := filepath.Join(extractTo, filepath.FromSlash(f.Name))
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return &UnzipError{Msg: "압축해제 오류", Status: 500}
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return &UnzipError{Msg: "압축해제 오류", Status: 500}
		}
		if err := extractZipFile(f, target); err != nil {
			return &UnzipError{Msg: "압축해제 오류", Status: 500}
		}
	}
	return nil
}

func extractZipFile(f *zip.File, dst string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, rc)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
