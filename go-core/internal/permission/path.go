// Package permission ports path security and folder-permission semantics:
//
//	utils/request_policy.py  (normalize_relative_path, is_protected_system_path,
//	                           ensure_path_access, build_path_capabilities, role_can_mutate)
//	utils/file_utils.py      (validate_path)
//	security/permissions.py  (check_permission, permission normalization/persistence)
//
// Layering matches Python exactly: validate_path does NOT know about
// protected paths; protection is enforced by ensure_path_access /
// build_path_capabilities on top.
package permission

import (
	"os"
	"path/filepath"
	"strings"
)

// NormalizeRelativePath mirrors normalize_relative_path: backslashes to
// slashes, strip leading/trailing slashes, drop empty and "." segments.
// NOTE: ".." is preserved (validation rejects escapes later).
func NormalizeRelativePath(path string) string {
	if path == "" {
		return ""
	}
	value := strings.ReplaceAll(path, "\\", "/")
	value = strings.Trim(value, "/")
	parts := strings.Split(value, "/")
	kept := parts[:0]
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "/")
}

// GetParentRelativePath mirrors get_parent_relative_path.
func GetParentRelativePath(path string) string {
	normalized := NormalizeRelativePath(path)
	if normalized == "" {
		return ""
	}
	if i := strings.LastIndex(normalized, "/"); i >= 0 {
		return normalized[:i]
	}
	return ""
}

// IsProtectedSystemPath mirrors is_protected_system_path: any segment
// starting with "." (which subsumes ".webshare", kept as an explicit check
// for parity) blocks access.
func IsProtectedSystemPath(path string) bool {
	normalized := NormalizeRelativePath(path)
	if normalized == "" {
		return false
	}
	for _, segment := range strings.Split(normalized, "/") {
		if strings.HasPrefix(segment, ".") || strings.HasPrefix(strings.ToLower(segment), ".webshare") {
			return true
		}
	}
	return false
}

// ValidatePath mirrors utils/file_utils.validate_path: the canonicalized
// final path must stay inside baseDir. Returns (valid, fullPath, errMsg)
// with the same Korean denial message as Python.
func ValidatePath(baseDir, rel string) (bool, string, string) {
	const denied = "접근 권한이 없습니다"
	baseReal, err := canonicalBase(baseDir)
	if err != nil {
		return false, "", denied
	}
	if rel == "" {
		return true, baseReal, ""
	}
	target, err := resolveStrictFalse(baseReal, rel)
	if err != nil {
		return false, "", denied
	}
	if commonPrefix(baseReal, target) != baseReal {
		return false, "", denied
	}
	return true, target, ""
}

// canonicalBase is realpath(normpath(base)).
func canonicalBase(base string) (string, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return real, nil
}

// resolveStrictFalse mirrors Path(base, rel).resolve(strict=False): resolve
// symlinks on the deepest existing ancestor, append the remainder lexically.
// An absolute rel discards the base (pathlib division semantics); the common
// check then rejects it unless it genuinely sits inside baseDir. Volume
// (drive) handling mirrors os.path.commonpath raising ValueError on drive
// mismatch — callers treat that as invalid via commonPrefix.
func resolveStrictFalse(baseReal, rel string) (string, error) {
	relOS := filepath.FromSlash(rel)
	joined := filepath.Join(baseReal, relOS)
	if filepath.IsAbs(relOS) {
		joined = filepath.Clean(relOS)
	}
	if _, err := os.Lstat(joined); err == nil {
		return filepath.EvalSymlinks(joined)
	}
	// Walk up to the deepest existing ancestor.
	current := joined
	var tail []string
	for {
		parent := filepath.Dir(current)
		if parent == current {
			return "", os.ErrNotExist
		}
		tail = append([]string{filepath.Base(current)}, tail...)
		if _, err := os.Lstat(parent); err == nil {
			realParent, err := filepath.EvalSymlinks(parent)
			if err != nil {
				return "", err
			}
			return filepath.Join(append([]string{realParent}, tail...)...), nil
		}
		current = parent
	}
}

// commonPrefix mirrors os.path.commonpath([base, target]) with case-SENSITIVE
// component comparison (ntpath.commonpath does not fold case, so a
// case-differing target is rejected in Python too). Drive letters compare
// case-insensitively (splitdrive semantics); mismatched drives yield "".
func commonPrefix(base, target string) string {
	baseVol := filepath.VolumeName(base)
	targetVol := filepath.VolumeName(target)
	if !strings.EqualFold(baseVol, targetVol) {
		return ""
	}
	stripVol := func(p, vol string) string { return strings.TrimPrefix(p, vol) }
	sep := string(filepath.Separator)
	split := func(p string) []string {
		p = stripVol(p, filepath.VolumeName(p))
		p = strings.Trim(p, sep)
		if p == "" {
			return nil
		}
		return strings.Split(p, sep)
	}
	bc, tc := split(base), split(target)
	var common []string
	for i := 0; i < len(bc) && i < len(tc); i++ {
		if bc[i] != tc[i] {
			break
		}
		common = append(common, bc[i])
	}
	if len(common) == 0 {
		// Base itself may be the volume root (e.g. "C:\").
		if len(bc) == 0 {
			return baseVol + sep
		}
		return ""
	}
	return baseVol + sep + strings.Join(common, sep)
}
