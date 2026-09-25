package mutate

import (
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Versioning mirrors utils/helpers/file_versions.py.
const (
	VersionDirName = ".webshare_versions"
	MaxVersions    = 5
)

// CreateFileVersion mirrors create_file_version (no-op when disabled or missing).
func CreateFileVersion(root, absPath string, versioning bool, now time.Time) {
	if !versioning {
		return
	}
	if _, err := os.Stat(absPath); err != nil {
		return
	}
	versionDir := filepath.Join(root, VersionDirName)
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		return
	}
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return
	}
	relSlash := filepath.ToSlash(rel)
	// Parity: "%Y%m%d_%H%M%S_%f" with real microseconds.
	stamp := now.Format("20060102_150405") + "_" + sprintf06(now.Nanosecond()/1000)
	name := BuildVersionFilename(relSlash, stamp)
	dst := filepath.Join(versionDir, name)
	if err := copyFileMode(absPath, dst); err != nil {
		return
	}
	CleanupOldVersions(versionDir, relSlash)
}

// BuildVersionFilename mirrors build_version_filename:
// {timestamp}__{urlsafe-b64-nopad(rel)}__{basename}. Default timestamp
// (Python) is "%Y%m%d_%H%M%S" without microseconds.
func BuildVersionFilename(relSlash, timestamp string) string {
	if timestamp == "" {
		timestamp = time.Now().Format("20060102_150405")
	}
	enc := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(relSlash))
	base := relSlash
	if i := strings.LastIndex(relSlash, "/"); i >= 0 {
		base = relSlash[i+1:]
	}
	return timestamp + "__" + enc + "__" + base
}

func decodeVersionRel(value string) string {
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return strings.ReplaceAll(string(raw), "\\", "/")
	}
	padded := value + strings.Repeat("=", (4-len(value)%4)%4)
	raw, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(raw), "\\", "/")
}

func legacyVersionKey(relSlash string) string {
	return strings.ReplaceAll(strings.ReplaceAll(relSlash, "/", "_"), string(filepath.Separator), "_")
}

// VersionNameMatchesRelPath mirrors version_name_matches_rel_path.
func VersionNameMatchesRelPath(versionName, relSlash string) bool {
	if strings.Contains(versionName, "__") {
		parts := strings.SplitN(versionName, "__", 3)
		if len(parts) == 3 {
			decoded := decodeVersionRel(parts[1])
			base := relSlash
			if i := strings.LastIndex(relSlash, "/"); i >= 0 {
				base = relSlash[i+1:]
			}
			return decoded == relSlash && parts[2] == base
		}
	}
	if len(versionName) > 16 {
		suffix := versionName[16:]
		return suffix == legacyVersionKey(relSlash)
	}
	return false
}

// CleanupOldVersions mirrors cleanup_old_versions.
func CleanupOldVersions(versionDir, relSlash string) {
	entries, err := os.ReadDir(versionDir)
	if err != nil {
		return
	}
	legacyName := legacyVersionKey(relSlash)
	legacyRe := regexp.MustCompile(`^\d{8}_\d{6}_` + regexp.QuoteMeta(legacyName) + `$`)
	var matches []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if VersionNameMatchesRelPath(name, relSlash) || legacyRe.MatchString(name) {
			matches = append(matches, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	// Parity with Python slice semantics: beyond-length slices are empty.
	if len(matches) > maxVersions() {
		for _, old := range matches[maxVersions():] {
			os.Remove(filepath.Join(versionDir, old))
		}
	}
}

func maxVersions() int { return MaxVersions }

// copyFileMode copies content + mode bits (parity with shutil.copy2 for tests;
// timestamps beyond mode are not compared in contract).
func copyFileMode(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// AtomicWriteFile mirrors atomic_write_bytes (same-dir temp + rename).
func AtomicWriteFile(path string, payload []byte) error {
	return atomicWriteFile(path, payload)
}

func atomicWriteFile(path string, payload []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".webshare_write_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// AtomicCopyFile mirrors atomic_copy_file (temp in dest dir + rename).
func AtomicCopyFile(src, dst string) error {
	dir := filepath.Dir(dst)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".webshare_copy_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	tmp.Close()
	os.Remove(tmpName)
	if err := copyFileMode(src, tmpName); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
