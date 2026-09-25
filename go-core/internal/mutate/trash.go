package mutate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"webshare-core/internal/permission"
)

// Trash layout mirrors features/trash.py.
const (
	TrashDirName     = ".webshare_trash"
	TrashMetadataFile = ".webshare_trash.json"
)

// TrashEntry mirrors one trash metadata entry.
type TrashEntry struct {
	ID             string `json:"id"`
	OriginalRelPath string `json:"original_rel_path"`
	TrashName      string `json:"trash_name"`
	DeletedAt      string `json:"deleted_at"`
	IsDir          bool   `json:"is_dir"`
}

func uuidHex() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return hex.EncodeToString(b[:])
}

func trashTime(t time.Time) string {
	return t.Format("20060102_150405")
}

func isoTime(t time.Time) string {
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += sprintf06(us)
	}
	return s
}

func sprintf06(n int) string {
	s := itoa(n)
	for len(s) < 6 {
		s = "0" + s
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// NextAvailablePath mirrors _next_available_path: name, name_1.ext, ...
func NextAvailablePath(path string) string { return nextAvailablePath(path) }

// nextAvailablePath mirrors _next_available_trash_path/_next_available_path:
// name, name_1.ext, name_2.ext...
func nextAvailablePath(path string) string {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return path
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for counter := 1; ; counter++ {
		candidate := filepath.Join(dir, stem+"_"+itoa(counter)+ext)
		if _, err := os.Lstat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

// MoveToTrash mirrors features/trash.move_to_trash. absPath must already be
// validated inside root. Returns the trash name.
// Naming: {timestamp}_{uuid}_{filename} with _next_available dedup.
func MoveToTrash(root, absPath string, now time.Time) (string, error) {
	trashDir := filepath.Join(root, TrashDirName)
	if err := os.MkdirAll(trashDir, 0o755); err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, absPath)
	if err != nil {
		return "", err
	}
	filename := filepath.Base(absPath)
	entryID := uuidHex()
	trashName := trashTime(now) + "_" + entryID + "_" + filename
	trashName = filepath.Base(nextAvailablePath(filepath.Join(trashDir, trashName)))
	trashPath := filepath.Join(trashDir, trashName)
	if err := os.Rename(absPath, trashPath); err != nil {
		return "", err
	}
	st, _ := os.Lstat(trashPath)
	entry := TrashEntry{
		ID:              entryID,
		OriginalRelPath: filepath.ToSlash(rel),
		TrashName:       trashName,
		DeletedAt:       isoTime(now),
		IsDir:           st != nil && st.IsDir(),
	}
	meta := loadTrashMetadata(root)
	if meta.Entries == nil {
		meta.Entries = map[string]TrashEntry{}
	}
	meta.Entries[trashName] = entry
	if err := saveTrashMetadata(root, meta); err != nil {
		return "", err
	}
	return trashName, nil
}

// TrashMetadata mirrors the metadata file shape.
type TrashMetadata struct {
	Entries map[string]TrashEntry `json:"entries"`
}

func trashMetadataPath(root string) string {
	return filepath.Join(root, TrashMetadataFile)
}

// loadTrashMetadata tolerates missing/corrupt/legacy-list shapes like Python.
func loadTrashMetadata(root string) TrashMetadata {
	var meta TrashMetadata
	data, err := os.ReadFile(trashMetadataPath(root))
	if err != nil {
		return TrashMetadata{Entries: map[string]TrashEntry{}}
	}
	var raw struct {
		Entries json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(data, &raw); err != nil || len(raw.Entries) == 0 {
		return TrashMetadata{Entries: map[string]TrashEntry{}}
	}
	if err := json.Unmarshal(raw.Entries, &meta.Entries); err != nil || meta.Entries == nil {
		// Legacy list shape.
		var list []TrashEntry
		if err2 := json.Unmarshal(raw.Entries, &list); err2 == nil {
			meta.Entries = map[string]TrashEntry{}
			for _, e := range list {
				key := e.TrashName
				if key == "" {
					key = e.ID
				}
				if key != "" {
					meta.Entries[key] = e
				}
			}
			return meta
		}
		return TrashMetadata{Entries: map[string]TrashEntry{}}
	}
	return meta
}

func saveTrashMetadata(root string, meta TrashMetadata) error {
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(trashMetadataPath(root), append(out, '\n'))
}

// LoadTrashMetadata exposes metadata for trash admin routes (later phases).
func LoadTrashMetadata(root string) TrashMetadata {
	return loadTrashMetadata(root)
}

// ExtractOriginalName mirrors extract_original_name_from_trash.
func ExtractOriginalName(trashName string) string {
	parts := strings.SplitN(trashName, "_", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return trashName
}

// RestoreFromTrash mirrors restore_from_trash: (ok, restoredAbsOrMsg).
func RestoreFromTrash(root, trashName string) (bool, string) {
	trashDir := filepath.Join(root, TrashDirName)
	safeName := filepath.Base(trashName)
	trashPath := filepath.Join(trashDir, safeName)
	if _, err := os.Lstat(trashPath); err != nil {
		return false, "파일을 찾을 수 없습니다"
	}
	meta := loadTrashMetadata(root)
	originalRel := ""
	if entry, ok := meta.Entries[safeName]; ok {
		originalRel = strings.Trim(entry.OriginalRelPath, "/")
	}
	targetRel := originalRel
	if targetRel == "" {
		targetRel = ExtractOriginalName(safeName)
	}
	valid, validated, _ := permission.ValidatePath(root, targetRel)
	if !valid {
		return false, "유효하지 않은 복원 파일명입니다"
	}
	if err := os.MkdirAll(filepath.Dir(validated), 0o755); err != nil {
		return false, "휴지통에서 복원하는 중 오류가 발생했습니다."
	}
	final := nextAvailablePath(validated)
	if err := os.Rename(trashPath, final); err != nil {
		return false, "휴지통에서 복원하는 중 오류가 발생했습니다."
	}
	if _, ok := meta.Entries[safeName]; ok {
		delete(meta.Entries, safeName)
		_ = saveTrashMetadata(root, meta)
	}
	return true, final
}

// AutoCleanupTrash mirrors auto_cleanup_trash: drops name-timestamped items
// older than maxAgeDays, returns the removed count.
func AutoCleanupTrash(root string, maxAgeDays int) int {
	trashDir := filepath.Join(root, TrashDirName)
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		return 0
	}
	now := time.Now()
	removed := 0
	meta := loadTrashMetadata(root)
	changed := false
	for _, e := range entries {
		name := e.Name()
		if len(name) < 15 {
			continue
		}
		deletedAt, err := time.Parse("20060102_150405", name[:15])
		if err != nil {
			continue
		}
		if int(now.Sub(deletedAt).Hours()/24) < maxAgeDays {
			continue
		}
		itemPath := filepath.Join(trashDir, name)
		var rmErr error
		if st, err := os.Lstat(itemPath); err == nil && st.IsDir() {
			rmErr = os.RemoveAll(itemPath)
		} else {
			rmErr = os.Remove(itemPath)
		}
		if rmErr == nil {
			removed++
			if _, ok := meta.Entries[name]; ok {
				delete(meta.Entries, name)
				changed = true
			}
		}
	}
	if changed {
		_ = saveTrashMetadata(root, meta)
	}
	return removed
}
