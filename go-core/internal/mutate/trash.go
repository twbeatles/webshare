package mutate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"webshare-core/internal/permission"
)

// trashMetaMu serializes every load→modify→save of the trash metadata file
// so concurrent deletes/restores cannot drop each other's entries
// (audit ISSUE-004). One process serves one shared folder.
var trashMetaMu sync.Mutex

// updateTrashMetadata runs fn on the current metadata under trashMetaMu and
// saves the result when fn reports a change.
func updateTrashMetadata(root string, fn func(meta *TrashMetadata) bool) error {
	trashMetaMu.Lock()
	defer trashMetaMu.Unlock()
	meta := loadTrashMetadata(root)
	if meta.Entries == nil {
		meta.Entries = map[string]TrashEntry{}
	}
	if !fn(&meta) {
		return nil
	}
	return saveTrashMetadata(root, meta)
}

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
	Pending        bool   `json:"pending,omitempty"`
	Healed         bool   `json:"healed,omitempty"`
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
		s += "." + sprintf06(us)
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
	entry := TrashEntry{
		ID:              entryID,
		OriginalRelPath: filepath.ToSlash(rel),
		TrashName:       trashName,
		DeletedAt:       isoTime(now),
		Pending:         true,
	}
	// 1) pending entry first: a crash before the move leaves an orphan
	// entry that SelfHealTrashMetadata drops (move_to_trash parity).
	if err := updateTrashMetadata(root, func(meta *TrashMetadata) bool {
		meta.Entries[trashName] = entry
		return true
	}); err != nil {
		return "", err
	}
	dropEntry := func() {
		_ = updateTrashMetadata(root, func(meta *TrashMetadata) bool {
			_, ok := meta.Entries[trashName]
			delete(meta.Entries, trashName)
			return ok
		})
	}
	// 2) the move itself.
	if err := os.Rename(absPath, trashPath); err != nil {
		dropEntry()
		return "", err
	}
	// 3) confirm; on failure undo the move so nothing is half-committed.
	st, _ := os.Lstat(trashPath)
	entry.Pending = false
	entry.IsDir = st != nil && st.IsDir()
	if err := updateTrashMetadata(root, func(meta *TrashMetadata) bool {
		meta.Entries[trashName] = entry
		return true
	}); err != nil {
		_ = os.Rename(trashPath, absPath)
		dropEntry()
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

// LoadTrashMetadata exposes metadata for trash admin routes.
func LoadTrashMetadata(root string) TrashMetadata {
	trashMetaMu.Lock()
	defer trashMetaMu.Unlock()
	return loadTrashMetadata(root)
}

// ClearTrashMetadata removes the metadata file (empty_trash), serialized
// with every other metadata writer.
func ClearTrashMetadata(root string) {
	trashMetaMu.Lock()
	defer trashMetaMu.Unlock()
	os.Remove(trashMetadataPath(root))
}

var (
	modernTrashName = regexp.MustCompile(`^\d{8}_\d{6}_[0-9a-fA-F]{32}_(.+)$`)
	legacyTrashName = regexp.MustCompile(`^\d{8}_\d{6}_(.+)$`)
)

// ExtractOriginalName mirrors extract_original_name_from_trash:
// YYYYMMDD_HHMMSS_<uuid32>_name (current) or YYYYMMDD_HHMMSS_name (legacy).
func ExtractOriginalName(trashName string) string {
	if m := modernTrashName.FindStringSubmatch(trashName); m != nil {
		return m[1]
	}
	if m := legacyTrashName.FindStringSubmatch(trashName); m != nil {
		return m[1]
	}
	return trashName
}

// RestoreFromTrash mirrors restore_from_trash: (ok, restoredAbsOrMsg).
// The metadata entry is removed before the move (a crash afterwards leaves
// the file in the trash for self-heal) and put back if the move fails.
func RestoreFromTrash(root, trashName string) (bool, string) {
	trashDir := filepath.Join(root, TrashDirName)
	safeName := filepath.Base(trashName)
	trashPath := filepath.Join(trashDir, safeName)
	if _, err := os.Lstat(trashPath); err != nil {
		return false, "파일을 찾을 수 없습니다"
	}
	var removed *TrashEntry
	var final string
	failMsg := ""
	err := updateTrashMetadata(root, func(meta *TrashMetadata) bool {
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
			failMsg = "유효하지 않은 복원 파일명입니다"
			return false
		}
		if err := os.MkdirAll(filepath.Dir(validated), 0o755); err != nil {
			failMsg = "휴지통에서 복원하는 중 오류가 발생했습니다."
			return false
		}
		final = nextAvailablePath(validated)
		if entry, ok := meta.Entries[safeName]; ok {
			removed = &entry
			delete(meta.Entries, safeName)
			return true
		}
		return false
	})
	if failMsg != "" {
		return false, failMsg
	}
	if err != nil {
		return false, "휴지통에서 복원하는 중 오류가 발생했습니다."
	}
	if err := os.Rename(trashPath, final); err != nil {
		if removed != nil {
			entry := *removed
			_ = updateTrashMetadata(root, func(meta *TrashMetadata) bool {
				meta.Entries[safeName] = entry
				return true
			})
		}
		return false, "휴지통에서 복원하는 중 오류가 발생했습니다."
	}
	return true, final
}

// SelfHealTrashMetadata mirrors self_heal_trash_metadata: registers trash
// items that have no entry (crash/lost-update leftovers) and drops entries
// whose item is gone. Returns the number of re-registered items.
func SelfHealTrashMetadata(root string, now time.Time) int {
	trashDir := filepath.Join(root, TrashDirName)
	dirEntries, err := os.ReadDir(trashDir)
	if err != nil {
		return 0
	}
	present := map[string]bool{}
	names := make([]string, 0, len(dirEntries))
	for _, e := range dirEntries {
		present[e.Name()] = true
		names = append(names, e.Name())
	}
	sort.Strings(names)
	healed := 0
	_ = updateTrashMetadata(root, func(meta *TrashMetadata) bool {
		changed := false
		for _, name := range names {
			if _, ok := meta.Entries[name]; ok || strings.HasPrefix(name, ".") {
				continue
			}
			if !legacyTrashName.MatchString(name) {
				continue
			}
			st, _ := os.Lstat(filepath.Join(trashDir, name))
			meta.Entries[name] = TrashEntry{
				OriginalRelPath: ExtractOriginalName(name),
				TrashName:       name,
				DeletedAt:       isoTime(now),
				IsDir:           st != nil && st.IsDir(),
				Healed:          true,
			}
			healed++
			changed = true
		}
		for name := range meta.Entries {
			if !present[name] {
				delete(meta.Entries, name)
				changed = true
			}
		}
		return changed
	})
	return healed
}

// AutoCleanupTrash mirrors auto_cleanup_trash: self-heals the metadata,
// then drops name-timestamped items older than maxAgeDays. Returns the
// removed count.
func AutoCleanupTrash(root string, maxAgeDays int) int {
	trashDir := filepath.Join(root, TrashDirName)
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		return 0
	}
	now := time.Now()
	SelfHealTrashMetadata(root, now)
	removedNames := []string{}
	for _, e := range entries {
		name := e.Name()
		if len(name) < 15 {
			continue
		}
		// Trash names carry naive local time (datetime.now() parity).
		deletedAt, err := time.ParseInLocation("20060102_150405", name[:15], time.Local)
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
			removedNames = append(removedNames, name)
		}
	}
	if len(removedNames) > 0 {
		_ = updateTrashMetadata(root, func(meta *TrashMetadata) bool {
			changed := false
			for _, name := range removedNames {
				if _, ok := meta.Entries[name]; ok {
					delete(meta.Entries, name)
					changed = true
				}
			}
			return changed
		})
	}
	return len(removedNames)
}
