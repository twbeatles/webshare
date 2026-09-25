package quota

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// TrackerFile mirrors runtime_state.DOWNLOAD_TRACKER_FILE.
const TrackerFile = ".webshare_download_tracker.json"

type persistedEntry struct {
	Count int64  `json:"count"`
	Bytes int64  `json:"bytes"`
	Date  string `json:"date"`
}

// SetPersistence roots the tracker for Save/Load and loads existing state.
// Empty root disables persistence.
func (t *Tracker) SetPersistence(root string) {
	t.mu.Lock()
	t.root = root
	t.mu.Unlock()
	if root != "" {
		t.Load()
	}
}

// saveLocked persists the snapshot (caller holds t.mu).
func (t *Tracker) saveLocked() {
	if t.root == "" {
		t.dirty = false
		return
	}
	payload := map[string]persistedEntry{}
	for key, e := range t.entries {
		payload[key] = persistedEntry{Count: e.count, Bytes: e.bytes, Date: e.date}
	}
	if err := atomicWriteJSON(filepath.Join(t.root, TrackerFile), payload); err == nil {
		t.dirty = false
	}
}

// Flush persists when dirty (mirrors save_download_tracker dirty gate;
// called at shutdown and after share-quota mutations).
func (t *Tracker) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.dirty {
		return
	}
	t.saveLocked()
}

// Load mirrors load_download_tracker (corrupt → keep current state).
func (t *Tracker) Load() {
	if t.root == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(t.root, TrackerFile))
	if err != nil {
		return
	}
	var payload map[string]persistedEntry
	if err := json.Unmarshal(data, &payload); err != nil || payload == nil {
		return
	}
	loaded := map[string]*entry{}
	for key, pe := range payload {
		count, bytes := pe.Count, pe.Bytes
		if count < 0 {
			count = 0
		}
		if bytes < 0 {
			bytes = 0
		}
		loaded[key] = &entry{key: key, count: count, bytes: bytes, date: pe.Date}
	}
	t.mu.Lock()
	t.entries = loaded
	t.dirty = false
	t.mu.Unlock()
}

func atomicWriteJSON(path string, payload any) error {
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".webshare_write_*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
