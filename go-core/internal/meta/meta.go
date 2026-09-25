// Package meta ports features/metadata.py: file tags, favorite folders,
// file memos and bookmarks persisted in .webshare_meta.json.
package meta

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MetaFile mirrors the metadata persistence filename.
const MetaFile = ".webshare_meta.json"

// Tag mirrors one FILE_TAGS entry.
type Tag struct {
	Tag   string `json:"tag"`
	Color string `json:"color"`
}

// Favorite mirrors one FAVORITE_FOLDERS entry.
type Favorite struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Added string `json:"added"`
}

// Memo mirrors one FILE_MEMOS entry.
type Memo struct {
	Memo    string `json:"memo"`
	Updated string `json:"updated"`
}

// Bookmark mirrors one BOOKMARKS entry.
type Bookmark struct {
	Path  string `json:"path"`
	Name  string `json:"name"`
	Added string `json:"added"`
}

// Store holds metadata with atomic persistence.
type Store struct {
	mu        sync.Mutex
	root      string
	Tags      map[string][]Tag
	Favorites []Favorite
	Memos     map[string]Memo
	Bookmarks []Bookmark
	now       func() time.Time
}

// NewStore builds a store rooted at the shared folder and loads state.
func NewStore(root string) *Store {
	s := &Store{
		root:      root,
		Tags:      map[string][]Tag{},
		Favorites: []Favorite{},
		Memos:     map[string]Memo{},
		Bookmarks: []Bookmark{},
		now:       time.Now,
	}
	s.Load()
	return s
}

// NowISO formats now like datetime.now().isoformat() (naive).
func (s *Store) NowISO() string {
	t := s.now()
	out := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		out += "." + zeroPad6(us)
	}
	return out
}

func zeroPad6(n int) string {
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

// Save mirrors save_metadata (synchronous; failures are swallowed like the
// Python logger-only path).
func (s *Store) Save() {
	s.mu.Lock()
	payload := map[string]any{
		"tags":      s.Tags,
		"favorites": s.Favorites,
		"memos":     s.Memos,
		"bookmarks": s.Bookmarks,
		"updated":   s.NowISO(),
	}
	if payload["favorites"] == nil {
		payload["favorites"] = []Favorite{}
	}
	if payload["bookmarks"] == nil {
		payload["bookmarks"] = []Bookmark{}
	}
	s.mu.Unlock()
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return
	}
	dest := filepath.Join(s.root, MetaFile)
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".webshare_meta_*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmpName, dest)
}

// Load mirrors load_metadata (missing/corrupt → keep current state).
func (s *Store) Load() {
	data, err := os.ReadFile(filepath.Join(s.root, MetaFile))
	if err != nil {
		return
	}
	var raw struct {
		Tags      map[string][]Tag `json:"tags"`
		Favorites []Favorite       `json:"favorites"`
		Memos     map[string]Memo  `json:"memos"`
		Bookmarks []Bookmark       `json:"bookmarks"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return
	}
	// Parity: missing keys reset the collection (clear + update with {}).
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Tags = raw.Tags
	if s.Tags == nil {
		s.Tags = map[string][]Tag{}
	}
	s.Favorites = raw.Favorites
	if s.Favorites == nil {
		s.Favorites = []Favorite{}
	}
	s.Memos = raw.Memos
	if s.Memos == nil {
		s.Memos = map[string]Memo{}
	}
	s.Bookmarks = raw.Bookmarks
	if s.Bookmarks == nil {
		s.Bookmarks = []Bookmark{}
	}
}
