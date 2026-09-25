package files

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Listing mirrors utils/listing.py list_directory_page (no TTL cache — the
// cache is a pure performance layer with no observable contract).

// PageSize bounds mirror _normalize_page/_normalize_page_size.
const (
	DefaultPageSize = 200
	MaxPageSize     = 1000
	MinPageSize     = 20
)

// Item is one directory entry in API shape.
type Item struct {
	Name         string          `json:"name"`
	Path         string          `json:"path"`
	IsDir        bool            `json:"is_dir"`
	Type         string          `json:"type"`
	Size         int64           `json:"size"`
	Mtime        float64         `json:"mtime"`
	Ext          string          `json:"ext"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

// Page is the list_directory_page payload shape.
type Page struct {
	Success    bool       `json:"success"`
	Path       string     `json:"path"`
	Items      []Item     `json:"items"`
	Pagination Pagination `json:"pagination"`
	SortBy     string     `json:"-"`
	Order      string     `json:"-"`
	Query      string     `json:"query"`
	Error      string     `json:"error,omitempty"`
	Status     int        `json:"-"`
}

// Pagination mirrors the listing pagination block.
type Pagination struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	TotalCount int  `json:"total_count"`
	TotalPages int  `json:"total_pages"`
	HasNext    bool `json:"has_next"`
	HasPrev    bool `json:"has_prev"`
}

// AccessFilter decides per-item read visibility (ensure_path_access).
type AccessFilter func(relPath, action string) bool

// CapabilityResolver builds per-item capabilities.
type CapabilityResolver func(relPath string, isDir bool, itemType string) map[string]bool

// ListOptions mirrors list_directory_page arguments.
type ListOptions struct {
	BaseDir  string
	Subpath  string
	Page     int
	PageSize int
	SortBy   string
	Order    string
	Query    string
	CanRead  AccessFilter
	Caps     CapabilityResolver
}

// ListPage lists one directory page.
func ListPage(o ListOptions) Page {
	page := o.Page
	if page < 1 {
		page = 1
	}
	pageSize := o.PageSize
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize < MinPageSize {
		pageSize = MinPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	sortBy := strings.ToLower(strings.TrimSpace(o.SortBy))
	switch sortBy {
	case "name", "size", "date", "type":
	default:
		sortBy = "name"
	}
	order := strings.ToLower(strings.TrimSpace(o.Order))
	reverse := false
	if order == "desc" {
		order = "desc"
		reverse = true
	} else {
		order = "asc"
	}
	query := strings.ToLower(strings.TrimSpace(o.Query))

	entries, ferr := readDirEntries(o.BaseDir, o.Subpath, query, o.CanRead)
	if ferr != nil {
		return *ferr
	}
	var folders, fileList []Item
	for _, it := range entries {
		if it.IsDir {
			folders = append(folders, it)
		} else {
			fileList = append(fileList, it)
		}
	}
	sortItems(folders, sortBy, reverse)
	sortItems(fileList, sortBy, reverse)
	entries = append(folders, fileList...)

	total := len(entries)
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
	if totalPages < 1 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}
	items := append([]Item{}, entries[start:end]...)
	if o.Caps != nil {
		for i := range items {
			caps := o.Caps(items[i].Path, items[i].IsDir, items[i].Type)
			if caps == nil {
				caps = map[string]bool{}
			}
			items[i].Capabilities = caps
		}
	}
	return Page{Success: true, Path: o.Subpath, Items: items, Pagination: Pagination{
		Page: page, PageSize: pageSize, TotalCount: total,
		TotalPages: totalPages, HasNext: page < totalPages, HasPrev: page > 1,
	}, SortBy: sortBy, Order: order, Query: query}
}

func sortItems(items []Item, sortBy string, reverse bool) {
	less := func(a, b Item) bool {
		var c bool
		switch sortBy {
		case "size":
			if a.Size != b.Size {
				c = a.Size < b.Size
			} else {
				c = strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
		case "date":
			if a.Mtime != b.Mtime {
				c = a.Mtime < b.Mtime
			} else {
				c = strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
		case "type":
			if a.Type != b.Type {
				c = a.Type < b.Type
			} else {
				c = strings.ToLower(a.Name) < strings.ToLower(b.Name)
			}
		default:
			c = strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if reverse {
			return !c
		}
		return c
	}
	// Python list.sort is stable; preserve input (scandir) order on ties.
	sort.SliceStable(items, func(i, j int) bool { return less(items[i], items[j]) })
}

func readDirEntries(baseDir, subpath, query string, canRead AccessFilter) ([]Item, *Page) {
	// NOTE: containment is enforced by the caller via ValidatePath.
	full := filepath.Join(baseDir, filepath.FromSlash(subpath))
	st, err := os.Stat(full)
	if err != nil || !st.IsDir() {
		if err == nil {
			return nil, &Page{Success: false, Error: "폴더가 아닙니다", Status: 400}
		}
		if os.IsNotExist(err) {
			return nil, &Page{Success: false, Error: "경로를 찾을 수 없습니다", Status: 404}
		}
		if os.IsPermission(err) {
			return nil, &Page{Success: false, Error: "접근 권한이 없습니다", Status: 403}
		}
		return nil, &Page{Success: false, Error: "목록을 불러오는 중 오류가 발생했습니다.", Status: 500}
	}
	dir, err := os.Open(full)
	if err != nil {
		if os.IsPermission(err) {
			return nil, &Page{Success: false, Error: "접근 권한이 없습니다", Status: 403}
		}
		return nil, &Page{Success: false, Error: "목록을 불러오는 중 오류가 발생했습니다.", Status: 500}
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return nil, &Page{Success: false, Error: "목록을 불러오는 중 오류가 발생했습니다.", Status: 500}
	}
	var items []Item
	for _, name := range names {
		if strings.HasPrefix(name, ".") {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(name), query) {
			continue
		}
		abs := filepath.Join(full, name)
		fi, err := os.Lstat(abs)
		if err != nil {
			continue
		}
		isDir := fi.IsDir() // Lstat: symlinks listed as non-dirs (parity with follow_symlinks=False)
		ext := ""
		if !isDir {
			ext = strings.ToLower(filepath.Ext(name))
		}
		rel := strings.Trim(subpath+"/"+name, "/")
		if canRead != nil && !canRead(rel, "read") {
			continue
		}
		mtime := 0.0
		if t := fi.ModTime(); !t.IsZero() {
			mtime = float64(t.UnixNano()) / 1e9
		}
		var size int64
		if !isDir {
			size = fi.Size()
		}
		itemType := "folder"
		if !isDir {
			itemType = FileType(ext)
		}
		items = append(items, Item{
			Name: name, Path: rel, IsDir: isDir, Type: itemType,
			Size: size, Mtime: mtime, Ext: ext,
		})
	}
	return items, nil
}
