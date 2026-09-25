package files

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Search mirrors services/file_service._search_files_fallback: bounded
// substring walk with dot-dir pruning and per-item read checks.

// DefaultSearchBudget mirrors time_budget_seconds=1.5.
const DefaultSearchBudget = 1500 * time.Millisecond

// SearchResult is one fallback hit.
type SearchResult struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

// SearchFallback walks baseDir for names containing query (case-insensitive).
func SearchFallback(baseDir, query string, maxResults int, budget time.Duration, canRead func(relPath string) bool) []SearchResult {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return nil
	}
	if maxResults <= 0 {
		maxResults = 100
	}
	if budget <= 0 {
		budget = DefaultSearchBudget
	}
	deadline := time.Now().Add(budget)
	var results []SearchResult
	stopped := false
	var walk func(root string)
	walk = func(root string) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		var subdirs []string
		for _, e := range entries {
			if time.Now().After(deadline) {
				stopped = true
				return
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			abs := filepath.Join(root, name)
			if e.IsDir() {
				subdirs = append(subdirs, abs)
			}
			if !strings.Contains(strings.ToLower(name), q) {
				continue
			}
			rel, err := filepath.Rel(baseDir, abs)
			if err != nil {
				continue
			}
			rel = filepath.ToSlash(rel)
			if canRead != nil && !canRead(rel) {
				continue
			}
			results = append(results, SearchResult{Name: name, Path: rel, IsDir: e.IsDir()})
			if len(results) >= maxResults {
				stopped = true
				return
			}
		}
		for _, sub := range subdirs {
			if stopped {
				return
			}
			// Prune dot-directories (parity: dirs[:] filter).
			if strings.HasPrefix(filepath.Base(sub), ".") {
				continue
			}
			walk(sub)
		}
	}
	walk(baseDir)
	return results
}
