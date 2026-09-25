package permission

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Folder-permission engine (parity with webshare_app/security/permissions.py
// and the mutation/capability helpers in utils/request_policy.py).
//
// Actions are exactly read/write/delete; principals are admin/guest/*.
// Admin bypasses all checks. Permissions inherit down the tree: walking from
// the root toward the target, any ancestor entry that names the action but
// does not grant the user denies (this matches Python's early-return).

// PermissionsFile is the store filename inside the shared folder.
const PermissionsFile = ".webshare_permissions.json"

// ValidActions and ValidPrincipals mirror the Python allow-lists.
var ValidActions = []string{"read", "write", "delete"}

// DefaultPermission mirrors DEFAULT_PERMISSION.
var DefaultPermission = map[string][]string{
	"read":   {"*"},
	"write":  {"*"},
	"delete": {"admin"},
}

// Capabilities mirrors build_path_capabilities exactly, including the
// parent-write rules for rename/upload/mkdir/unzip.
type Capabilities struct {
	Read   bool `json:"read"`
	Write  bool `json:"write"`
	Delete bool `json:"delete"`
	Rename bool `json:"rename"`
	Move   bool `json:"move"`
	Copy   bool `json:"copy"`
	Upload bool `json:"upload"`
	Mkdir  bool `json:"mkdir"`
	Edit   bool `json:"edit"`
	Trash  bool `json:"trash"`
	Unzip  bool `json:"unzip"`
}

func validAction(action string) bool {
	for _, a := range ValidActions {
		if a == action {
			return true
		}
	}
	return false
}

// NormalizePermissionPath mirrors normalize_permission_path: lexical
// cleanup, ".." rejected, empty/protected rejected, and the result must
// validate inside root.
func NormalizePermissionPath(root, path string) (string, error) {
	value := strings.ReplaceAll(path, "\\", "/")
	value = strings.Trim(value, "/")
	var parts []string
	for _, part := range strings.Split(value, "/") {
		part = strings.TrimSpace(part)
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return "", errors.New("invalid permission path")
		}
		parts = append(parts, part)
	}
	normalized := strings.Join(parts, "/")
	if normalized == "" || IsProtectedSystemPath(normalized) {
		return "", errors.New("invalid permission path")
	}
	if ok, _, _ := ValidatePath(root, normalized); !ok {
		return "", errors.New("invalid permission path")
	}
	return normalized, nil
}

// NormalizePermissionUsers mirrors normalize_permission_users (dedup preserving order).
func NormalizePermissionUsers(users []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u != "admin" && u != "guest" && u != "*" {
			return nil, errors.New("invalid permission user")
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// NormalizePermissionEntry mirrors normalize_permission_entry.
func NormalizePermissionEntry(root, path string, data map[string][]string) (string, map[string][]string, error) {
	if data == nil {
		return "", nil, errors.New("invalid permission entry")
	}
	normalizedPath, err := NormalizePermissionPath(root, path)
	if err != nil {
		return "", nil, err
	}
	entry := map[string][]string{}
	for action, users := range data {
		if !validAction(action) {
			return "", nil, errors.New("invalid permission action")
		}
		nu, err := NormalizePermissionUsers(users)
		if err != nil {
			return "", nil, err
		}
		entry[action] = nu
	}
	if len(entry) == 0 {
		return "", nil, errors.New("empty permission entry")
	}
	return normalizedPath, entry, nil
}

// Store is the in-memory folder-permission table with persistence.
type Store struct {
	mu      sync.RWMutex
	root    string
	entries map[string]map[string][]string
}

// NewStore creates a store rooted at the shared folder.
func NewStore(root string) *Store {
	return &Store{root: root, entries: map[string]map[string][]string{}}
}

// Root returns the shared folder root.
func (s *Store) Root() string { return s.root }

// Check mirrors check_permission (inherited, admin bypass).
func (s *Store) Check(path, user, action string) bool {
	if user == "admin" {
		return true
	}
	if !validAction(action) {
		return false
	}
	normalized := strings.Trim(strings.ReplaceAll(path, "\\", "/"), "/")
	s.mu.RLock()
	defer s.mu.RUnlock()
	current := ""
	for _, part := range strings.Split(normalized, "/") {
		if part == "" {
			continue
		}
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		perm, ok := s.entries[current]
		if !ok {
			continue
		}
		users, ok := perm[action]
		if !ok {
			continue
		}
		granted := false
		for _, u := range users {
			if u == "*" || u == user {
				granted = true
				break
			}
		}
		if !granted {
			return false
		}
	}
	return true
}

// Set mirrors set_folder_permission (validated, merged over defaults).
func (s *Store) Set(path, action string, users []string) error {
	normalizedPath, err := NormalizePermissionPath(s.root, path)
	if err != nil {
		return err
	}
	if !validAction(action) {
		return errors.New("invalid permission action")
	}
	nu, err := NormalizePermissionUsers(users)
	if err != nil {
		return err
	}
	s.mu.Lock()
	current := map[string][]string{}
	for k, v := range DefaultPermission {
		current[k] = append([]string{}, v...)
	}
	for k, v := range s.entries[normalizedPath] {
		current[k] = append([]string{}, v...)
	}
	current[action] = nu
	s.entries[normalizedPath] = current
	s.mu.Unlock()
	return s.Save()
}

// Delete mirrors delete_folder_permission.
func (s *Store) Delete(path string) bool {
	normalizedPath, err := NormalizePermissionPath(s.root, path)
	if err != nil {
		return false
	}
	s.mu.Lock()
	if _, ok := s.entries[normalizedPath]; !ok {
		s.mu.Unlock()
		return false
	}
	delete(s.entries, normalizedPath)
	s.mu.Unlock()
	_ = s.Save()
	return true
}

// Save persists validated entries atomically (temp + rename).
func (s *Store) Save() error {
	s.mu.RLock()
	snapshot := map[string]map[string][]string{}
	for path, entry := range s.entries {
		np, ne, err := NormalizePermissionEntry(s.root, path, entry)
		if err != nil {
			continue
		}
		snapshot[np] = ne
	}
	s.mu.RUnlock()
	out, err := json.MarshalIndent(snapshot, "", "    ")
	if err != nil {
		return err
	}
	dest := filepath.Join(s.root, PermissionsFile)
	tmp, err := os.CreateTemp(s.root, ".webshare_perm_*.tmp")
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
	return os.Rename(tmpName, dest)
}

// Load reads the store file, skipping invalid legacy entries.
func (s *Store) Load() error {
	data, err := os.ReadFile(filepath.Join(s.root, PermissionsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var loaded map[string]map[string][]string
	if err := json.Unmarshal(data, &loaded); err != nil {
		return err
	}
	normalized := map[string]map[string][]string{}
	for path, entry := range loaded {
		np, ne, err := NormalizePermissionEntry(s.root, path, entry)
		if err != nil {
			continue
		}
		normalized[np] = ne
	}
	s.mu.Lock()
	s.entries = normalized
	s.mu.Unlock()
	return nil
}

// RoleCanMutate mirrors role_can_mutate: admins always, guests only when
// guest upload is enabled.
func RoleCanMutate(role string, allowGuestUpload bool) bool {
	if role == "admin" {
		return true
	}
	return allowGuestUpload
}

// EnsureMutationAllowed mirrors ensure_mutation_allowed.
func EnsureMutationAllowed(role string, allowGuestUpload bool) (bool, string, int) {
	if RoleCanMutate(role, allowGuestUpload) {
		return true, "", 200
	}
	return false, "업로드/변경 권한이 없습니다", 403
}

// EnsurePathAccess mirrors ensure_path_access: protected check first,
// then the permission engine. Returns (ok, message, status).
func (s *Store) EnsurePathAccess(path, action, role string) (bool, string, int) {
	normalized := NormalizeRelativePath(path)
	if IsProtectedSystemPath(normalized) {
		return false, "시스템 경로 접근이 차단되었습니다", 403
	}
	if !s.Check(normalized, role, action) {
		return false, "권한이 없습니다", 403
	}
	return true, "", 200
}

// BuildCapabilities mirrors build_path_capabilities.
func (s *Store) BuildCapabilities(path, role string, isDir bool, itemType string, allowGuestUpload bool) Capabilities {
	normalized := NormalizeRelativePath(path)
	parent := GetParentRelativePath(normalized)
	mut := RoleCanMutate(role, allowGuestUpload)
	read := !IsProtectedSystemPath(normalized) && s.Check(normalized, role, "read")
	write := mut && !IsProtectedSystemPath(normalized) && s.Check(normalized, role, "write")
	del := mut && !IsProtectedSystemPath(normalized) && s.Check(normalized, role, "delete")
	parentWrite := mut && !IsProtectedSystemPath(parent) && s.Check(parent, role, "write")
	uploadMkdir := write
	if !isDir {
		uploadMkdir = parentWrite
	}
	return Capabilities{
		Read:   read,
		Write:  write,
		Delete: del,
		Rename: del && parentWrite,
		Move:   del,
		Copy:   mut && read,
		Upload: uploadMkdir,
		Mkdir:  uploadMkdir,
		Edit:   write && !isDir,
		Trash:  del,
		Unzip:  mut && !isDir && itemType == "archive" && read && parentWrite,
	}
}
