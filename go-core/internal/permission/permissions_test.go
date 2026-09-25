package permission

import (
	"encoding/json"
	"reflect"
	"testing"
)

func loadStore(t *testing.T, root string) *Store {
	t.Helper()
	v := fixture(t, "path_vectors.json")
	raw, err := json.Marshal(v["permission_store"])
	if err != nil {
		t.Fatal(err)
	}
	var store map[string]map[string][]string
	if err := json.Unmarshal(raw, &store); err != nil {
		t.Fatal(err)
	}
	s := NewStore(root)
	s.entries = store
	return s
}

func TestPermissionCheckVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	root := testRoot(t)
	s := loadStore(t, root)
	for i, c := range v["permission_checks"].([]any) {
		m := c.(map[string]any)
		got := s.Check(m["path"].(string), m["user"].(string), m["action"].(string))
		if got != m["expect"].(bool) {
			t.Errorf("case %d: Check(%q,%q,%q) = %v, want %v",
				i, m["path"], m["user"], m["action"], got, m["expect"])
		}
	}
}

func TestCapabilitiesVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	root := testRoot(t)
	s := loadStore(t, root)
	for i, c := range v["capabilities"].([]any) {
		m := c.(map[string]any)
		got := s.BuildCapabilities(
			m["path"].(string), m["role"].(string),
			m["is_dir"].(bool), m["item_type"].(string),
			m["allow_guest_upload"].(bool),
		)
		raw, _ := json.Marshal(m["expect"])
		var want Capabilities
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("case %d: capabilities(%v) = %+v, want %+v", i, m, got, want)
		}
	}
}

func TestAccessVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	root := testRoot(t)
	s := loadStore(t, root)
	for i, c := range v["access"].([]any) {
		m := c.(map[string]any)
		ok, _, code := s.EnsurePathAccess(m["path"].(string), m["action"].(string), m["role"].(string))
		if ok != m["expect_ok"].(bool) || code != int(m["expect_code"].(float64)) {
			t.Errorf("case %d: access = (%v,%d), want (%v,%v)",
				i, ok, code, m["expect_ok"], m["expect_code"])
		}
	}
}

func TestStoreSetDeleteLoadRoundTrip(t *testing.T) {
	root := testRoot(t)
	s := NewStore(root)
	if err := s.Set("docs", "write", []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if s.Check("docs/a.txt", "guest", "write") {
		t.Fatal("guest write allowed after admin-only set")
	}
	if !s.Check("docs/a.txt", "guest", "read") {
		t.Fatal("guest read lost (defaults not merged)")
	}
	if s.Set("../escape", "read", []string{"*"}) == nil {
		t.Fatal("traversal permission path accepted")
	}
	if s.Set("docs", "execute", []string{"*"}) == nil {
		t.Fatal("invalid action accepted")
	}
	if !s.Delete("docs") {
		t.Fatal("delete failed")
	}
	if s.Delete("docs") {
		t.Fatal("double delete reported success")
	}
	// Persistence round trip (Set merges over DEFAULT_PERMISSION, so
	// write stays open to everyone — parity with set_folder_permission).
	if err := s.Set("docs", "read", []string{"guest"}); err != nil {
		t.Fatal(err)
	}
	loaded := NewStore(root)
	if err := loaded.Load(); err != nil {
		t.Fatal(err)
	}
	if !loaded.Check("docs/f.txt", "guest", "read") {
		t.Fatal("loaded store lost permission")
	}
	if !loaded.Check("docs/f.txt", "guest", "write") {
		t.Fatal("loaded store lost default-merged write")
	}
}
