package permission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	p := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "fixtures", "go_migration", "milestone_b", name)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// testRoot builds a root dir matching the vector assumptions (a/, a/b/).
func testRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"a", "a/b", "realdir", "docs", "docs/public", "private"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func expandPlaceholders(root, rel string) string {
	rel = strings.ReplaceAll(rel, "$ROOT", root)
	return strings.ReplaceAll(rel, "$PARENT", filepath.Dir(root))
}

func TestNormalizeVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	for i, c := range v["normalize"].([]any) {
		m := c.(map[string]any)
		var in string
		if m["inp"] != nil {
			in = m["inp"].(string)
		}
		if got := NormalizeRelativePath(in); got != m["out"].(string) {
			t.Errorf("case %d: Normalize(%q) = %q, want %q", i, in, got, m["out"])
		}
	}
}

func TestProtectedVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	for i, c := range v["protected"].([]any) {
		m := c.(map[string]any)
		in, _ := m["inp"].(string)
		if got := IsProtectedSystemPath(in); got != m["expect"].(bool) {
			t.Errorf("case %d: Protected(%q) = %v, want %v", i, in, got, m["expect"])
		}
	}
}

func TestParentVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	for i, c := range v["parent"].([]any) {
		m := c.(map[string]any)
		if got := GetParentRelativePath(m["inp"].(string)); got != m["out"].(string) {
			t.Errorf("case %d: Parent(%q) = %q, want %q", i, m["inp"], got, m["out"])
		}
	}
}

func TestValidateVectors(t *testing.T) {
	v := fixture(t, "path_vectors.json")
	root := testRoot(t)
	for i, c := range v["validate"].([]any) {
		m := c.(map[string]any)
		if plat, _ := m["platform"].(string); plat != "any" && plat != runtime.GOOS {
			continue
		}
		rel := expandPlaceholders(root, m["rel"].(string))
		ok, _, _ := ValidatePath(root, rel)
		if ok != m["expect_valid"].(bool) {
			t.Errorf("case %d: Validate(%q) = %v, want %v", i, m["rel"], ok, m["expect_valid"])
		}
	}
	// Symlink escape: created in-test when the platform allows it.
	if v["symlink_tested"] == true {
		link := filepath.Join(root, "evillink")
		if err := os.Symlink(filepath.Join("..", "outside"), link); err != nil {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		if ok, _, _ := ValidatePath(root, "evillink/x"); ok {
			t.Error("symlink escape validated")
		}
	}
}

func TestTraversalBattery(t *testing.T) {
	root := testRoot(t)
	// NOTE: %2e forms are NOT decoded by validate_path on either side
	// (decoding is the HTTP layer's job, tested with routes in Phase 6+).
	evil := []string{
		"..", "../x", "a/../../x", "a/../..",
		"a/b/../../../../x",
	}
	if runtime.GOOS == "windows" {
		// Backslash is a separator only on Windows.
		evil = append(evil, "..\\..\\x")
	}
	for _, rel := range evil {
		if ok, _, _ := ValidatePath(root, rel); ok {
			t.Errorf("traversal accepted: %q", rel)
		}
	}
}
