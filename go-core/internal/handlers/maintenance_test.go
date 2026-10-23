package handlers

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"webshare-core/internal/config"
	"webshare-core/internal/mutate"
	"webshare-core/internal/upload"
)

func tryLogin(app *App, t *testing.T, password string) int {
	form := url.Values{"password": {password}}.Encode()
	rec := app.do(t, "POST", "/", strings.NewReader(form),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, nil)
	return rec.Code
}

// A password changed on disk applies after ReloadConfig without a restart;
// boot-bound settings are reported instead of applied (audit ISSUE-007).
func TestReloadConfigAppliesPasswordChange(t *testing.T) {
	app, root := testApp(t)
	if code := tryLogin(app, t, "adminpw"); code != http.StatusFound {
		t.Fatalf("initial login = %d", code)
	}
	onDisk := app.Config()
	onDisk.AdminPw = "rotated-pw"
	onDisk.AllowGuestUpload = true
	onDisk.Folder = filepath.Join(root, "elsewhere")
	if err := config.Save(app.ConfigPath, onDisk); err != nil {
		t.Fatal(err)
	}

	restart, err := app.ReloadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(restart) != 1 || restart[0] != "folder" {
		t.Fatalf("restart = %v", restart)
	}
	if app.conf().Folder == onDisk.Folder {
		t.Fatalf("folder changed live")
	}
	if !app.conf().AllowGuestUpload {
		t.Fatalf("allow_guest_upload not applied")
	}
	if code := tryLogin(app, t, "adminpw"); code == http.StatusFound {
		t.Fatalf("old password still accepted after reload")
	}
	if code := tryLogin(app, t, "rotated-pw"); code != http.StatusFound {
		t.Fatalf("new password login = %d", code)
	}
}

// One maintenance pass auto-deletes old trash and expired upload sessions
// (audit ISSUE-006).
func TestMaintenanceOnceCleansTrashAndUploads(t *testing.T) {
	app, root := testApp(t)
	trashDir := filepath.Join(root, mutate.TrashDirName)
	if err := os.MkdirAll(trashDir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -31).Format("20060102_150405") + "_0277624c2d1c4be1b3ef49a2df11a424_old.txt"
	fresh := time.Now().Format("20060102_150405") + "_1277624c2d1c4be1b3ef49a2df11a424_new.txt"
	for _, name := range []string{old, fresh} {
		if err := os.WriteFile(filepath.Join(trashDir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tempDir := filepath.Join(root, ".upload_temp", "expired")
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatal(err)
	}
	app.Uploads.Put("expired", &upload.Session{TempDir: tempDir, Expires: time.Now().Add(-time.Minute)})

	report := app.MaintenanceOnce()

	if report.Trash != 1 || report.Uploads != 1 {
		t.Fatalf("report = %+v", report)
	}
	if _, err := os.Stat(filepath.Join(trashDir, old)); !os.IsNotExist(err) {
		t.Fatalf("31-day-old trash item kept")
	}
	if _, err := os.Stat(filepath.Join(trashDir, fresh)); err != nil {
		t.Fatalf("fresh trash item removed: %v", err)
	}
	if _, err := os.Stat(tempDir); !os.IsNotExist(err) {
		t.Fatalf("expired upload temp dir kept")
	}
	if app.Uploads.Get("expired") != nil {
		t.Fatalf("expired upload session kept")
	}
}
