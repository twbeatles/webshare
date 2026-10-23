package mutate

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func writeZip(t *testing.T, path string, members []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for _, name := range members {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("data-" + name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// Insufficient disk space refuses before extracting anything (audit ISSUE-009).
func TestUnzipArchiveReserveFailureExtractsNothing(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "a.zip")
	writeZip(t, zipPath, []string{"one.txt", "dir/two.txt"})
	extractTo := filepath.Join(root, "a")
	var asked int64
	err := UnzipArchive(zipPath, extractTo, func(total int64) (func(), *UnzipError) {
		asked = total
		return nil, &UnzipError{Msg: "디스크 여유 공간이 부족합니다.", Status: 507}
	})
	var uz *UnzipError
	if !errors.As(err, &uz) || uz.Status != 507 {
		t.Fatalf("err = %v", err)
	}
	if asked <= 0 {
		t.Fatalf("reserve asked for %d bytes", asked)
	}
	if _, err := os.Stat(extractTo); !os.IsNotExist(err) {
		t.Fatalf("extract dir created despite refusal")
	}
}

// A failure mid-extraction removes the partial directory and releases the
// reservation.
func TestUnzipArchivePartialFailureCleansUp(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "b.zip")
	// "a.txt" is a file, so creating "a.txt/b.txt" must fail.
	writeZip(t, zipPath, []string{"first.txt", "a.txt", "a.txt/b.txt"})
	extractTo := filepath.Join(root, "b")
	released := false
	err := UnzipArchive(zipPath, extractTo, func(int64) (func(), *UnzipError) {
		return func() { released = true }, nil
	})
	var uz *UnzipError
	if !errors.As(err, &uz) || uz.Status != 500 {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(extractTo); !os.IsNotExist(err) {
		t.Fatalf("partial extract dir left behind")
	}
	if !released {
		t.Fatalf("reservation not released")
	}
}

func TestUnzipArchiveSuccess(t *testing.T) {
	root := t.TempDir()
	zipPath := filepath.Join(root, "c.zip")
	writeZip(t, zipPath, []string{"one.txt", "dir/two.txt"})
	extractTo := filepath.Join(root, "c")
	if err := UnzipArchive(zipPath, extractTo, nil); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(extractTo, "dir", "two.txt")); err != nil || string(data) != "data-dir/two.txt" {
		t.Fatalf("extracted = %q %v", data, err)
	}
}
