//go:build windows

package files

import (
	"syscall"
	"time"
	"unsafe"
)

func fileTimes(abs string) (created, accessed time.Time) {
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return time.Time{}, time.Time{}
	}
	var data syscall.Win32FileAttributeData
	if err := syscall.GetFileAttributesEx(p, syscall.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&data))); err != nil {
		return time.Time{}, time.Time{}
	}
	created = time.Unix(0, data.CreationTime.Nanoseconds())
	accessed = time.Unix(0, data.LastAccessTime.Nanoseconds())
	return created, accessed
}

func creationTimeOS(abs string) time.Time {
	c, _ := fileTimes(abs)
	return c
}

func accessTimeOS(abs string) time.Time {
	_, a := fileTimes(abs)
	return a
}
