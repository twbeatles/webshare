package upload

import (
	"syscall"
	"unsafe"
)

// DiskUsageTotalFree mirrors shutil.disk_usage: (total, free) bytes.
func DiskUsageTotalFree(dir string) (total, free int64, err error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	pathPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, err
	}
	var freeToCaller, totalBytes int64
	ret, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&totalBytes)),
		0,
	)
	if ret == 0 {
		if callErr != nil {
			return 0, 0, callErr
		}
		return 0, 0, syscall.EINVAL
	}
	return totalBytes, freeToCaller, nil
}
