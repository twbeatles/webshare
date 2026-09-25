package upload

import (
	"syscall"
	"unsafe"
)

// freeDiskBytes reports free bytes via GetDiskFreeSpaceEx (stdlib syscall,
// no cgo).
func freeDiskBytes(dir string) (int64, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	pathPtr, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var freeToCaller int64
	ret, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		0,
		0,
	)
	if ret == 0 {
		if callErr != nil {
			return 0, callErr
		}
		return 0, syscall.EINVAL
	}
	return freeToCaller, nil
}
