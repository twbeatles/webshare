//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// ISSUE-003: Windows parent liveness via kernel32 (stdlib only, no new
// dependencies). OpenProcess fails once the PID is gone; a live handle
// whose exit code is no longer STILL_ACTIVE means the parent exited (the
// PID may since have been recycled, same caveat as Unix signal 0).
const (
	winProcessQueryLimitedInformation = 0x1000
	winStillActive                    = 259
)

var (
	winKernel32               = syscall.NewLazyDLL("kernel32.dll")
	winProcOpenProcess        = winKernel32.NewProc("OpenProcess")
	winProcGetExitCodeProcess = winKernel32.NewProc("GetExitCodeProcess")
	winProcCloseHandle        = winKernel32.NewProc("CloseHandle")
)

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, _, _ := winProcOpenProcess.Call(
		uintptr(winProcessQueryLimitedInformation), 0, uintptr(pid))
	if handle == 0 {
		return false
	}
	defer winProcCloseHandle.Call(handle)
	var code uint32
	ret, _, _ := winProcGetExitCodeProcess.Call(
		handle, uintptr(unsafe.Pointer(&code)))
	if ret == 0 {
		// Cannot query the exit code; assume alive rather than
		// killing a healthy server on a spurious lookup failure.
		return true
	}
	return code == winStillActive
}
