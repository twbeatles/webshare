//go:build windows

package main

func processAlive(pid int) bool {
	// No stdlib signal-0 on Windows; watchParent skips on windows.
	return true
}
