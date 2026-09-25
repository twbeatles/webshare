//go:build !windows

package main

import "syscall"

func processAlive(pid int) bool {
	// Signal 0 performs no action but error-checks the PID.
	err := syscall.Kill(pid, 0)
	return err == nil
}
