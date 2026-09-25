//go:build !windows

package upload

import "syscall"

// freeDiskBytes reports free bytes via statfs.
func freeDiskBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bfree) * int64(st.Bsize), nil
}
