//go:build !windows

package upload

import "syscall"

// DiskUsageTotalFree mirrors shutil.disk_usage: (total, free) bytes.
func DiskUsageTotalFree(dir string) (total, free int64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	bsize := int64(st.Bsize)
	return int64(st.Blocks) * bsize, int64(st.Bavail) * bsize, nil
}
