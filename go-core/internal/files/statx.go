package files

import (
	"os"
	"time"
)

// statx.go provides creation/access times with OS-specific backends.
// Defaults (all platforms): creation falls back to mtime, access to now.

func creationTime(abs string, st os.FileInfo) time.Time {
	if t := creationTimeOS(abs); !t.IsZero() {
		return t
	}
	return st.ModTime()
}

func accessTime(abs string, st os.FileInfo) time.Time {
	if t := accessTimeOS(abs); !t.IsZero() {
		return t
	}
	return time.Now()
}
