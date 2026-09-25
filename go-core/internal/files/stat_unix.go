//go:build !windows

package files

import "time"

func creationTimeOS(abs string) time.Time { return time.Time{} }

func accessTimeOS(abs string) time.Time { return time.Time{} }
