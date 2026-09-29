package files

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseRangesCapFallsBackToFull(t *testing.T) {
	var specs []string
	for i := int64(0); i < MaxRanges+1; i++ {
		specs = append(specs, fmt.Sprintf("%d-%d", i, i))
	}
	ranges, action := ParseRanges("bytes="+strings.Join(specs, ","), MaxRanges+1)
	if action != rangeFull {
		t.Fatalf("over-cap action = %d, want rangeFull", action)
	}
	if ranges != nil {
		t.Fatalf("over-cap ranges = %v, want nil", ranges)
	}

	specs = specs[:MaxRanges]
	ranges, action = ParseRanges("bytes="+strings.Join(specs, ","), MaxRanges)
	if action != rangeMulti || len(ranges) != MaxRanges {
		t.Fatalf("at-cap action = %d len = %d, want rangeMulti/%d", action, len(ranges), MaxRanges)
	}
}

func TestCheckZipBoundsRejectsOversize(t *testing.T) {
	big := make([]ZipItem, MaxZipItems+1)
	for i := range big {
		big[i] = ZipItem{AbsPath: "/nonexistent", ArcName: fmt.Sprintf("f%d", i)}
	}
	if err := CheckZipBounds(big); !IsZipTooLarge(err) {
		t.Fatalf("item over-cap err = %v, want zip_too_large", err)
	}
	if _, err := CreateTempZip(big); !IsZipTooLarge(err) {
		t.Fatalf("CreateTempZip over-cap err = %v, want zip_too_large", err)
	}
	if err := CheckZipBounds(nil); err != nil {
		t.Fatalf("empty items err = %v, want nil", err)
	}
}
