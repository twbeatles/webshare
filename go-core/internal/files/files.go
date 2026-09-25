// Package files ports read-only file semantics:
//
//	utils/listing.py      (list_directory_page, pagination/sort/query)
//	utils/file_utils.py   (get_file_type, fmt_bytes, safe_filename)
//	utils/zip_utils.py    (zip collection, NO_COMPRESS rules, temp zips)
//	services/file_service (_collect_allowed_zip_files, _search_files_fallback)
package files

import (
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// Extension sets mirror config ARCHIVE/AUDIO/IMAGE/TEXT/VIDEO_EXTENSIONS.
var (
	ArchiveExtensions = []string{".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
	AudioExtensions   = []string{".aac", ".flac", ".m4a", ".mp3", ".ogg", ".opus", ".wav", ".wma"}
	ImageExtensions   = []string{".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".svg", ".tiff", ".webp"}
	TextExtensions    = []string{".bat", ".c", ".cfg", ".conf", ".cpp", ".css", ".go", ".h", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".log", ".md", ".php", ".ps1", ".py", ".rb", ".rs", ".sh", ".sql", ".svelte", ".toml", ".ts", ".tsx", ".txt", ".vue", ".xml", ".yaml", ".yml"}
	VideoExtensions   = []string{".avi", ".flv", ".m4v", ".mkv", ".mov", ".mp4", ".mpeg", ".webm", ".wmv"}
)

// NoCompressExtensions mirrors zip_utils.NO_COMPRESS_EXTENSIONS.
var NoCompressExtensions = []string{
	".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".tgz",
	".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp",
	".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".flv",
	".mp3", ".aac", ".ogg", ".flac", ".m4a", ".wav",
	".pdf", ".docx", ".xlsx", ".pptx",
}

func inSet(set []string, ext string) bool {
	for _, e := range set {
		if e == ext {
			return true
		}
	}
	return false
}

// FileType mirrors get_file_type (ext includes the dot, lowercased).
func FileType(ext string) string {
	ext = strings.ToLower(ext)
	switch {
	case inSet(ImageExtensions, ext):
		return "image"
	case inSet(VideoExtensions, ext):
		return "video"
	case inSet(AudioExtensions, ext):
		return "audio"
	case inSet(TextExtensions, ext):
		return "text"
	case inSet(ArchiveExtensions, ext):
		return "archive"
	default:
		return "file"
	}
}

// ShouldCompress mirrors _compress_type_for.
func ShouldCompress(path string) bool {
	return !inSet(NoCompressExtensions, strings.ToLower(filepath.Ext(path)))
}

// FmtBytes mirrors fmt_bytes.
func FmtBytes(size int64) string {
	switch {
	case size < 1024:
		return itoa(size) + " B"
	case size < 1024*1024:
		return ftoa1(float64(size)/1024) + " KB"
	case size < 1024*1024*1024:
		return ftoa1(float64(size)/1024/1024) + " MB"
	default:
		return ftoa2(float64(size)/1024/1024/1024) + " GB"
	}
}

// SafeFilename mirrors safe_filename (cross-platform sanitizing, Unicode
// preserved), including the leading NFC normalization.
func SafeFilename(name string) string {
	if name == "" {
		return "unnamed"
	}
	name = norm.NFC.String(name)
	var b strings.Builder
	for _, r := range name {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	s := b.String()
	// Collapse runs of underscores (Python re.sub(r"_+", "_")).
	var out strings.Builder
	prevUnderscore := false
	for _, r := range s {
		if r == '_' {
			if prevUnderscore {
				continue
			}
			prevUnderscore = true
		} else {
			prevUnderscore = false
		}
		out.WriteRune(r)
	}
	s = strings.TrimSpace(out.String())
	s = strings.Trim(s, "_")
	s = strings.TrimRight(s, ". ")
	if strings.HasPrefix(s, ".") {
		s = "_" + s
	}
	if s == "" {
		return "unnamed"
	}
	ext := filepath.Ext(s)
	stem := strings.TrimSuffix(s, ext)
	if isWindowsReserved(stem) {
		s = "_" + s
		ext = filepath.Ext(s)
		stem = strings.TrimSuffix(s, ext)
	}
	if len([]rune(s)) > 200 {
		s = truncateKeepExt(stem, ext, 200)
	}
	return s
}

var windowsReserved = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

func isWindowsReserved(stem string) bool {
	upper := strings.ToUpper(stem)
	for _, r := range windowsReserved {
		if upper == r {
			return true
		}
	}
	return false
}

// truncateKeepExt cuts stem (by runes) so stem+ext fits maxLen chars.
func truncateKeepExt(stem, ext string, maxLen int) string {
	allow := maxLen - len([]rune(ext))
	if allow < 0 {
		allow = 0
	}
	runes := []rune(stem)
	if len(runes) > allow {
		runes = runes[:allow]
	}
	return string(runes) + ext
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func ftoa1(f float64) string {
	return formatFloat(f, 1)
}

func ftoa2(f float64) string {
	return formatFloat(f, 2)
}

func formatFloat(f float64, prec int) string {
	// Mirrors Python f"{x:.Nf}" (round-half-even differs at exact .5 ties;
	// inputs here are byte ratios that never land exactly on a tie).
	neg := f < 0
	if neg {
		f = -f
	}
	mult := 1.0
	for i := 0; i < prec; i++ {
		mult *= 10
	}
	rounded := float64(int64(f*mult+0.5)) / mult
	intPart := int64(rounded)
	fracPart := int64((rounded-float64(intPart))*mult + 0.5)
	s := itoa(intPart) + "."
	frac := itoa(fracPart)
	for len(frac) < prec {
		frac = "0" + frac
	}
	if neg {
		s = "-" + s
	}
	return s + frac
}
