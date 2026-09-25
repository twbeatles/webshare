package files

import (
	"fmt"
	"hash/adler32"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// ByteRange is one parsed Range-spec.
type ByteRange struct {
	Start  int64
	Length int64
}

// WerkzeugETag mirrors send_file ETag generation:
// set_etag(f"{mtime}-{size}-{adler32(path) & 0xFFFFFFFF}"). mtime is float
// seconds like os.path.getmtime; the float formats like Python repr:
// shortest digits, but integral floats keep ".0" (repr never yields "1700000000").
func WerkzeugETag(abs string, mtime float64, size int64) string {
	num := strconv.FormatFloat(mtime, 'f', -1, 64)
	if !strings.ContainsAny(num, ".eE") {
		num += ".0"
	}
	check := adler32.Checksum([]byte(abs))
	return `"` + num + "-" +
		strconv.FormatInt(size, 10) + "-" + strconv.FormatUint(uint64(check), 10) + `"`
}

// mtimeFloat mirrors os.path.getmtime: CPython computes whole seconds plus
// the nanosecond remainder over 1e9 (verified bit-identical), not ns/1e9.
func mtimeFloat(modtime time.Time) float64 {
	return float64(modtime.Unix()) + float64(modtime.Nanosecond())/1e9
}

// ParseRange mirrors Werkzeug's single-range handling for "bytes=" specs.
// Multiple ranges are rejected (gap documented: Werkzeug serves multipart).
func ParseRange(header string, size int64) (ranges []ByteRange, ok bool, unsatisfiable bool) {
	if header == "" {
		return nil, true, false
	}
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return nil, true, false
	}
	spec := strings.TrimSpace(header[len(prefix):])
	if spec == "" || strings.Contains(spec, ",") {
		// Empty or multi-range: multi is a documented gap (Werkzeug
		// multipart); empty falls back to full content like send_file.
		if spec == "" {
			return nil, true, false
		}
		return nil, false, false
	}
	startStr, endStr, _ := strings.Cut(spec, "-")
	var start, end int64
	if startStr == "" {
		// Suffix range: last N bytes.
		n, err := strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
		if err != nil || n < 0 {
			return nil, false, true
		}
		if n == 0 {
			return nil, false, true
		}
		if n > size {
			n = size
		}
		return []ByteRange{{Start: size - n, Length: n}}, true, false
	}
	var err error
	start, err = strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	if err != nil || start < 0 {
		return nil, false, true
	}
	if strings.TrimSpace(endStr) == "" {
		end = size - 1
	} else {
		end, err = strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
		if err != nil || end < 0 {
			return nil, false, true
		}
	}
	if start >= size {
		return nil, false, true
	}
	if end >= size {
		end = size - 1
	}
	if end < start {
		return nil, false, true
	}
	return []ByteRange{{Start: start, Length: end - start + 1}}, true, false
}

// ServeFile streams abs with attachment disposition, range support,
// Last-Modified/ETag conditionals. w must not have a status written yet.
func ServeFile(w http.ResponseWriter, r *http.Request, abs, displayName string) {
	ServeFileWithDisposition(w, r, abs, displayName, true)
}

// ServeFileWithDisposition mirrors send_from_directory: attachment selects
// Content-Disposition attachment, otherwise inline.
func ServeFileWithDisposition(w http.ResponseWriter, r *http.Request, abs, displayName string, attachment bool) {
	ServeFileEx(w, r, abs, abs, displayName, attachment)
}

// ServeFileEx serves abs for IO while etagPath feeds the Werkzeug ETag hash
// (mirrors safe_join(conf folder, rel): no symlink resolution, so twin
// backends agree when the shared folder path contains none).
func ServeFileEx(w http.ResponseWriter, r *http.Request, abs, etagPath, displayName string, attachment bool) {
	f, err := os.Open(abs)
	if err != nil {
		http.Error(w, "open failed", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.Error(w, "not a file", http.StatusInternalServerError)
		return
	}
	size := st.Size()
	modtime := st.ModTime()
	mtype := mimeTypeOf(abs)
	// Werkzeug appends "; charset=utf-8" to text/* and *+xml responses.
	if strings.HasPrefix(mtype, "text/") || strings.HasSuffix(mtype, "+xml") {
		mtype += "; charset=utf-8"
	}

	disposition := ContentDisposition(displayName)
	if !attachment {
		disposition = InlineDisposition(displayName)
	}
	etag := WerkzeugETag(etagPath, mtimeFloat(modtime), size)
	w.Header().Set("Content-Type", mtype)
	w.Header().Set("Content-Disposition", disposition)
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", etag)

	if checkPreconditions(w, r, modtime, etag) {
		return
	}

	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" && !ifRangeAllows(r.Header.Get("If-Range"), etag, modtime) {
		rangeHeader = ""
	}
	ranges, action := ParseRanges(rangeHeader, size)
	switch action {
	case rangeUnsatisfiable:
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	case rangeSingle:
		rg := ranges[0]
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rg.Start, rg.Start+rg.Length-1, size))
		w.Header().Set("Content-Length", strconv.FormatInt(rg.Length, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = f.Seek(rg.Start, io.SeekStart)
		_, _ = io.CopyN(w, f, rg.Length)
		return
	case rangeMulti:
		serveMultipartRanges(w, f, mtype, size, ranges)
		return
	default:
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	}
}

// rangeAction classifies a Range header.
type rangeAction int

const (
	rangeFull rangeAction = iota
	rangeSingle
	rangeMulti
	rangeUnsatisfiable
)

// ParseRanges parses "bytes=" specs including multi-range sets like
// Werkzeug. Invalid syntax → rangeFull (header ignored); valid but nothing
// satisfiable → rangeUnsatisfiable.
func ParseRanges(header string, size int64) ([]ByteRange, rangeAction) {
	if header == "" {
		return nil, rangeFull
	}
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return nil, rangeFull
	}
	specs := strings.Split(header[len(prefix):], ",")
	var out []ByteRange
	for _, spec := range specs {
		rg, ok := parseOneRange(strings.TrimSpace(spec), size)
		if !ok {
			return nil, rangeFull
		}
		if rg != nil {
			out = append(out, *rg)
		}
	}
	if len(out) == 0 {
		return nil, rangeUnsatisfiable
	}
	if len(out) == 1 {
		return out, rangeSingle
	}
	return out, rangeMulti
}

// parseOneRange parses one spec: (range, true) when syntactically valid,
// nil range when valid-but-unsatisfiable, false when invalid syntax.
func parseOneRange(spec string, size int64) (*ByteRange, bool) {
	startStr, endStr, _ := strings.Cut(spec, "-")
	if startStr == "" {
		n, err := strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
		if err != nil || n < 0 {
			if strings.TrimSpace(endStr) == "" {
				return nil, false
			}
			return nil, true
		}
		if n == 0 {
			return nil, true
		}
		if n > size {
			n = size
		}
		return &ByteRange{Start: size - n, Length: n}, true
	}
	start, err := strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	if err != nil || start < 0 {
		return nil, false
	}
	var end int64
	if strings.TrimSpace(endStr) == "" {
		end = size - 1
	} else {
		end, err = strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
		if err != nil || end < 0 {
			return nil, false
		}
	}
	if start >= size {
		return nil, true
	}
	if end >= size {
		end = size - 1
	}
	if end < start {
		return nil, true
	}
	return &ByteRange{Start: start, Length: end - start + 1}, true
}

// serveMultipartRanges streams a multipart/byteranges 206 like Werkzeug.
func serveMultipartRanges(w http.ResponseWriter, f *os.File, mtype string, size int64, ranges []ByteRange) {
	mw := multipart.NewWriter(w)
	w.Header().Set("Content-Type", "multipart/byteranges; boundary="+mw.Boundary())
	w.WriteHeader(http.StatusPartialContent)
	for _, rg := range ranges {
		h := textproto.MIMEHeader{}
		h.Set("Content-Type", mtype)
		h.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rg.Start, rg.Start+rg.Length-1, size))
		part, err := mw.CreatePart(h)
		if err != nil {
			return
		}
		_, _ = f.Seek(rg.Start, io.SeekStart)
		_, _ = io.CopyN(part, f, rg.Length)
	}
	_ = mw.Close()
}

// checkPreconditions handles If-None-Match (weak comparison, 304) and
// If-Modified-Since (304). Like Werkzeug, a present If-None-Match takes
// precedence over If-Modified-Since.
func checkPreconditions(w http.ResponseWriter, r *http.Request, modtime time.Time, etag string) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if inm := r.Header.Get("If-None-Match"); inm != "" {
		for _, tag := range strings.Split(inm, ",") {
			tag = strings.TrimSpace(tag)
			if tag == "*" || weakETagEqual(tag, etag) {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
		return false
	}
	if ims := r.Header.Get("If-Modified-Since"); ims != "" {
		if t, err := time.Parse(http.TimeFormat, ims); err == nil {
			if !modtime.Truncate(time.Second).After(t) {
				w.WriteHeader(http.StatusNotModified)
				return true
			}
		}
	}
	return false
}

// weakETagEqual compares ETags weakly (W/ prefix and quotes ignored).
func weakETagEqual(a, b string) bool {
	return stripETag(a) == stripETag(b)
}

func stripETag(tag string) string {
	tag = strings.TrimSpace(tag)
	tag = strings.TrimPrefix(tag, "W/")
	tag = strings.Trim(tag, `"`)
	return tag
}

// ifRangeAllows mirrors make_conditional If-Range: an entity-tag must match
// strongly, an HTTP-date passes when the file is not newer.
func ifRangeAllows(value, etag string, modtime time.Time) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if t, err := time.Parse(http.TimeFormat, value); err == nil {
		return !modtime.Truncate(time.Second).After(t)
	}
	bare := strings.Trim(value, `"`)
	return bare != "" && bare == stripETag(etag) && !strings.HasPrefix(value, "W/")
}

// ContentDisposition mirrors Werkzeug send_file attachment style:
// bare token names stay bare, ASCII names are quoted, non-ASCII names get
// an ASCII fallback plus RFC 5987 filename* (urllib.quote rules: only
// unreserved chars stay unescaped).
func ContentDisposition(name string) string {
	if isTokenName(name) {
		return "attachment; filename=" + name
	}
	if isASCII(name) {
		return `attachment; filename="` + quoteString(name) + `"`
	}
	fallback := asciiFallback(name)
	if fallback == "" {
		fallback = "file"
	}
	return `attachment; filename="` + quoteString(fallback) + `"; filename*=UTF-8''` + rfc5987(name)
}

func isTokenName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '&', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// ZipContentDisposition mirrors make_zip_stream_response: always quoted
// fallback plus RFC 5987 filename*, even for ASCII names.
func ZipContentDisposition(name string) string {
	fallback := SafeFilename(name)
	return `attachment; filename="` + quoteString(fallback) + `"; filename*=UTF-8''` + rfc5987(name)
}

// InlineDisposition mirrors send_file(as_attachment=False): same encoding
// with the inline directive.
func InlineDisposition(name string) string {
	if isTokenName(name) {
		return "inline; filename=" + name
	}
	if isASCII(name) {
		return `inline; filename="` + quoteString(name) + `"`
	}
	fallback := asciiFallback(name)
	if fallback == "" {
		fallback = "file"
	}
	return `inline; filename="` + quoteString(fallback) + `"; filename*=UTF-8''` + rfc5987(name)
}

// quoteString escapes backslash and double-quote for quoted-string.
func quoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

// asciiFallback mirrors Werkzeug's latin-1 fallback (non-ASCII dropped).
func asciiFallback(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] < 128 {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// rfc5987 percent-encodes like urllib.parse.quote (uppercase hex,
// unreserved [A-Za-z0-9-_.~] left bare).
func rfc5987(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&0xf])
		}
	}
	return b.String()
}
