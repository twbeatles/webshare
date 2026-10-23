package handlers

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"webshare-core/internal/upload"
)

// initChunkSession starts a one-chunk upload session and sends its data.
func initChunkSession(t *testing.T, app *App, cookies []*http.Cookie, csrf, name string, payload []byte) string {
	t.Helper()
	rec := postJSON(t, app, "/upload/chunk/init", map[string]any{
		"filename": name, "total_size": len(payload), "chunk_size": len(payload), "path": "",
	}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("init = %d (%s)", rec.Code, rec.Body.String())
	}
	sid, _ := decodeBody(t, rec)["session_id"].(string)
	rec = postMultipart(t, app, "/upload/chunk/"+sid, map[string]string{"index": "0"},
		map[string]filePart{"chunk": {"c", payload}}, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk = %d (%s)", rec.Code, rec.Body.String())
	}
	return sid
}

// Two sessions committing the same name concurrently must both survive
// under distinct names (audit ISSUE-002).
func TestChunkCompleteSameNameNeverOverwrites(t *testing.T) {
	for round := 0; round < 5; round++ {
		app, root := testApp(t)
		a := loginAs(t, app, "adminpw")
		acsrf := csrfFor(t, app, a)
		b := loginAs(t, app, "adminpw")
		bcsrf := csrfFor(t, app, b)
		pa := bytes.Repeat([]byte("A"), 4<<20)
		pb := bytes.Repeat([]byte("B"), 4<<20)
		sa := initChunkSession(t, app, a, acsrf, "IMG_0001.jpg", pa)
		sb := initChunkSession(t, app, b, bcsrf, "IMG_0001.jpg", pb)

		names := make([]string, 2)
		var wg sync.WaitGroup
		for i, c := range []struct {
			sid     string
			cookies []*http.Cookie
			csrf    string
		}{{sa, a, acsrf}, {sb, b, bcsrf}} {
			wg.Add(1)
			go func(i int, sid string, cookies []*http.Cookie, csrf string) {
				defer wg.Done()
				rec := postJSON(t, app, "/upload/chunk/"+sid+"/complete", nil, cookies, csrf)
				if rec.Code != http.StatusOK {
					t.Errorf("complete %d = %d (%s)", i, rec.Code, rec.Body.String())
					return
				}
				names[i], _ = decodeBody(t, rec)["filename"].(string)
			}(i, c.sid, c.cookies, c.csrf)
		}
		wg.Wait()
		if names[0] == "" || names[0] == names[1] {
			t.Fatalf("round %d: committed names = %v", round, names)
		}
		got := map[byte]bool{}
		for _, n := range names {
			data, err := os.ReadFile(filepath.Join(root, n))
			if err != nil || len(data) != 4<<20 {
				t.Fatalf("round %d: %s unreadable (len=%d err=%v)", round, n, len(data), err)
			}
			got[data[0]] = true
		}
		if !got['A'] || !got['B'] {
			t.Fatalf("round %d: contents lost, have %v", round, got)
		}
	}
}

// Exactly one of two concurrent completes of one session merges; the
// other gets 409 (or the idempotent 200 when it arrives after commit).
func TestChunkCompleteConcurrentSingleMerge(t *testing.T) {
	for round := 0; round < 10; round++ {
		app, root := testApp(t)
		cookies := loginAs(t, app, "adminpw")
		csrf := csrfFor(t, app, cookies)
		sid := initChunkSession(t, app, cookies, csrf, "d.bin", bytes.Repeat([]byte("z"), 1<<20))
		codes := make([]string, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				rec := postJSON(t, app, "/upload/chunk/"+sid+"/complete", nil, cookies, csrf)
				doc := decodeBody(t, rec)
				switch {
				case rec.Code == http.StatusOK && doc["idempotent"] == true:
					codes[i] = "idem"
				case rec.Code == http.StatusOK:
					codes[i] = "ok"
				default:
					codes[i] = itoa(rec.Code)
				}
			}(i)
		}
		wg.Wait()
		sort.Strings(codes)
		if !(codes[0] == "409" && codes[1] == "ok") && !(codes[0] == "idem" && codes[1] == "ok") {
			t.Fatalf("round %d: outcomes = %v", round, codes)
		}
		ents, _ := os.ReadDir(root)
		count := 0
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "d") {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("round %d: %d d*.bin files", round, count)
		}
	}
}

// Cancel during completing is refused and leaves the session intact
// (cancel_chunk_upload parity, audit ISSUE-005).
func TestChunkCancelWhileCompletingConflicts(t *testing.T) {
	app, _ := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)
	sid := initChunkSession(t, app, cookies, csrf, "x.bin", []byte("abcd"))
	app.Uploads.Update(sid, func(s *upload.Session) { s.Status = upload.StatusCompleting })
	tempDir := app.Uploads.Get(sid).TempDir

	rec := postJSON(t, app, "/upload/chunk/"+sid+"/cancel", nil, cookies, csrf)
	if rec.Code != http.StatusConflict {
		t.Fatalf("cancel during completing = %d (%s)", rec.Code, rec.Body.String())
	}
	if app.Uploads.Get(sid) == nil {
		t.Fatalf("session removed by refused cancel")
	}
	if _, err := os.Stat(tempDir); err != nil {
		t.Fatalf("temp dir removed by refused cancel: %v", err)
	}
}

// Parallel chunk transfers into one session must not race on the chunk map.
func TestChunkTransferParallelSameSession(t *testing.T) {
	app, root := testApp(t)
	cookies := loginAs(t, app, "adminpw")
	csrf := csrfFor(t, app, cookies)
	const n = 32
	rec := postJSON(t, app, "/upload/chunk/init", map[string]any{
		"filename": "p.bin", "total_size": n * 16, "chunk_size": 16, "path": "",
	}, cookies, csrf)
	sid, _ := decodeBody(t, rec)["session_id"].(string)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			postMultipart(t, app, "/upload/chunk/"+sid, map[string]string{"index": itoa(i)},
				map[string]filePart{"chunk": {"c", []byte(strings.Repeat(string(rune('a'+i%26)), 16))}}, cookies, csrf)
		}(i)
	}
	wg.Wait()
	rec = postJSON(t, app, "/upload/chunk/"+sid+"/complete", nil, cookies, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("complete = %d (%s)", rec.Code, rec.Body.String())
	}
	if st, err := os.Stat(filepath.Join(root, "p.bin")); err != nil || st.Size() != n*16 {
		t.Fatalf("merged file wrong: %v", err)
	}
}
