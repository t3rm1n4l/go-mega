package mega

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSpansCoverChunksContiguously(t *testing.T) {
	for _, size := range []int64{1, 131072, 5 << 20, 100 << 20, 1 << 30} {
		chunks := getChunkSizes(size)
		for _, workers := range []int{1, 3, 8} {
			next := 0
			for _, s := range spans(chunks, workers) {
				if s.first != next || s.last < s.first {
					t.Fatalf("size %d workers %d: gap at %+v", size, workers, s)
				}
				var bytes int64
				for _, c := range chunks[s.first : s.last+1] {
					bytes += int64(c.size)
				}
				if bytes > maxSpan && s.first != s.last {
					t.Fatalf("size %d: span %+v is %d bytes", size, s, bytes)
				}
				next = s.last + 1
			}
			if next != len(chunks) {
				t.Fatalf("size %d workers %d: covered %d of %d chunks", size, workers, next, len(chunks))
			}
		}
	}
}

func TestProgressSpeedIsRecent(t *testing.T) {
	var got Progress
	now := time.Now()
	// 100 s of idle history, then 50 MB in the last 6 s.
	p := &progressReporter{start: now.Add(-100 * time.Second), callback: func(pr Progress) { got = pr }}
	p.mark, p.prev = now.Add(-6*time.Second), now.Add(-10*time.Second)
	p.add(50 << 20)
	if got.BytesPerSecond < 5<<20 {
		t.Fatalf("speed %d reflects the lifetime average", got.BytesPerSecond)
	}
}

// spanServer serves byte ranges of encrypted; serve may misbehave per request.
func spanServer(t *testing.T, data []byte, serve func(n int, w http.ResponseWriter, body []byte)) (string, []byte, *[]string) {
	key, encrypted := fixtureFile(data)
	meta, _ := fileMeta(key)
	var mu sync.Mutex
	var requests []string
	count := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs" {
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"s": len(data), "at": fixtureAttr(meta.key, "file.bin"), "g": "http://" + r.Host + "/bytes"}})
			return
		}
		var first, last int
		_, _ = fmt.Sscanf(r.URL.Path, "/bytes/%d-%d", &first, &last)
		mu.Lock()
		count++
		n := count
		requests = append(requests, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Length", strconv.Itoa(last-first+1))
		serve(n, w, encrypted[first:last+1])
	}))
	t.Cleanup(server.Close)
	return server.URL, key, &requests
}

func spanDownload(t *testing.T, api string, key []byte, configure func(*Mega)) ([]byte, error) {
	m := New()
	defer m.Close()
	m.SetAPIUrl(api)
	_ = m.SetDownloadWorkers(1)
	if configure != nil {
		configure(m)
	}
	res, err := m.DownloadPublic(context.Background(), "https://mega.nz/file/"+fixtureHandle+"#"+base64urlencode(key), t.TempDir(), nil)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(res.Path)
}

func TestSpanResumesAtFirstMissingChunk(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 3<<20/16)
	api, key, requests := spanServer(t, data, func(n int, w http.ResponseWriter, body []byte) {
		if n == 1 {
			// Cut the first span partway through its fourth chunk.
			_, _ = w.Write(body[:131072+262144+393216+1000])
			return
		}
		_, _ = w.Write(body)
	})
	got, err := spanDownload(t, api, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("corrupt output")
	}
	// The cut span resumes at chunk 3 (byte 786432) with the same end.
	var end int
	_, _ = fmt.Sscanf((*requests)[0], "/bytes/0-%d", &end)
	if end == 0 || (*requests)[1] != fmt.Sprintf("/bytes/786432-%d", end) {
		t.Fatalf("requests %v", *requests)
	}
}

func TestSpanStallIsRetried(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 300000)
	api, key, requests := spanServer(t, data, func(n int, w http.ResponseWriter, body []byte) {
		if n == 1 {
			_, _ = w.Write(body[:1000])
			w.(http.Flusher).Flush()
			time.Sleep(2 * time.Second)
			return
		}
		_, _ = w.Write(body)
	})
	start := time.Now()
	got, err := spanDownload(t, api, key, func(m *Mega) { m.SetTimeOut(200 * time.Millisecond) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) || len(*requests) != 2 {
		t.Fatalf("requests %v", *requests)
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("stall was not detected promptly")
	}
}

func TestSpanCorruptionMarkedUnverified(t *testing.T) {
	data := bytes.Repeat([]byte{9}, 2<<20)
	api, key, _ := spanServer(t, data, func(_ int, w http.ResponseWriter, body []byte) {
		bad := append([]byte(nil), body...)
		bad[len(bad)/2] ^= 1
		_, _ = w.Write(bad)
	})
	m := New()
	defer m.Close()
	m.SetAPIUrl(api)
	res, err := m.DownloadPublic(context.Background(), "https://mega.nz/file/"+fixtureHandle+"#"+base64urlencode(key), t.TempDir(), nil)
	if err != nil || len(res.Unverified) != 1 {
		t.Fatalf("err = %v, unverified = %v", err, res.Unverified)
	}
}

func TestSpanQuotaIsNotRetried(t *testing.T) {
	api, key, requests := spanServer(t, make([]byte, 1000), func(_ int, w http.ResponseWriter, _ []byte) {
		w.WriteHeader(509)
	})
	if _, err := spanDownload(t, api, key, nil); !errors.Is(err, EOVERQUOTA) || len(*requests) != 1 {
		t.Fatalf("err = %v requests %v", err, *requests)
	}
}
