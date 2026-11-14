package mega

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestExpiredDownloadURLRefresh(t *testing.T) {
	data := []byte("fresh URL ciphertext")
	key, encrypted := fixtureFile(data)
	meta, _ := fileMeta(key)
	var resolutions atomic.Int32
	var expired atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs" {
			version := "expired"
			if resolutions.Add(1) >= 3 {
				version = "fresh"
			}
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"s": len(data), "at": fixtureAttr(meta.key, "file.bin"), "g": "http://" + r.Host + "/" + version}})
			return
		}
		if r.URL.Path[:8] == "/expired" {
			expired.Add(1)
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write(encrypted)
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(server.URL)
	m.SetRetries(0)
	result, err := m.DownloadPublic(context.Background(), "https://mega.nz/file/"+fixtureHandle+"#"+base64urlencode(key), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(result.Path)
	if string(got) != string(data) || expired.Load() != 1 {
		t.Fatal("failed to refresh URL")
	}
}

func TestDownloadCancellationJoinsRequests(t *testing.T) {
	data := make([]byte, 500000)
	key, _ := fixtureFile(data)
	meta, _ := fileMeta(key)
	started := make(chan struct{}, 8)
	stopped := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs" {
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"s": len(data), "at": fixtureAttr(meta.key, "file.bin"), "g": "http://" + r.Host + "/slow"}})
			return
		}
		started <- struct{}{}
		<-r.Context().Done()
		stopped <- struct{}{}
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(server.URL)
	_ = m.SetDownloadWorkers(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	dest := t.TempDir()
	go func() {
		_, err := m.DownloadPublic(ctx, "https://mega.nz/file/"+fixtureHandle+"#"+base64urlencode(key), dest, nil)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("no request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancel blocked")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("request leaked")
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 0 {
		t.Fatal("cancel left partial output")
	}
}

func TestQuotaPositiveStatesAreNotErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("[2]")) }))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(server.URL)
	state, err := m.EstimateFreeTransferQuota(context.Background(), nil, []string{fixtureHandle}, 0)
	if err != nil || state != 2 {
		t.Fatalf("quota state=%d err=%v", state, err)
	}
}

func TestStalledBodyHasBoundedRequestDeadline(t *testing.T) {
	stopped := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "8")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		stopped <- struct{}{}
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetRetries(0)
	m.SetTimeOut(100 * time.Millisecond)
	start := time.Now()
	if _, err := m.transferRequest(context.Background(), "GET", server.URL, nil, 8, true); err == nil {
		t.Fatal("stalled body succeeded")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("stalled body ignored deadline")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled body request leaked")
	}
}
