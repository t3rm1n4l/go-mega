package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fixtureHandle = "AAAAAAAB"

// fixtureFile implements MAC accumulation using ECB/XOR, independently of the
// transfer implementation's CBC modes, and returns MEGA's packed file key.
func fixtureFile(data []byte) (key, ciphertext []byte) {
	aesKey := []byte("0123456789abcdef")
	nonce := []byte("12345678")
	block, _ := aes.NewCipher(aesKey)
	var aggregate [16]byte
	for _, chunk := range getChunkSizes(int64(len(data))) {
		var mac [16]byte
		copy(mac[:8], nonce)
		copy(mac[8:], nonce)
		for offset := 0; offset < chunk.size; offset += 16 {
			var piece [16]byte
			n := chunk.size - offset
			if n > 16 {
				n = 16
			}
			copy(piece[:], data[chunk.position+int64(offset):chunk.position+int64(offset+n)])
			for i := range mac {
				mac[i] ^= piece[i]
			}
			block.Encrypt(mac[:], mac[:])
		}
		for i := range aggregate {
			aggregate[i] ^= mac[i]
		}
		block.Encrypt(aggregate[:], aggregate[:])
	}
	mac := make([]byte, 8)
	for i := 0; i < 4; i++ {
		mac[i] = aggregate[i] ^ aggregate[i+4]
		mac[i+4] = aggregate[i+8] ^ aggregate[i+12]
	}
	key = make([]byte, 32)
	copy(key[16:24], nonce)
	copy(key[24:], mac)
	for i := 0; i < 16; i++ {
		key[i] = aesKey[i] ^ key[i+16]
	}
	iv := make([]byte, 16)
	copy(iv, nonce)
	ciphertext = make([]byte, len(data))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, data)
	return
}

func fixtureAttr(key []byte, name string) string {
	data, _ := json.Marshal(map[string]string{"n": name})
	plain := append([]byte("MEGA"), data...)
	plain = append(plain, make([]byte, (16-len(plain)%16)%16)...)
	block, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(plain, plain)
	return base64urlencode(plain)
}

func TestParsePublicLink(t *testing.T) {
	fileKey := base64urlencode(make([]byte, 32))
	folderKey := base64urlencode(make([]byte, 16))
	for _, tc := range []struct {
		raw      string
		folder   bool
		selected string
	}{
		{"https://mega.nz/file/" + fixtureHandle + "#" + fileKey, false, ""},
		{"https://mega.co.nz/#!" + fixtureHandle + "!" + fileKey, false, ""},
		{"https://mega.nz/folder/" + fixtureHandle + "#" + folderKey, true, ""},
		{"https://mega.co.nz/#F!" + fixtureHandle + "!" + folderKey + "!AAAAAAAC", true, "AAAAAAAC"},
		{"https://mega.nz/folder/" + fixtureHandle + "#" + folderKey + "/folder/AAAAAAAC", true, "AAAAAAAC"},
		{"https://mega.nz/folder/" + fixtureHandle + "#" + folderKey + "?sub=AAAAAAAC", true, "AAAAAAAC"},
		{"https://mega.nz/folder/" + fixtureHandle + "?folder=AAAAAAAC#" + folderKey, true, "AAAAAAAC"},
	} {
		link, err := ParsePublicLink(tc.raw)
		if err != nil || link.Folder != tc.folder || link.SelectedHandle != tc.selected {
			t.Fatalf("parse link shape: %v", err)
		}
	}
	for _, raw := range []string{"https://mega.nz.evil/file/" + fixtureHandle + "#" + fileKey, "https://user:password@mega.nz/file/" + fixtureHandle + "#" + fileKey, "https://mega.nz/file/AAAAAAAA#bad", "https://mega.nz:443/file/" + fixtureHandle + "#" + fileKey} {
		_, err := ParsePublicLink(raw)
		if err == nil {
			t.Fatal("accepted malformed link")
		}
		if strings.Contains(err.Error(), raw) {
			t.Fatal("error leaked link")
		}
	}
}

// fileFixture serves one public file; corrupt flips a bit in the first chunk
// of every payload request that starts at offset 0.
func fileFixture(t *testing.T, data []byte, corrupt bool) (*Mega, string, *atomic.Int32) {
	t.Helper()
	key, ciphertext := fixtureFile(data)
	meta, _ := fileMeta(key)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cs" {
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"s": len(data), "at": fixtureAttr(meta.key, "video.bin"), "g": "http://" + r.Host + "/content"}})
			return
		}
		var first, last int64
		if _, err := fmt.Sscanf(r.URL.Path, "/content/%d-%d", &first, &last); err != nil || first < 0 || last >= int64(len(data)) {
			http.Error(w, "bad range", 400)
			return
		}
		calls.Add(1)
		out := append([]byte(nil), ciphertext[first:last+1]...)
		if first == 0 && corrupt {
			out[0] ^= 1
		}
		_, _ = w.Write(out)
	}))
	t.Cleanup(server.Close)
	m := New()
	m.SetAPIUrl(server.URL)
	m.SetRetries(0)
	_ = m.SetDownloadWorkers(3)
	t.Cleanup(m.Close)
	return m, "https://mega.nz/file/" + fixtureHandle + "#" + base64urlencode(key), &calls
}

func TestPublicDownloadIntegrity(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 131071, 131072, 131073, 1048593, 6 << 20} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			data := bytes.Repeat([]byte{byte(size)}, size)
			m, link, _ := fileFixture(t, data, false)
			var last int64
			result, err := m.DownloadPublic(context.Background(), link, t.TempDir(), func(p Progress) {
				if p.Transferred < last || p.Transferred > int64(size) {
					t.Error("invalid progress")
				}
				last = p.Transferred
			})
			if err != nil {
				t.Fatal(err)
			}
			actual, err := os.ReadFile(result.Path)
			if err != nil || !bytes.Equal(data, actual) {
				t.Fatal("payload mismatch", err)
			}
			if last != int64(size) || result.Size != int64(size) {
				t.Fatal("wrong completed size")
			}
		})
	}
}

// A file whose MAC never verifies is kept and named, not failed: some
// uploaders store a wrong MAC for intact data.
func TestPersistentMACMismatchKeptUnverified(t *testing.T) {
	m, link, _ := fileFixture(t, bytes.Repeat([]byte{7}, 200000), true)
	result, err := m.DownloadPublic(context.Background(), link, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Unverified) != 1 || result.Unverified[0] != "video.bin" {
		t.Fatalf("unverified = %v", result.Unverified)
	}
	if info, err := os.Stat(result.Path); err != nil || info.Size() != 200000 {
		t.Fatal("unverified file not kept whole", err)
	}
}

func TestDownloadDoesNotReplace(t *testing.T) {
	m, link, _ := fileFixture(t, []byte("new"), false)
	dest := t.TempDir()
	path := filepath.Join(dest, "video.bin")
	_ = os.WriteFile(path, []byte("original"), 0600)
	if _, err := m.DownloadPublic(context.Background(), link, dest, nil); !errors.Is(err, EEXIST) {
		t.Fatalf("got %v", err)
	}
	actual, _ := os.ReadFile(path)
	if string(actual) != "original" {
		t.Fatal("replaced existing target")
	}
}

func TestMissingChunkFailsFinish(t *testing.T) {
	block, _ := aes.NewCipher(make([]byte, 16))
	d := &Download{aes_block: block, chunk_macs: [][]byte{nil}}
	if !errors.Is(d.Finish(), EINCOMPLETE) {
		t.Fatal("accepted incomplete download")
	}
}

func TestRunChunksLastError(t *testing.T) {
	expected := errors.New("last chunk failed")
	if err := runChunks(context.Background(), 1, 3, func(context.Context, int) error { return expected }); !errors.Is(err, expected) {
		t.Fatalf("lost final error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var stopped atomic.Int32
	err := runChunks(ctx, 10, 3, func(ctx context.Context, id int) error {
		if id == 0 {
			cancel()
		}
		<-ctx.Done()
		stopped.Add(1)
		return ctx.Err()
	})
	if !errors.Is(err, context.Canceled) || stopped.Load() == 0 {
		t.Fatalf("cancel: %v", err)
	}
}

func TestAPIRetriesCannotSucceedSilently(t *testing.T) {
	for _, status := range []int{402, 403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			m := New()
			defer m.Close()
			m.SetAPIUrl(server.URL)
			m.SetRetries(1)
			if _, err := m.GetUserContext(context.Background()); err == nil {
				t.Fatal("reported success after HTTP errors")
			}
		})
	}
}

func TestAPIQueuedCancellation(t *testing.T) {
	m := New()
	defer m.Close()
	m.apiGate <- struct{}{}
	defer func() { <-m.apiGate }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := m.GetUserContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation blocked")
	}
}

func TestRetryShortBodyAndQuota(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte("a"))
		} else {
			_, _ = w.Write([]byte("abc"))
		}
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetRetries(1)
	data, err := m.transferRequest(context.Background(), "GET", server.URL, nil, 3, true)
	if err != nil || string(data) != "abc" || calls.Load() != 2 {
		t.Fatalf("short response retry: %v", err)
	}
	quota := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(509) }))
	defer quota.Close()
	if _, err := m.transferRequest(context.Background(), "GET", quota.URL, nil, 3, true); !errors.Is(err, EOVERQUOTA) {
		t.Fatal(err)
	}
}

func TestMalformedAttributesAndSession(t *testing.T) {
	for _, raw := range []string{"", base64urlencode([]byte{1}), base64urlencode(make([]byte, 16))} {
		if _, err := decryptAttr(make([]byte, 16), raw); err == nil {
			t.Fatal("accepted invalid encrypted attributes")
		}
	}
	if _, err := decryptSessionId("AA", "AA", make([]byte, 16)); err == nil {
		t.Fatal("accepted malformed session")
	}
}

func TestInvalidWorkerCounts(t *testing.T) {
	m := New()
	defer m.Close()
	for _, n := range []int{-1, 0, 31} {
		if m.SetDownloadWorkers(n) == nil || m.SetUploadWorkers(n) == nil {
			t.Fatal("accepted invalid workers")
		}
	}
}

func TestConcurrentPublicDownloads(t *testing.T) {
	m, link, _ := fileFixture(t, bytes.Repeat([]byte{9}, 300000), false)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		dest := t.TempDir()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.DownloadPublic(context.Background(), link, dest, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// folderFixture serves a public folder of count identical small files. Batched
// "g" commands get one result each; the file named missing resolves to -9.
// Each content GET sleeps briefly so concurrency is observable.
func folderFixture(t *testing.T, count int, missing string) (link string, gSizes *[]int, maxInflight *atomic.Int32) {
	share := []byte("folder-share-key")
	block, _ := aes.NewCipher(share)
	data := []byte("parallel file")
	key, encrypted := fixtureFile(data)
	meta, _ := fileMeta(key)
	wrap := func(k []byte) string {
		wrapped := make([]byte, len(k))
		_ = blockEncrypt(block, wrapped, k)
		return "AAAAAAAB:" + base64urlencode(wrapped)
	}
	folderKey := []byte("folder-node-key!")
	nodes := []FSNode{{Hash: "AAAAAAAB", T: FOLDER, Key: wrap(folderKey), Attr: fixtureAttr(folderKey, "bundle")}}
	for i := 0; i < count; i++ {
		h := fmt.Sprintf("AAAA%04d", i)
		nodes = append(nodes, FSNode{Hash: h, Parent: "AAAAAAAB", T: FILE, Sz: int64(len(data)), Key: wrap(key), Attr: fixtureAttr(meta.key, h+".bin")})
	}
	var mu sync.Mutex
	gSizes = new([]int)
	maxInflight = new(atomic.Int32)
	var inflight atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cs" {
			now := inflight.Add(1)
			for seen := maxInflight.Load(); now > seen && !maxInflight.CompareAndSwap(seen, now); seen = maxInflight.Load() {
			}
			time.Sleep(20 * time.Millisecond)
			inflight.Add(-1)
			_, _ = w.Write(encrypted)
			return
		}
		var request []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request[0]["a"] == "f" {
			_ = json.NewEncoder(w).Encode([]FilesResp{{F: nodes}})
			return
		}
		mu.Lock()
		*gSizes = append(*gSizes, len(request))
		mu.Unlock()
		var out []any
		for _, cmd := range request {
			if cmd["n"] == missing {
				out = append(out, -9)
			} else {
				out = append(out, map[string]any{"s": len(data), "g": "http://" + r.Host + "/content"})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(server.Close)
	return server.URL + "|https://mega.nz/folder/AAAAAAAB#" + base64urlencode(share), gSizes, maxInflight
}

func downloadFixture(t *testing.T, fixture string, workers int) (string, error) {
	api, link, _ := strings.Cut(fixture, "|")
	m := New()
	defer m.Close()
	m.SetAPIUrl(api)
	_ = m.SetDownloadWorkers(workers)
	result, err := m.DownloadPublic(context.Background(), link, t.TempDir(), nil)
	return result.Path, err
}

func TestPublicFolderBatchesURLsAndBoundsConnections(t *testing.T) {
	fixture, gSizes, maxInflight := folderFixture(t, 120, "")
	path, err := downloadFixture(t, fixture, 2)
	if err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(path); len(entries) != 120 {
		t.Fatalf("got %d files", len(entries))
	}
	if len(*gSizes) != 3 || (*gSizes)[0] != resolveBatch {
		t.Fatalf("URL requests %v, want three batches", *gSizes)
	}
	// Two workers give four shared slots; parallel files must fill, not exceed, them.
	if got := maxInflight.Load(); got != 4 {
		t.Fatalf("max in-flight GETs %d, want 4", got)
	}
}

func TestPublicFolderBatchFailureFallsBackPerFile(t *testing.T) {
	fixture, gSizes, _ := folderFixture(t, 10, "AAAA0004")
	_, err := downloadFixture(t, fixture, 2)
	if !errors.Is(err, ENOENT) {
		t.Fatalf("err = %v, want ENOENT", err)
	}
	single := 0
	for _, n := range *gSizes {
		if n == 1 {
			single++
		}
	}
	if single == 0 {
		t.Fatalf("failed batch entry was not retried alone: %v", *gSizes)
	}
}

func TestUnavailableFolderLink(t *testing.T) {
	for body, want := range map[string]error{
		`-9`:           ENOENT,
		`[{"f":[]}]`:   ENOENT,
		`[{"err":-6}]`: ETOOMANY,
		`[{"e":-16}]`:  EBLOCKED,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
		m := New()
		m.SetAPIUrl(server.URL)
		_, err := m.ResolvePublic(context.Background(), "https://mega.nz/folder/AAAAAAAB#"+base64urlencode([]byte("folder-share-key")))
		m.Close()
		server.Close()
		if !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", body, err, want)
		}
	}
}

func TestPublicFolderTree(t *testing.T) {
	share := []byte("folder-share-key")
	folderKey := []byte("folder-node-key!")
	block, _ := aes.NewCipher(share)
	data := []byte("folder file")
	key, encrypted := fixtureFile(data)
	meta, _ := fileMeta(key)
	node := func(h, parent, name string, kind int, key []byte, size int) FSNode {
		wrapped := make([]byte, len(key))
		_ = blockEncrypt(block, wrapped, key)
		attributeKey := key
		if kind == FILE {
			attributeKey = meta.key
		}
		return FSNode{Hash: h, Parent: parent, T: kind, Sz: int64(size), Key: "AAAAAAAB:" + base64urlencode(wrapped), Attr: fixtureAttr(attributeKey, name)}
	}
	nodes := []FSNode{node("AAAAAAAD", "AAAAAAAC", "sample.txt", FILE, key, len(data)), node("AAAAAAAC", "AAAAAAAB", "nested", FOLDER, folderKey, 0), node("AAAAAAAB", "", "bundle", FOLDER, folderKey, 0), node("AAAAAAAE", "AAAAAAAB", "empty", FOLDER, folderKey, 0)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cs" {
			_, _ = w.Write(encrypted)
			return
		}
		if r.URL.Query().Get("n") != "AAAAAAAB" || r.URL.Query().Get("sid") != "account-session" {
			t.Error("lost folder/account auth")
		}
		var request []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request[0]["a"] == "f" {
			_ = json.NewEncoder(w).Encode([]FilesResp{{F: nodes}})
		} else {
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"s": len(data), "g": "http://" + r.Host + "/content"}})
		}
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(server.URL)
	m.sid = "account-session"
	link := "https://mega.nz/folder/AAAAAAAB#" + base64urlencode(share)
	resource, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	if resource.Size() != int64(len(data)) || len(resource.Entries()) != 4 {
		t.Fatal("incomplete metadata")
	}
	result, err := resource.Download(context.Background(), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(filepath.Join(result.Path, "nested", "sample.txt"))
	if !bytes.Equal(actual, data) {
		t.Fatal("nested file mismatch")
	}
	if info, err := os.Stat(filepath.Join(result.Path, "empty")); err != nil || !info.IsDir() {
		t.Fatal("lost empty folder")
	}
	selected, err := m.ResolvePublic(context.Background(), link+"/folder/AAAAAAAC")
	if err != nil || selected.Name() != "nested" || len(selected.Entries()) != 2 {
		t.Fatal("subfolder resolution", err)
	}
	selected, err = m.ResolvePublic(context.Background(), link+"/file/AAAAAAAD")
	if err != nil || selected.IsFolder() {
		t.Fatal("selected file", err)
	}
	nodes = append(nodes, node("AAAAAAAF", "missing!", "orphan", FOLDER, folderKey, 0))
	if _, err = m.ResolvePublic(context.Background(), link); err == nil {
		t.Fatal("accepted disconnected tree")
	}
}

func TestSnapshotRejectsUnsafeNames(t *testing.T) {
	for _, name := range []string{"..", ".", "../escape", "a\\b", "", "bad\x00name", "tab\tname"} {
		r := &PublicResource{root: &Node{name: name, ntype: FILE}}
		if err := r.snapshot(); err == nil {
			t.Fatalf("accepted unsafe name %q", name)
		}
	}
}

// Names MEGA allows but Windows can't store are mapped, not refused, and
// case-insensitive duplicates within a folder get " (n)" suffixes.
func TestSnapshotMapsWindowsNames(t *testing.T) {
	for in, want := range map[string]string{
		"C:escape":             "C_escape",
		"NUL":                  "_NUL",
		"com1.txt":             "_com1.txt",
		"file.":                "file",
		"Why?.mp4":             "Why_.mp4",
		`Ep 1: "Pilot" <HD>|*`: "Ep 1_ _Pilot_ _HD___",
		"...":                  "_",
	} {
		r := &PublicResource{root: &Node{name: in, ntype: FILE}}
		if err := r.snapshot(); err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if r.Name() != want || r.entries[0].Path != want {
			t.Errorf("%q -> name %q path %q, want %q", in, r.Name(), r.entries[0].Path, want)
		}
	}

	root := &Node{name: "Show: S1", ntype: FOLDER}
	for _, name := range []string{"A.mp4", "a.mp4", "a?.mp4", "a:.mp4", ".hidden", ".HIDDEN"} {
		root.children = append(root.children, &Node{name: name, ntype: FILE})
	}
	r := &PublicResource{root: root}
	if err := r.snapshot(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range r.entries {
		got = append(got, e.Path)
	}
	want := []string{"Show_ S1", "Show_ S1/.HIDDEN", "Show_ S1/.hidden (2)", "Show_ S1/A.mp4",
		"Show_ S1/a (2).mp4", "Show_ S1/a_.mp4", "Show_ S1/a_ (2).mp4"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("paths\n got %q\nwant %q", got, want)
	}
}

func TestHashcashCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := solveHashCashChallengeContext(ctx, base64urlencode(make([]byte, 48)), 0, time.Second, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzParsePublicLink(f *testing.F) {
	f.Add("https://mega.nz/file/AAAAAAAB#" + base64urlencode(make([]byte, 32)))
	f.Fuzz(func(t *testing.T, raw string) { _, _ = ParsePublicLink(raw) })
}
func FuzzDecryptAttr(f *testing.F) {
	f.Add("AA")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = decryptAttr(make([]byte, 16), raw) })
}

func TestLinkFormattingRedactsKey(t *testing.T) {
	key := base64urlencode(bytes.Repeat([]byte{5}, 32))
	link, err := ParsePublicLink("https://mega.nz/file/" + fixtureHandle + "#" + key)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{fmt.Sprint(link), fmt.Sprintf("%+v", link), fmt.Sprintf("%#v", link)} {
		if strings.Contains(text, key) || strings.Contains(text, "[5 5") {
			t.Fatal("formatted link leaked key")
		}
	}
}

func TestConcurrentPublicationRejectsDuplicate(t *testing.T) {
	m, link, _ := fileFixture(t, bytes.Repeat([]byte{3}, 300000), false)
	destination := t.TempDir()
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := m.DownloadPublic(context.Background(), link, destination, nil)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, EEXIST) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("published %d copies into one destination", successes.Load())
	}
}
