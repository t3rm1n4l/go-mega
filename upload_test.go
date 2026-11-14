package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fixtureUpload struct {
	data     []byte
	parts    map[int64]bool
	received int64
	token    string
}
type uploadFixture struct {
	mu         sync.Mutex
	master     []byte
	nodes      map[string]FSNode
	uploads    map[string]*fixtureUpload
	contents   map[string][]byte
	shares     map[string][]byte
	public     map[string]string
	next       int
	failFinal  bool
	shareSeen  bool
	repository []byte
}

func newUploadFixture(t *testing.T) (*Mega, *uploadFixture) {
	t.Helper()
	state := &uploadFixture{master: []byte("account-master!!"), nodes: map[string]FSNode{}, uploads: map[string]*fixtureUpload{}, contents: map[string][]byte{}, shares: map[string][]byte{}, public: map[string]string{}}
	server := httptest.NewServer(http.HandlerFunc(state.serve))
	t.Cleanup(server.Close)
	m := New()
	m.SetAPIUrl(server.URL)
	m.SetRetries(0)
	_ = m.SetUploadWorkers(3)
	m.sid = "fixture-session"
	m.k = append([]byte(nil), state.master...)
	t.Cleanup(m.Close)
	root := &Node{fs: m.FS, name: "Cloud Drive", hash: "AAAAAAAA", ntype: ROOT}
	m.FS.root = root
	m.FS.lookup[root.hash] = root
	return m, state
}

func (s *uploadFixture) newHandle() string {
	s.next++
	var raw [6]byte
	binary.BigEndian.PutUint32(raw[2:], uint32(s.next))
	return base64urlencode(raw[:])
}

func (s *uploadFixture) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := func(value any) { _ = json.NewEncoder(w).Encode([]any{value}) }
	if strings.HasPrefix(r.URL.Path, "/upload/") {
		parts := strings.Split(r.URL.Path, "/")
		offset, _ := strconv.ParseInt(parts[3], 10, 64)
		upload := s.uploads[parts[2]]
		if upload == nil {
			http.Error(w, "missing", 404)
			return
		}
		data, _ := io.ReadAll(r.Body)
		if offset < 0 || offset+int64(len(data)) > int64(len(upload.data)) {
			http.Error(w, "range", 400)
			return
		}
		copy(upload.data[offset:], data)
		if !upload.parts[offset] {
			upload.received += int64(len(data))
			upload.parts[offset] = true
		}
		if upload.received == int64(len(upload.data)) {
			if s.failFinal {
				_, _ = w.Write([]byte("-17"))
				return
			}
			_, _ = w.Write([]byte(upload.token))
		}
		return
	}
	if strings.HasPrefix(r.URL.Path, "/content/") {
		parts := strings.Split(r.URL.Path, "/")
		data := s.contents[parts[2]]
		var first, last int
		_, _ = fmt.Sscanf(parts[3], "%d-%d", &first, &last)
		if first < 0 || last >= len(data) {
			http.Error(w, "range", 400)
			return
		}
		_, _ = w.Write(data[first : last+1])
		return
	}
	var requests []map[string]json.RawMessage
	if json.NewDecoder(r.Body).Decode(&requests) != nil || len(requests) != 1 {
		http.Error(w, "bad request", 400)
		return
	}
	request := requests[0]
	str := func(name string) string { var value string; _ = json.Unmarshal(request[name], &value); return value }
	command := str("a")
	switch command {
	case "u":
		var size int
		_ = json.Unmarshal(request["s"], &size)
		id := s.newHandle()
		rawID, _ := base64urldecode(id)
		token := base64urlencode(append(make([]byte, 21), rawID...))
		s.uploads[id] = &fixtureUpload{data: make([]byte, size), parts: map[int64]bool{}, token: token}
		reply(map[string]any{"p": "http://" + r.Host + "/upload/" + id})
	case "p":
		var nodes []struct {
			H string `json:"h"`
			T int    `json:"t"`
			A string `json:"a"`
			K string `json:"k"`
		}
		_ = json.Unmarshal(request["n"], &nodes)
		if len(nodes) != 1 {
			reply(-2)
			return
		}
		incoming := nodes[0]
		handle := s.newHandle()
		node := FSNode{Hash: handle, Parent: str("t"), T: incoming.T, Attr: incoming.A, User: "fixture-user", Key: "fixture-user:" + incoming.K}
		if incoming.T == FILE {
			found := false
			for _, u := range s.uploads {
				if u.token == incoming.H {
					node.Sz = int64(len(u.data))
					s.contents[handle] = append([]byte(nil), u.data...)
					found = true
					break
				}
			}
			if !found {
				reply(-2)
				return
			}
		}
		s.nodes[handle] = node
		reply(UploadCompleteResp{F: []FSNode{node}})
	case "ug":
		reply(map[string]any{"u": "AAAAAAAAAAA", "email": "fixture@example.invalid"})
	case "uga":
		if s.repository != nil {
			reply(map[string]string{"av": base64urlencode(s.repository), "v": "fixture-version"})
			return
		}
		reply(-9)
	case "upv":
		var values []json.RawMessage
		if json.Unmarshal(request["^!keys"], &values) != nil || len(values) != 3 {
			reply(-2)
			return
		}
		var encoded string
		_ = json.Unmarshal(values[0], &encoded)
		container, err := base64urldecode(encoded)
		if err != nil {
			reply(-14)
			return
		}
		fields, err := decodeRepository(s.master, container)
		if err != nil {
			reply(-14)
			return
		}
		for _, field := range fields {
			if field.tag == 48 {
				for offset := 0; offset+23 <= len(field.value); offset += 23 {
					s.shares[base64urlencode(field.value[offset:offset+6])] = append([]byte(nil), field.value[offset+6:offset+22]...)
				}
			}
		}
		s.repository = container
		reply(map[string]string{"^!keys": "fixture-new-version"})
	case "s2":
		master, _ := aes.NewCipher(s.master)
		share, err := base64urldecode(str("ok"))
		if err != nil || blockDecrypt(master, share, share) != nil {
			reply(-14)
			return
		}
		auth, _ := base64urldecode(str("ha"))
		if s.repository != nil {
			owner, _ := base64urldecode(str("ok"))
			if !bytes.Equal(owner, make([]byte, 16)) || !bytes.Equal(auth, make([]byte, 16)) {
				reply(-14)
				return
			}
			share = s.shares[str("n")]
			if len(share) != 16 {
				reply(-14)
				return
			}
		} else if blockDecrypt(master, auth, auth) != nil || string(auth) != str("n")+str("n") {
			reply(-14)
			return
		}
		var cr []json.RawMessage
		if json.Unmarshal(request["cr"], &cr) != nil || len(cr) != 3 {
			reply(-2)
			return
		}
		var roots, handles []string
		var keys []json.RawMessage
		_ = json.Unmarshal(cr[0], &roots)
		_ = json.Unmarshal(cr[1], &handles)
		_ = json.Unmarshal(cr[2], &keys)
		if len(roots) != 1 || roots[0] != str("n") || len(keys) != 3*len(handles) {
			reply(-2)
			return
		}
		shareBlock, _ := aes.NewCipher(share)
		for i := 0; i < len(keys); i += 3 {
			var root, index int
			var encoded string
			_ = json.Unmarshal(keys[i], &root)
			_ = json.Unmarshal(keys[i+1], &index)
			_ = json.Unmarshal(keys[i+2], &encoded)
			if root != 0 || index != i/3 {
				reply(-2)
				return
			}
			node := s.nodes[handles[index]]
			_, wrapped, _ := strings.Cut(node.Key, ":")
			expected, _ := base64urldecode(wrapped)
			_ = blockDecrypt(master, expected, expected)
			actual, _ := base64urldecode(encoded)
			if blockDecrypt(shareBlock, actual, actual) != nil || !bytes.Equal(actual, expected) {
				reply(-14)
				return
			}
		}
		s.shareSeen = true
		s.shares[str("n")] = share
		reply(map[string]any{"r": []int{0}})
	case "l":
		handle := s.newHandle()
		s.public[handle] = str("n")
		reply(handle)
	case "f":
		if string(request["r"]) != "1" {
			reply(-2)
			return
		}
		root := s.public[r.URL.Query().Get("n")]
		share := s.shares[root]
		if len(share) != 16 {
			reply(-9)
			return
		}
		shareBlock, _ := aes.NewCipher(share)
		master, _ := aes.NewCipher(s.master)
		var selected []FSNode
		var collect func(string)
		collect = func(handle string) {
			node := s.nodes[handle]
			_, wrapped, _ := strings.Cut(node.Key, ":")
			key, _ := base64urldecode(wrapped)
			_ = blockDecrypt(master, key, key)
			_ = blockEncrypt(shareBlock, key, key)
			node.Key = root + ":" + base64urlencode(key)
			selected = append([]FSNode{node}, selected...)
			for child, n := range s.nodes {
				if n.Parent == handle {
					collect(child)
				}
			}
		}
		collect(root)
		reply(FilesResp{F: selected})
	case "g":
		handle := str("n")
		if pub := str("p"); pub != "" {
			handle = s.public[pub]
		}
		node, ok := s.nodes[handle]
		if !ok {
			reply(-9)
			return
		}
		reply(map[string]any{"s": node.Sz, "at": node.Attr, "g": "http://" + r.Host + "/content/" + handle})
	default:
		reply(-2)
	}
}

func TestUploadPublicRoundTrip(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprintf("secure=%t", secure), func(t *testing.T) { testUploadPublicRoundTrip(t, secure) })
	}
}

func testUploadPublicRoundTrip(t *testing.T, secure bool) {
	m, state := newUploadFixture(t)
	if secure {
		state.repository, _ = base64urldecode(repositoryVector)
	}
	root := filepath.Join(t.TempDir(), "bundle")
	_ = os.MkdirAll(filepath.Join(root, "nested", "empty"), 0700)
	for _, name := range []string{"zero.bin", "nested/日本語.txt", "nested/large.bin"} {
		data := []byte{}
		if name != "zero.bin" {
			data = bytes.Repeat([]byte{1, 2, 3, 4}, 400000)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var last int64
	result, err := m.UploadPath(context.Background(), root, m.FS.GetRoot(), func(p Progress) {
		if p.Transferred < last || p.Transferred > p.Total {
			t.Error("invalid upload progress")
		}
		last = p.Transferred
	})
	if err != nil {
		t.Fatal(err)
	}
	if !state.shareSeen || last != result.Size {
		t.Fatal("folder keys/progress missing")
	}
	anonymous := New()
	defer anonymous.Close()
	anonymous.SetAPIUrl(m.baseurl)
	downloaded, err := anonymous.DownloadPublic(context.Background(), result.Link, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	compareTree(t, root, downloaded.Path)
	fileResult, err := m.UploadPath(context.Background(), filepath.Join(root, "nested", "large.bin"), m.FS.GetRoot(), nil)
	if err != nil {
		t.Fatal(err)
	}
	file, err := anonymous.DownloadPublic(context.Background(), fileResult.Link, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(filepath.Join(root, "nested", "large.bin"))
	got, _ := os.ReadFile(file.Path)
	if !bytes.Equal(want, got) {
		t.Fatal("file roundtrip mismatch")
	}
}

func TestUploadResponseErrorNeverCommits(t *testing.T) {
	m, state := newUploadFixture(t)
	state.failFinal = true
	path := filepath.Join(t.TempDir(), "input.bin")
	_ = os.WriteFile(path, []byte("test"), 0600)
	if _, err := m.UploadFileContext(context.Background(), path, m.FS.GetRoot(), "", nil); !errors.Is(err, EOVERQUOTA) {
		t.Fatalf("got %v", err)
	}
	if len(state.nodes) != 0 {
		t.Fatal("committed failed upload")
	}
}

func TestUploadDoesNotMutatePlaintext(t *testing.T) {
	m, _ := newUploadFixture(t)
	data := []byte("unaltered input")
	u, err := m.NewUploadContext(context.Background(), m.FS.GetRoot(), "input", int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	expected := append([]byte(nil), data...)
	if err = u.UploadChunkContext(context.Background(), 0, data); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, expected) {
		t.Fatal("upload mutated plaintext")
	}
}

func TestIncompleteUploadCannotCommit(t *testing.T) {
	m, state := newUploadFixture(t)
	u, err := m.NewUploadContext(context.Background(), m.FS.GetRoot(), "input", 300000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = u.FinishContext(context.Background()); !errors.Is(err, EINCOMPLETE) {
		t.Fatalf("got %v", err)
	}
	if len(state.nodes) != 0 {
		t.Fatal("committed incomplete upload")
	}
}

func TestUploadedCiphertextReference(t *testing.T) {
	m, state := newUploadFixture(t)
	data := bytes.Repeat([]byte{1, 2, 3, 4, 5}, 300000)
	path := filepath.Join(t.TempDir(), "input.bin")
	_ = os.WriteFile(path, data, 0600)
	node, err := m.UploadFileContext(context.Background(), path, m.FS.GetRoot(), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	encrypted := append([]byte(nil), state.contents[node.hash]...)
	state.mu.Unlock()
	key := node.meta.compkey
	aesKey := make([]byte, 16)
	for i := range aesKey {
		aesKey[i] = key[i] ^ key[i+16]
	}
	iv := make([]byte, 16)
	copy(iv, key[16:24])
	block, _ := aes.NewCipher(aesKey)
	cipher.NewCTR(block, iv).XORKeyStream(encrypted, encrypted)
	if !bytes.Equal(encrypted, data) {
		t.Fatal("reference AES-CTR decryption mismatch")
	}
}

func TestUploadTokenMayStartWithDash(t *testing.T) {
	m, state := newUploadFixture(t)
	u, err := m.NewUploadContext(context.Background(), m.FS.GetRoot(), "input", 3)
	if err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	for _, upload := range state.uploads {
		upload.token = base64urlencode(append([]byte{0xfb}, make([]byte, 26)...))
	}
	state.mu.Unlock()
	if err = u.UploadChunkContext(context.Background(), 0, []byte("abc")); err != nil {
		t.Fatal("valid token beginning with dash:", err)
	}
}

// compareTree fails unless both directory trees hold the same paths and file bytes.
func compareTree(t *testing.T, want, got string) {
	t.Helper()
	expected := map[string][32]byte{}
	actual := map[string][32]byte{}
	scan := func(root string, out map[string][32]byte) {
		t.Helper()
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				out[relative] = [32]byte{}
				return nil
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			hash := sha256.New()
			_, copyErr := io.Copy(hash, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			var sum [32]byte
			copy(sum[:], hash.Sum(nil))
			out[relative] = sum
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	scan(want, expected)
	scan(got, actual)
	if len(expected) != len(actual) {
		t.Fatalf("tree entry count: want=%d got=%d", len(expected), len(actual))
	}
	for path, hash := range expected {
		if got, ok := actual[path]; !ok || got != hash {
			t.Fatalf("tree mismatch at %s", path)
		}
	}
}
