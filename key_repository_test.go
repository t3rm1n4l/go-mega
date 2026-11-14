package mega

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Independent Python cryptography HKDF-SHA256 + AESGCM vector, using synthetic
// keys and the official webclient's envelope/TLV format.
const repositoryVector = "FAAAAQIDBAUGBwgJCgvX4J7RDdBDPR5qXKbjfcL4cBXobVj9YunqNt8EySktPpuUTukWvluyK76-GMTNgDdhewEPoTS_xShaamc8VXi4fQ5T8CjomixGLLJe6YKPc0S8PWfcIzKDrvGK0gYXrPKwRHWQo9au5CVM_7hDcJVBwXNkVSR7hbMRUu_D5TfX"
const repositoryPlain = "01000001010200000400000001030000080000000000000000040000040000000710000017707269766174652d65642d6b65792d7072657365727665300000170101010101010202020202020202020202020202020201c8000014756e6b6e6f776e2d6675747572652d6669656c64"

func TestRepositoryIndependentVector(t *testing.T) {
	container, _ := base64urldecode(repositoryVector)
	fields, err := decodeRepository([]byte("account-master!!"), container)
	if err != nil {
		t.Fatal(err)
	}
	var plain []byte
	for _, f := range fields {
		n := len(f.value)
		plain = append(plain, f.tag, byte(n>>16), byte(n>>8), byte(n))
		plain = append(plain, f.value...)
	}
	expected, _ := hex.DecodeString(repositoryPlain)
	if !bytes.Equal(plain, expected) {
		t.Fatal("independent repository vector mismatch")
	}
	for _, position := range []int{0, 1, 2, 14, len(container) - 1} {
		corrupt := append([]byte(nil), container...)
		corrupt[position] ^= 1
		if _, err := decodeRepository([]byte("account-master!!"), corrupt); err == nil {
			t.Fatalf("accepted corrupt byte %d", position)
		}
	}
	if _, err := decodeRepository([]byte("different-master"), container); err == nil {
		t.Fatal("accepted wrong master key")
	}
}

func TestSecureShareRepository(t *testing.T) {
	for _, mode := range []string{"save", "conflict", "repeated-conflicts", "existing", "corrupt", "foreign-identity", "unknown-version", "malformed-shares", "generation-overflow", "missing"} {
		t.Run(mode, func(t *testing.T) {
			original, _ := base64urldecode(repositoryVector)
			fields, err := decodeRepository([]byte("account-master!!"), original)
			if err != nil {
				t.Fatal(err)
			}
			proposed := []byte("new-share-key!!!")
			handle := base64urlencode([]byte{3, 3, 3, 3, 3, 3})
			if mode == "existing" {
				handle = base64urlencode(bytes.Repeat([]byte{1}, 6))
			}
			switch mode {
			case "foreign-identity":
				fields[2].value[0] = 9
			case "unknown-version":
				fields[0].value[0] = 2
			case "malformed-shares":
				fields[5].value = append(fields[5].value, 1)
			case "generation-overflow":
				binary.BigEndian.PutUint32(fields[3].value, ^uint32(0))
			}
			container, _ := encodeRepository([]byte("account-master!!"), fields)
			if mode == "corrupt" {
				container[len(container)-1] ^= 1
			}
			reads, writes := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var commands [1]map[string]json.RawMessage
				_ = json.NewDecoder(r.Body).Decode(&commands)
				var action string
				_ = json.Unmarshal(commands[0]["a"], &action)
				reply := func(v any) { _ = json.NewEncoder(w).Encode([]any{v}) }
				switch action {
				case "ug":
					reply(map[string]string{"u": "AAAAAAAAAAA"})
				case "uga":
					reads++
					if mode == "missing" {
						reply(-9)
						return
					}
					reply(map[string]string{"av": base64urlencode(container), "v": "version-7"})
				case "upv":
					writes++
					if mode == "repeated-conflicts" || mode == "conflict" && writes == 1 {
						reply(-8)
						return
					}
					var values []json.RawMessage
					_ = json.Unmarshal(commands[0]["^!keys"], &values)
					if len(values) != 3 {
						t.Error("missing version/generation")
						reply(-2)
						return
					}
					var encoded, version string
					var generation uint32
					_ = json.Unmarshal(values[0], &encoded)
					_ = json.Unmarshal(values[1], &version)
					_ = json.Unmarshal(values[2], &generation)
					if version != "version-7" || generation != 8 {
						t.Error("unversioned write")
					}
					updated, _ := base64urldecode(encoded)
					got, err := decodeRepository([]byte("account-master!!"), updated)
					if err != nil {
						t.Error(err)
						reply(-14)
						return
					}
					if len(got) != len(fields) {
						t.Error("lost repository fields")
					}
					for i, f := range fields {
						if got[i].tag != f.tag {
							t.Error("reordered fields")
						}
						switch f.tag {
						case 4:
							if binary.BigEndian.Uint32(got[i].value) != 8 {
								t.Error("wrong generation")
							}
						case 48:
							want := append(append(append([]byte(nil), f.value...), bytes.Repeat([]byte{3}, 6)...), proposed...)
							want = append(want, 1)
							if !bytes.Equal(got[i].value, want) {
								t.Error("lost existing share or incorrect new share")
							}
						default:
							if !bytes.Equal(got[i].value, f.value) {
								t.Error("modified unrelated key/field")
							}
						}
					}
					reply(map[string]string{"^!keys": "version-8"})
				default:
					t.Errorf("unexpected action %s", action)
					reply(-2)
				}
			}))
			defer server.Close()
			m := New()
			defer m.Close()
			m.k = []byte("account-master!!")
			m.SetAPIUrl(server.URL)
			m.SetRetries(0)
			key, secure, err := m.secureShareKey(context.Background(), handle, proposed)
			switch mode {
			case "save", "conflict":
				if err != nil || !secure || !bytes.Equal(key, proposed) {
					t.Fatalf("secure save: %t %v", secure, err)
				}
				expected := 1
				if mode == "conflict" {
					expected = 2
				}
				if writes != expected || reads != expected {
					t.Fatal("conflict did not re-fetch repository")
				}
			case "existing":
				if err != nil || !secure || !bytes.Equal(key, bytes.Repeat([]byte{2}, 16)) || writes != 0 {
					t.Fatal("existing key not reused")
				}
			case "missing":
				if err != nil || secure || writes != 0 {
					t.Fatal("missing repository was initialized")
				}
			case "repeated-conflicts":
				if !errors.Is(err, EAGAIN) || writes != 4 {
					t.Fatal("unbounded version conflicts")
				}
			default:
				if err == nil || writes != 0 {
					t.Fatal("invalid repository was overwritten")
				}
			}
		})
	}
}

func TestRepositoryRejectsMalformedTLV(t *testing.T) {
	for _, plain := range [][]byte{{1}, {1, 0, 0, 2, 1}, {1, 0, 0, 1, 1, 1, 0, 0, 1, 1}} {
		aead, err := repositoryCipher([]byte("account-master!!"))
		if err != nil {
			t.Fatal(err)
		}
		container := make([]byte, 14)
		container[0] = 20
		container = aead.Seal(container, container[2:], plain, nil)
		if _, err := decodeRepository([]byte("account-master!!"), container); !errors.Is(err, EBADRESP) {
			t.Fatalf("malformed TLV: %v", err)
		}
	}
}
