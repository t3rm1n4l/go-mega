package mega

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoginContextDerivationAndNoTreeFetch(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request []map[string]any
		_ = json.NewDecoder(r.Body).Decode(&request)
		switch request[0]["a"] {
		case "us0":
			_ = json.NewEncoder(w).Encode([]any{map[string]any{"v": 2, "s": base64urlencode([]byte("fixed-mega-salt16"))}})
		case "us":
			if request[0]["uh"] != "WnuPUJjZalC2KkhQoXq6yA" {
				t.Error("PBKDF2 authentication derivation differs from independent hashlib vector")
			}
			_, _ = w.Write([]byte("[-9]"))
		default:
			t.Error("login fetched filesystem or started a poller")
			_, _ = w.Write([]byte("[-2]"))
		}
	}))
	defer server.Close()
	m := New()
	defer m.Close()
	m.SetAPIUrl(server.URL)
	if err := m.LoginContext(context.Background(), "test@example.invalid", "test-password"); !errors.Is(err, ENOENT) {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("unexpected login request count")
	}
}
