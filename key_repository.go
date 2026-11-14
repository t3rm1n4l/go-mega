package mega

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

// MEGA's secure key repository is a versioned, AES-GCM authenticated TLV
// container. Preserve every field, including unknown tags and unrelated shares.
// Never initialize or replace a missing/unsupported repository here.
type keyField struct {
	tag   byte
	value []byte
}

func repositoryCipher(master []byte) (cipher.AEAD, error) {
	if len(master) != 16 {
		return nil, EKEY
	}
	key, err := hkdf.Key(sha256.New, master, nil, string([]byte{1}), 16)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func decodeRepository(master, container []byte) ([]keyField, error) {
	if len(container) < 30 || container[0] != 20 || container[1] != 0 {
		return nil, EKEY
	}
	aead, err := repositoryCipher(master)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, container[2:14], container[14:], nil)
	if err != nil {
		return nil, EKEY
	}
	var fields []keyField
	seen := map[byte]bool{}
	for len(plain) > 0 {
		if len(plain) < 4 {
			return nil, EBADRESP
		}
		tag := plain[0]
		size := int(plain[1])<<16 | int(plain[2])<<8 | int(plain[3])
		if seen[tag] || size > len(plain)-4 {
			return nil, EBADRESP
		}
		seen[tag] = true
		fields = append(fields, keyField{tag, append([]byte(nil), plain[4:4+size]...)})
		plain = plain[4+size:]
	}
	return fields, nil
}

func encodeRepository(master []byte, fields []keyField) ([]byte, error) {
	var plain []byte
	for _, field := range fields {
		n := len(field.value)
		if n > 0xffffff {
			return nil, EARGS
		}
		plain = append(plain, field.tag, byte(n>>16), byte(n>>8), byte(n))
		plain = append(plain, field.value...)
	}
	aead, err := repositoryCipher(master)
	if err != nil {
		return nil, err
	}
	container := make([]byte, 14)
	container[0] = 20
	if _, err = rand.Read(container[2:]); err != nil {
		return nil, err
	}
	return aead.Seal(container, container[2:], plain, nil), nil
}

// secureShareKey uses compare-and-swap attribute versions to avoid overwriting
// changes made by another MEGA client. A missing repository selects the legacy
// sharing protocol; corrupt or unsupported repositories always fail closed.
// Call with exportGate held.
func (m *Mega) secureShareKey(ctx context.Context, handle string, proposed []byte) ([]byte, bool, error) {
	user, err := m.GetUserContext(ctx)
	if err != nil {
		return nil, false, err
	}
	identity, err := base64urldecode(user.U)
	if err != nil || len(identity) != 8 {
		return nil, false, EBADRESP
	}
	node, err := base64urldecode(handle)
	if err != nil || len(node) != 6 || len(proposed) != 16 {
		return nil, false, EARGS
	}
	for attempt := 0; attempt < 4; attempt++ {
		payload, _ := json.Marshal([]any{map[string]any{"a": "uga", "u": user.U, "ua": "^!keys", "v": 1}})
		body, err := m.apiRequest(ctx, payload, "")
		if errors.Is(err, ENOENT) {
			return proposed, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		var response [1]struct {
			AV string `json:"av"`
			V  string `json:"v"`
		}
		if json.Unmarshal(body, &response) != nil || response[0].V == "" {
			return nil, false, EBADRESP
		}
		container, err := base64urldecode(response[0].AV)
		if err != nil {
			return nil, false, EKEY
		}
		fields, err := decodeRepository(m.k, container)
		if err != nil {
			return nil, false, err
		}
		index := map[byte]int{}
		for i, field := range fields {
			index[field.tag] = i
		}
		for _, tag := range []byte{1, 3, 4, 48} {
			if _, ok := index[tag]; !ok {
				return nil, false, EBADRESP
			}
		}
		if !bytes.Equal(fields[index[1]].value, []byte{1}) || !bytes.Equal(fields[index[3]].value, identity) {
			return nil, false, EKEY
		}
		generation := fields[index[4]].value
		shares := fields[index[48]].value
		if len(generation) != 4 || len(shares)%23 != 0 {
			return nil, false, EBADRESP
		}
		for offset := 0; offset < len(shares); offset += 23 {
			if bytes.Equal(shares[offset:offset+6], node) {
				return append([]byte(nil), shares[offset+6:offset+22]...), true, nil
			}
		}
		next := binary.BigEndian.Uint32(generation)
		if next == math.MaxUint32 {
			return nil, false, EKEY
		}
		next++
		binary.BigEndian.PutUint32(generation, next)
		record := append(append(append([]byte(nil), node...), proposed...), byte(1))
		fields[index[48]].value = append(shares, record...)
		container, err = encodeRepository(m.k, fields)
		if err != nil {
			return nil, false, err
		}
		payload, _ = json.Marshal([]any{map[string]any{"a": "upv", "^!keys": []any{base64urlencode(container), response[0].V, next}}})
		body, err = m.apiRequest(ctx, payload, "")
		if errors.Is(err, EEXPIRED) {
			continue
		} // API -8: attribute version conflict
		if err != nil {
			return nil, false, err
		}
		var saved [1]map[string]string
		if json.Unmarshal(body, &saved) != nil || saved[0]["^!keys"] == "" {
			return nil, false, EBADRESP
		}
		return proposed, true, nil
	}
	return nil, false, fmt.Errorf("key repository version conflicts: %w", EAGAIN)
}
