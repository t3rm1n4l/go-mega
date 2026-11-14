package mega

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const numReplications = 262144
const tokenSlotSize = 48

// Base64ToBytes decodes a base64url-encoded string to a byte slice
func Base64ToBytes(s string) ([]byte, error) {
	if strings.ContainsAny(s, "+/=") {
		return nil, fmt.Errorf("invalid base64url format")
	}

	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// PadToAESBlockSize ensures a byte slice is padded to AES block size (16 bytes)
func PadToAESBlockSize(data []byte) []byte {
	if rem := len(data) % 16; rem != 0 {
		padding := make([]byte, 16-rem)
		return append(data, padding...)
	}
	return data
}

// parseHashcash parses the X-Hashcash header value and returns the components
func parseHashcash(header string) (easiness int, token string, valid bool) {
	parts := strings.Split(header, ":")
	if len(parts) != 4 {
		return 0, "", false
	}

	v, err := strconv.Atoi(parts[0])
	if err != nil || v != 1 {
		return 0, "", false
	}

	e, err := strconv.Atoi(parts[1])
	if err != nil || e < 0 || e > 255 {
		return 0, "", false
	}

	return e, parts[3], true
}

func gencashRange(ctx context.Context, token string, easiness, start, step int) string {
	if ctx.Err() != nil {
		return ""
	}
	threshold := uint32((((easiness & 63) << 1) + 1) << ((easiness>>6)*7 + 3))
	tokenBytes, err := Base64ToBytes(token)
	if err != nil {
		return ""
	}
	tokenBytes = PadToAESBlockSize(tokenBytes)
	buffer := make([]byte, 4+numReplications*tokenSlotSize)
	for i := 0; i < numReplications; i++ {
		copy(buffer[4+i*tokenSlotSize:], tokenBytes)
	}
	for nonce := uint64(start) + 1; nonce < 1<<32; nonce += uint64(step) {
		if ctx.Err() != nil {
			return ""
		}
		binary.LittleEndian.PutUint32(buffer[:4], uint32(nonce))
		hash := sha256.Sum256(buffer)
		if binary.BigEndian.Uint32(hash[:4]) <= threshold {
			return base64.RawURLEncoding.EncodeToString(buffer[:4])
		}
	}
	return ""
}

func solveHashCashChallengeContext(parent context.Context, token string, easiness int, timeout time.Duration, workers int) (string, error) {
	if _, err := Base64ToBytes(token); err != nil {
		return "", EARGS
	}
	if workers < 1 || workers > 32 || easiness < 0 || easiness > 255 {
		return "", EARGS
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()

	resultChan := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			result := gencashRange(ctx, token, easiness, start, workers)
			if result != "" {
				select {
				case resultChan <- result:
				case <-ctx.Done():
				}
			}
		}(i)
	}

	select {
	case result := <-resultChan:
		return result, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
