package mega

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"math/rand"
	"reflect"
	"testing"
	"time"
)

func TestSerialize64(t *testing.T) {
	for _, test := range []struct {
		value uint64
		want  []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01, 0x01}},
		{255, []byte{0x01, 0xff}},
		{256, []byte{0x02, 0x00, 0x01}},
		{258, []byte{0x02, 0x02, 0x01}},
		{65535, []byte{0x02, 0xff, 0xff}},
		{65536, []byte{0x03, 0x00, 0x00, 0x01}},
		{1 << 32, []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{1 << 63, []byte{0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}},
		{^uint64(0), []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	} {
		got := serialize64(test.value)
		if !bytes.Equal(test.want, got) {
			t.Errorf("serialize64(%d): want %v, got %v", test.value, test.want, got)
		}
		value, n, err := unserialize64(got)
		if err != nil {
			t.Errorf("unserialize64(%v): %v", got, err)
			continue
		}
		if n != len(got) {
			t.Errorf("unserialize64(%v): consumed %d bytes, want %d", got, n, len(got))
		}
		if value != test.value {
			t.Errorf("unserialize64(%v): want %d, got %d", got, test.value, value)
		}
	}
}

func TestUnserialize64Invalid(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0x01},
		{0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x03, 0x01},
	} {
		if _, _, err := unserialize64(data); err == nil {
			t.Errorf("unserialize64(%v): expected error", data)
		}
	}
}

func TestFingerprintRoundTrip(t *testing.T) {
	var crc [16]byte
	if _, err := rand.Read(crc[:]); err != nil {
		t.Fatalf("rand failed: %v", err)
	}
	const mtime = 1727417600

	fingerprint := serializeFingerprint(crc, mtime)
	gotCRC, gotMtime, err := unserializeFingerprint(fingerprint)
	if err != nil {
		t.Fatalf("unserializeFingerprint(%q): %v", fingerprint, err)
	}
	if gotCRC != crc {
		t.Errorf("CRC mismatch: want %v, got %v", crc, gotCRC)
	}
	if gotMtime != mtime {
		t.Errorf("mtime mismatch: want %d, got %d", mtime, gotMtime)
	}
}

func TestUnserializeFingerprintInvalid(t *testing.T) {
	for _, s := range []string{
		"",
		"____",
		"bm90IGxvbmcgZW5vdWdo", // base64 of 16 bytes only
	} {
		if _, _, err := unserializeFingerprint(s); err == nil {
			t.Errorf("unserializeFingerprint(%q): expected error", s)
		}
	}
}

// fingerprintTestData returns deterministic pseudo random test data of
// the given size.
func fingerprintTestData(size int64) []byte {
	r := rand.New(rand.NewSource(size))
	data := make([]byte, size)
	r.Read(data)
	return data
}

// collectFingerprintCRC feeds data to a fingerprintCRC collector in
// chunks of the given size, in the order given by the piece indexes.
func collectFingerprintCRC(t *testing.T, data []byte, pieceSize int, order []int) [16]byte {
	t.Helper()
	f := newFingerprintCRC(int64(len(data)))
	var next func(idx int)
	next = func(idx int) {
		pos := int64(idx) * int64(pieceSize)
		end := pos + int64(pieceSize)
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		f.write(pos, data[pos:end])
	}
	if order == nil {
		for idx := 0; idx*pieceSize < len(data); idx++ {
			next(idx)
		}
	} else {
		for _, idx := range order {
			next(idx)
		}
	}
	crc, err := f.sum()
	if err != nil {
		t.Fatalf("fingerprint CRC incomplete for size %d: %v", len(data), err)
	}
	return crc
}

func TestFingerprintCRC(t *testing.T) {
	for _, size := range []int64{0, 1, 5, 16, 17, 100, 4096, 8192, 8193, 10000, 1 << 20, 10 << 20} {
		data := fingerprintTestData(size)

		want, err := fingerprintCRCFromReader(bytes.NewReader(data), size)
		if err != nil {
			t.Fatalf("fingerprintCRCFromReader(size %d): %v", size, err)
		}

		// Sequential collection in small pieces must match
		got := collectFingerprintCRC(t, data, 4096, nil)
		if got != want {
			t.Errorf("fingerprint CRC mismatch for size %d: want %v, got %v", size, want, got)
		}

		// Collection in upload chunk sized pieces, in reverse and
		// shuffled order must match too
		if size > 0 {
			pieceSize := 128 * 1024
			if int64(pieceSize) > size {
				pieceSize = int(size)
			}
			pieces := int((size + int64(pieceSize) - 1) / int64(pieceSize))
			order := make([]int, pieces)
			for i := range order {
				order[i] = pieces - 1 - i
			}
			got = collectFingerprintCRC(t, data, pieceSize, order)
			if got != want {
				t.Errorf("fingerprint CRC mismatch (reverse order) for size %d: want %v, got %v", size, want, got)
			}

			r := rand.New(rand.NewSource(size))
			r.Shuffle(pieces, func(i, j int) { order[i], order[j] = order[j], order[i] })
			got = collectFingerprintCRC(t, data, pieceSize, order)
			if got != want {
				t.Errorf("fingerprint CRC mismatch (shuffled order) for size %d: want %v, got %v", size, want, got)
			}
		}
	}
}

// TestFingerprintCRCLanes verifies the CRC lane computation against a
// direct implementation of the algorithm used by the MEGA SDK.
func TestFingerprintCRCLanes(t *testing.T) {
	const k = 1024

	// Small files are covered by 4 contiguous CRC32 lanes
	data := fingerprintTestData(1000)
	crc, err := fingerprintCRCFromReader(bytes.NewReader(data), 1000)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		h := crc32.NewIEEE()
		h.Write(data[i*1000/4 : (i+1)*1000/4])
		var want [4]byte
		binary.BigEndian.PutUint32(want[:], h.Sum32())
		if !bytes.Equal(want[:], crc[i*4:i*4+4]) {
			t.Errorf("lane %d mismatch: want %v, got %v", i, want, crc[i*4:i*4+4])
		}
	}

	// Tiny files are covered verbatim, zero padded
	data = fingerprintTestData(10)
	crc, err = fingerprintCRCFromReader(bytes.NewReader(data), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, crc[:10]) || crc[10] != 0 {
		t.Errorf("tiny file CRC mismatch: want %v padded with zeros, got %v", data, crc)
	}

	// Large files are covered by 4 lanes of 32 sparse 64 byte blocks
	const size = 10 * k * k
	data = fingerprintTestData(size)
	crc, err = fingerprintCRCFromReader(bytes.NewReader(data), size)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		h := crc32.NewIEEE()
		for j := 0; j < fingerprintSparseBlocks; j++ {
			off := fingerprintSparseOffset(size, i*fingerprintSparseBlocks+j)
			h.Write(data[off : off+fingerprintSparseBlock])
		}
		var want [4]byte
		binary.BigEndian.PutUint32(want[:], h.Sum32())
		if !bytes.Equal(want[:], crc[i*4:i*4+4]) {
			t.Errorf("sparse lane %d mismatch: want %v, got %v", i, want, crc[i*4:i*4+4])
		}
	}
}

func TestAttrMapRoundTrip(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand failed: %v", err)
	}

	attrs := map[string]string{
		"n":   "hello.txt",
		"c":   "aVbK3-L0L7AAAAAAAAAAAA",
		"fav": "1",
		"lbl": "3",
	}
	data, err := encryptAttrMap(key, attrs)
	if err != nil {
		t.Fatalf("encryptAttrMap: %v", err)
	}

	got, err := decryptAttrMap(key, data)
	if err != nil {
		t.Fatalf("decryptAttrMap: %v", err)
	}
	if !reflect.DeepEqual(attrs, got) {
		t.Errorf("attribute round trip mismatch: want %v, got %v", attrs, got)
	}

	attr, err := decryptAttr(key, data)
	if err != nil {
		t.Fatalf("decryptAttr: %v", err)
	}
	if attr.Name != "hello.txt" {
		t.Errorf("name mismatch: want %q, got %q", "hello.txt", attr.Name)
	}
	if attr.C != attrs["c"] {
		t.Errorf("fingerprint mismatch: want %q, got %q", attrs["c"], attr.C)
	}

	// encrypting via the FileAttr wrapper must produce the same
	// attribute string as the map based variant
	data2, err := encryptAttr(key, FileAttr{Name: "hello.txt", C: attrs["c"]})
	if err != nil {
		t.Fatalf("encryptAttr: %v", err)
	}
	got2, err := decryptAttrMap(key, data2)
	if err != nil {
		t.Fatalf("decryptAttrMap: %v", err)
	}
	if !reflect.DeepEqual(map[string]string{"n": "hello.txt", "c": attrs["c"]}, got2) {
		t.Errorf("FileAttr round trip mismatch: got %v", got2)
	}
}

func TestParseModificationTime(t *testing.T) {
	if got := parseModificationTime(""); !got.IsZero() {
		t.Errorf("empty fingerprint: want zero time, got %v", got)
	}
	if got := parseModificationTime("invalid"); !got.IsZero() {
		t.Errorf("invalid fingerprint: want zero time, got %v", got)
	}
	mtime := time.Unix(1727417600, 0)
	fingerprint := serializeFingerprint([16]byte{}, 1727417600)
	if got := parseModificationTime(fingerprint); !got.Equal(mtime) {
		t.Errorf("want %v, got %v", mtime, got)
	}
}
