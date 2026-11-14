package mega

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
)

func TestStreamRangeFull(t *testing.T) {
	data := []byte("Hello Mega Streaming World! This is a test of AES-CTR on the fly streaming.")
	m, link, _ := fileFixture(t, data, false)

	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	reader, size, err := res.OpenStream(context.Background(), fixtureHandle, 0, int64(len(data)-1))
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer reader.Close()

	if size != int64(len(data)) {
		t.Fatalf("size mismatch: got %d, want %d", size, len(data))
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Fatalf("content mismatch:\ngot:  %q\nwant: %q", string(got), string(data))
	}
}

func TestStreamRangeArbitrarySlices(t *testing.T) {
	// 500 bytes of non-repeating data
	data := make([]byte, 500)
	for i := range data {
		data[i] = byte(i % 256)
	}

	m, link, _ := fileFixture(t, data, false)
	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	testCases := []struct {
		name  string
		start int64
		end   int64
	}{
		{"First 16 bytes (aligned)", 0, 15},
		{"Second block (aligned)", 16, 31},
		{"Single byte at offset 0", 0, 0},
		{"Single byte at offset 17 (unaligned)", 17, 17},
		{"Unaligned start across block boundary", 5, 25},
		{"Deep unaligned slice", 33, 199},
		{"Last byte", int64(len(data) - 1), int64(len(data) - 1)},
		{"Full range via OpenStream", 0, int64(len(data) - 1)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader, size, err := res.OpenStream(context.Background(), fixtureHandle, tc.start, tc.end)
			if err != nil {
				t.Fatalf("OpenStream(%d, %d) failed: %v", tc.start, tc.end, err)
			}
			defer reader.Close()

			expectedLen := tc.end - tc.start + 1
			if size != expectedLen {
				t.Fatalf("size mismatch: got %d, want %d", size, expectedLen)
			}

			got, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			want := data[tc.start : tc.end+1]
			if !bytes.Equal(got, want) {
				t.Fatalf("slice mismatch for [%d:%d]:\ngot len %d, want len %d", tc.start, tc.end, len(got), len(want))
			}
		})
	}
}

func TestStreamRangeBounds(t *testing.T) {
	data := []byte("boundary check data")
	m, link, _ := fileFixture(t, data, false)

	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	// Negative start
	if _, _, err := res.OpenStream(context.Background(), fixtureHandle, -1, 5); err == nil {
		t.Error("expected error for negative start")
	}

	// Start > End
	if _, _, err := res.OpenStream(context.Background(), fixtureHandle, 10, 5); err == nil {
		t.Error("expected error for start > end")
	}

	// End >= size
	if _, _, err := res.OpenStream(context.Background(), fixtureHandle, 0, int64(len(data))); err == nil {
		t.Error("expected error for end >= size")
	}

	// Non-existent handle
	if _, _, err := res.OpenStream(context.Background(), "NONEXIST", 0, 5); err == nil {
		t.Error("expected error for unknown handle")
	}
}

func TestStreamPipelinedMultiSpan(t *testing.T) {
	// 5 MiB of pseudorandom data to cross multiple 2 MiB pipeline spans
	data := make([]byte, 5*1024*1024)
	for i := range data {
		data[i] = byte((i * 31) % 256)
	}

	m, link, _ := fileFixture(t, data, false)
	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}

	reader, size, err := res.OpenStream(context.Background(), fixtureHandle, 0, int64(len(data)-1))
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	defer reader.Close()

	if size != int64(len(data)) {
		t.Fatalf("size mismatch: got %d, want %d", size, len(data))
	}

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(got) != len(data) {
		t.Fatalf("len mismatch: got %d, want %d", len(got), len(data))
	}

	if !bytes.Equal(got, data) {
		t.Fatal("pipelined multi-span content mismatch against source data")
	}
}

func TestStreamUnalignedAcrossSpans(t *testing.T) {
	data := make([]byte, 5*1024*1024+123)
	for i := range data {
		data[i] = byte((i * 17) % 251)
	}
	m, link, _ := fileFixture(t, data, false)
	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	start, end := int64(300007), int64(len(data)-4001)
	reader, size, err := res.OpenStream(context.Background(), fixtureHandle, start, end)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if size != end-start+1 || !bytes.Equal(got, data[start:end+1]) {
		t.Fatalf("mismatch: size %d len %d", size, len(got))
	}
}

func TestStreamEarlyClose(t *testing.T) {
	data := make([]byte, 6*1024*1024)
	m, link, _ := fileFixture(t, data, false)
	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	reader, _, err := res.OpenStream(context.Background(), fixtureHandle, 0, int64(len(data)-1))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadFull(reader, make([]byte, 1000))
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenStreamAsksMegaOncePerFile(t *testing.T) {
	data := make([]byte, 3<<20)
	for i := range data {
		data[i] = byte(i % 253)
	}
	m, link, _ := fileFixture(t, data, false)
	res, err := m.ResolvePublic(context.Background(), link)
	if err != nil {
		t.Fatal(err)
	}
	before := m.sn // every API call advances the sequence number

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := int64(i) * 100000
			reader, _, err := res.OpenStream(context.Background(), fixtureHandle, start, start+200000)
			if err != nil {
				t.Error(err)
				return
			}
			defer reader.Close()
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, data[start:start+200001]) {
				t.Errorf("range %d mismatch: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if calls := m.sn - before; calls != 1 {
		t.Fatalf("8 concurrent streams made %d API calls, want 1", calls)
	}
	reader, _, err := res.OpenStream(context.Background(), fixtureHandle, 0, 9)
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	if calls := m.sn - before; calls != 1 {
		t.Fatalf("a later stream made another API call (%d total)", calls)
	}
}
