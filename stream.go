package mega

import (
	"bytes"
	"context"
	"io"
	"sort"
	"sync"
)

// streamBufferCap bounds decrypted-but-unread bytes held for one stream.
const streamBufferCap = 8 << 20

// LookupEntry returns entry metadata for the given handle.
func (r *PublicResource) LookupEntry(handle string) (Entry, bool) {
	for _, entry := range r.entries {
		if entry.Handle == handle {
			return entry, true
		}
	}
	return Entry{}, false
}

func (r *PublicResource) findNode(handle string) *Node {
	for i, entry := range r.entries {
		if entry.Handle == handle {
			return r.nodes[i]
		}
	}
	return nil
}

// OpenStream returns a reader for the inclusive byte range [start, end] without
// touching disk. It runs on the same span engine as file downloads (parallel
// GETs, retry/resume, stall timeout, URL refresh); chunks are decrypted by the
// engine and handed to the reader in file order.
func (r *PublicResource) OpenStream(ctx context.Context, handle string, start, end int64) (io.ReadCloser, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	node := r.findNode(handle)
	if node == nil || node.ntype != FILE {
		return nil, 0, ENOENT
	}
	if node.size == 0 {
		if start == 0 && end == 0 {
			return io.NopCloser(bytes.NewReader(nil)), 0, nil
		}
		return nil, 0, EARGS
	}
	if start < 0 || start > end || end >= node.size {
		return nil, 0, EARGS
	}

	d, err := r.client.NewDownloadContext(ctx, node)
	if err != nil {
		return nil, 0, err
	}

	// Chunks covering [start, end].
	chunks := d.chunks
	first := sort.Search(len(chunks), func(i int) bool { return chunks[i].position+int64(chunks[i].size) > start })
	last := sort.Search(len(chunks), func(i int) bool { return chunks[i].position > end }) - 1
	work := spans(chunks[first:last+1], r.client.dl_workers)
	for i := range work {
		work[i].first += first
		work[i].last += first
	}

	child, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	var (
		mu       sync.Mutex
		cond     = sync.NewCond(&mu)
		pending  = map[int][]byte{}
		buffered int
		next     = first
		failed   error
	)
	stop := context.AfterFunc(child, func() { mu.Lock(); cond.Broadcast(); mu.Unlock() })

	emit := func(id int, data []byte) error {
		mu.Lock()
		defer mu.Unlock()
		// The chunk the reader is waiting for is never held back.
		for buffered >= streamBufferCap && id != next && child.Err() == nil {
			cond.Wait()
		}
		if err := child.Err(); err != nil {
			return err
		}
		pending[id] = append([]byte(nil), data...) // engine reuses data
		buffered += len(data)
		cond.Broadcast()
		return nil
	}

	go func() {
		err := runChunks(child, len(work), r.client.dl_workers, func(ctx context.Context, i int) error {
			return d.downloadSpan(ctx, work[i], make([]byte, 1<<20), make([]byte, macScratch), emit)
		})
		mu.Lock()
		failed = err
		cond.Broadcast()
		mu.Unlock()
	}()

	go func() {
		defer stop()
		for id := first; id <= last; id++ {
			mu.Lock()
			for pending[id] == nil && failed == nil {
				cond.Wait()
			}
			data, ok := pending[id]
			if !ok {
				err := failed
				mu.Unlock()
				cancel()
				pw.CloseWithError(err)
				return
			}
			delete(pending, id)
			buffered -= len(data)
			next = id + 1
			cond.Broadcast()
			mu.Unlock()

			pos := chunks[id].position
			lo := max(start-pos, 0)
			hi := min(end+1-pos, int64(len(data)))
			if _, err := pw.Write(data[lo:hi]); err != nil {
				cancel()
				return
			}
		}
		cancel()
		pw.Close()
	}()

	return &streamReader{PipeReader: pr, cancel: cancel}, end - start + 1, nil
}

type streamReader struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (s *streamReader) Close() error {
	s.cancel()
	return s.PipeReader.Close()
}
