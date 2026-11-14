package mega

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type decryptReader struct {
	body      io.ReadCloser
	stream    cipher.Stream
	cancel    context.CancelFunc
	skip      int64
	remaining int64
}

func (r *decryptReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	if r.skip > 0 {
		scratch := make([]byte, r.skip)
		if _, err := io.ReadFull(r.body, scratch); err != nil {
			return 0, err
		}
		r.stream.XORKeyStream(scratch, scratch)
		r.skip = 0
	}
	n, err := r.body.Read(p)
	if n > 0 {
		r.stream.XORKeyStream(p[:n], p[:n])
		r.remaining -= int64(n)
		if r.remaining <= 0 && err == nil {
			err = io.EOF
		}
	}
	return n, err
}

func (r *decryptReader) Close() error {
	var err error
	if r.body != nil {
		err = r.body.Close()
	}
	if r.cancel != nil {
		r.cancel()
	}
	return err
}

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

const (
	pipelineSpanSize     = 2 * 1024 * 1024 // 2 MiB spans for parallel pre-fetching
	minPipelineThreshold = 2 * 1024 * 1024 // Only pipeline for ranges > 2 MiB
)

type spanItem struct {
	index int
	data  []byte
	len   int
	err   error
}

type pipelinedReader struct {
	ctx       context.Context
	cancel    context.CancelFunc
	inOrder   chan spanItem
	curBuf    []byte
	curOffset int
	curLen    int
	closed    atomic.Bool
	spanPool  *sync.Pool
}

func (pr *pipelinedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for pr.curOffset >= pr.curLen {
		if pr.curBuf != nil {
			pr.spanPool.Put(pr.curBuf)
			pr.curBuf = nil
		}

		item, ok := <-pr.inOrder
		if !ok {
			return 0, io.EOF
		}
		if item.err != nil {
			if item.data != nil {
				pr.spanPool.Put(item.data)
			}
			return 0, item.err
		}

		pr.curBuf = item.data
		pr.curOffset = 0
		pr.curLen = item.len
	}

	n := copy(p, pr.curBuf[pr.curOffset:pr.curLen])
	pr.curOffset += n
	return n, nil
}

func (pr *pipelinedReader) Close() error {
	if pr.closed.CompareAndSwap(false, true) {
		pr.cancel()
		if pr.curBuf != nil {
			pr.spanPool.Put(pr.curBuf)
			pr.curBuf = nil
		}
		// Drain remaining buffered spans to return memory to pool
		go func() {
			for item := range pr.inOrder {
				if item.data != nil {
					pr.spanPool.Put(item.data)
				}
			}
		}()
	}
	return nil
}

func (r *PublicResource) fetchSpan(ctx context.Context, d *Download, node *Node, start, end int64, out []byte) error {
	alignedStart := (start / 16) * 16
	skip := start - alignedStart
	contentLen := end - start + 1

	ctr_iv, err := bytes_to_a32(node.meta.iv)
	if err != nil {
		return err
	}
	blockIndex := uint64(alignedStart / 16)
	ctr_iv[2] = uint32(blockIndex / 0x1000000000)
	ctr_iv[3] = uint32(blockIndex & 0xFFFFFFFF)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return err
	}
	ctrStream := cipher.NewCTR(d.aes_block, bctr_iv)

	base := d.url()
	timeout := r.client.config.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	var lastErr error
	for attempt := 0; attempt <= r.client.retries; attempt++ {
		if attempt > 0 {
			if err := waitRetry(ctx, attempt); err != nil {
				return err
			}
		}

		resp, cancel, err := r.client.openTransfer(ctx, rangeURL(base, alignedStart, end+1))
		if errors.Is(err, EEXPIRED) {
			if base, err = d.refreshURL(ctx, base); err == nil {
				resp, cancel, err = r.client.openTransfer(ctx, rangeURL(base, alignedStart, end+1))
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}

		body := stallReader{resp.Body, time.AfterFunc(timeout, cancel), timeout}

		if skip > 0 {
			scratch := make([]byte, skip)
			if _, err := io.ReadFull(body, scratch); err != nil {
				body.timer.Stop()
				cancel()
				_ = resp.Body.Close()
				lastErr = err
				continue
			}
			ctrStream.XORKeyStream(scratch, scratch)
		}

		_, err = io.ReadFull(body, out[:contentLen])
		body.timer.Stop()
		cancel()
		_ = resp.Body.Close()

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			lastErr = err
			continue
		}

		ctrStream.XORKeyStream(out[:contentLen], out[:contentLen])
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("span fetch failed after retries")
}

func (r *PublicResource) openPipelinedStream(ctx context.Context, d *Download, node *Node, start, end int64) (io.ReadCloser, int64, error) {
	contentLen := end - start + 1
	workers := r.client.dl_workers
	if workers < 1 {
		workers = 4
	}

	type spanJob struct {
		index int
		start int64
		end   int64
	}

	var jobs []spanJob
	cur := start
	idx := 0
	for cur <= end {
		spanEnd := cur + int64(pipelineSpanSize) - 1
		if spanEnd > end {
			spanEnd = end
		}
		jobs = append(jobs, spanJob{index: idx, start: cur, end: spanEnd})
		cur = spanEnd + 1
		idx++
	}

	spanPool := &sync.Pool{
		New: func() any {
			return make([]byte, pipelineSpanSize)
		},
	}

	childCtx, cancel := context.WithCancel(ctx)
	inOrder := make(chan spanItem, workers+2)

	pr := &pipelinedReader{
		ctx:      childCtx,
		cancel:   cancel,
		inOrder:  inOrder,
		spanPool: spanPool,
	}

	go func() {
		defer close(inOrder)

		numJobs := len(jobs)
		if numJobs == 0 {
			return
		}

		jobCh := make(chan spanJob, numJobs)
		for _, j := range jobs {
			jobCh <- j
		}
		close(jobCh)

		rawResults := make(chan spanItem, workers+2)

		var wg sync.WaitGroup
		actualWorkers := workers
		if actualWorkers > numJobs {
			actualWorkers = numJobs
		}

		for w := 0; w < actualWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range jobCh {
					if childCtx.Err() != nil {
						return
					}
					buf := spanPool.Get().([]byte)
					spanLen := int(j.end - j.start + 1)
					err := r.fetchSpan(childCtx, d, node, j.start, j.end, buf)
					if err != nil {
						if childCtx.Err() == nil {
							select {
							case rawResults <- spanItem{index: j.index, data: buf, len: spanLen, err: err}:
							case <-childCtx.Done():
							}
						} else {
							spanPool.Put(buf)
						}
						return
					}
					select {
					case rawResults <- spanItem{index: j.index, data: buf, len: spanLen, err: nil}:
					case <-childCtx.Done():
						spanPool.Put(buf)
						return
					}
				}
			}()
		}

		go func() {
			wg.Wait()
			close(rawResults)
		}()

		pending := make(map[int]spanItem)
		nextSpan := 0

		for {
			if nextSpan >= numJobs {
				return
			}

			if item, exists := pending[nextSpan]; exists {
				delete(pending, nextSpan)
				select {
				case inOrder <- item:
					if item.err != nil {
						cancel()
						return
					}
					nextSpan++
					continue
				case <-childCtx.Done():
					return
				}
			}

			item, ok := <-rawResults
			if !ok {
				for nextSpan < numJobs {
					if it, ex := pending[nextSpan]; ex {
						delete(pending, nextSpan)
						select {
						case inOrder <- it:
							if it.err != nil {
								cancel()
								return
							}
						case <-childCtx.Done():
							return
						}
					}
					nextSpan++
				}
				return
			}

			if item.index == nextSpan {
				select {
				case inOrder <- item:
					if item.err != nil {
						cancel()
						return
					}
					nextSpan++
				case <-childCtx.Done():
					return
				}
			} else {
				pending[item.index] = item
			}
		}
	}()

	return pr, contentLen, nil
}

// OpenStream returns an io.ReadCloser for the specified byte range [start, end] (inclusive)
// without saving any data to disk. The stream is decrypted on the fly with AES-CTR.
// For ranges larger than 2 MiB, transfers are automatically pipelined across parallel connections.
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

	contentLen := end - start + 1

	// For ranges larger than threshold, use pipelined multi-connection streaming
	if contentLen > minPipelineThreshold {
		return r.openPipelinedStream(ctx, d, node, start, end)
	}

	// For smaller ranges, direct single connection is lowest latency
	alignedStart := (start / 16) * 16
	skip := start - alignedStart

	ctr_iv, err := bytes_to_a32(node.meta.iv)
	if err != nil {
		return nil, 0, err
	}
	blockIndex := uint64(alignedStart / 16)
	ctr_iv[2] = uint32(blockIndex / 0x1000000000)
	ctr_iv[3] = uint32(blockIndex & 0xFFFFFFFF)
	bctr_iv, err := a32_to_bytes(ctr_iv)
	if err != nil {
		return nil, 0, err
	}
	ctrStream := cipher.NewCTR(d.aes_block, bctr_iv)

	base := d.url()
	resp, cancel, err := r.client.openTransfer(ctx, rangeURL(base, alignedStart, end+1))
	if errors.Is(err, EEXPIRED) {
		if base, err = d.refreshURL(ctx, base); err == nil {
			resp, cancel, err = r.client.openTransfer(ctx, rangeURL(base, alignedStart, end+1))
		}
	}
	if err != nil {
		return nil, 0, err
	}

	dr := &decryptReader{
		body:      resp.Body,
		stream:    ctrStream,
		cancel:    cancel,
		skip:      skip,
		remaining: contentLen,
	}
	return dr, contentLen, nil
}

// DownloadReader returns an io.ReadCloser for the full file content without saving to disk.
func (r *PublicResource) DownloadReader(ctx context.Context, handle string) (io.ReadCloser, int64, error) {
	node := r.findNode(handle)
	if node == nil || node.ntype != FILE {
		return nil, 0, ENOENT
	}
	if node.size == 0 {
		return io.NopCloser(bytes.NewReader(nil)), 0, nil
	}
	return r.OpenStream(ctx, handle, 0, node.size-1)
}
