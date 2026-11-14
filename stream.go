package mega

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"io"
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

// OpenStream returns an io.ReadCloser for the specified byte range [start, end] (inclusive)
// without saving any data to disk. The stream is decrypted on the fly with AES-CTR.
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

	alignedStart := (start / 16) * 16
	skip := start - alignedStart
	contentLen := end - start + 1

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
