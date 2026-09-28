package mega

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"math/big"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"time"
)

func newHttpClient(timeout time.Duration) *http.Client {
	// TODO: Need to test this out
	// Doesn't seem to work as expected
	c := &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, timeout)
				if err != nil {
					return nil, err
				}
				return c, nil
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}
	return c
}

// bytes_to_a32 converts the byte slice b to uint32 slice considering
// the bytes to be in big endian order.
func bytes_to_a32(b []byte) ([]uint32, error) {
	length := len(b) + 3
	a := make([]uint32, length/4)
	buf := bytes.NewBuffer(b)
	for i := range a {
		err := binary.Read(buf, binary.BigEndian, &a[i])
		if err != nil {
			return nil, err
		}
	}

	return a, nil
}

// a32_to_bytes converts the uint32 slice a to byte slice where each
// uint32 is decoded in big endian order.
func a32_to_bytes(a []uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.Grow(len(a) * 4) // To prevent reallocations in Write
	for _, v := range a {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// base64urlencode encodes byte slice b using base64 url encoding
// without `=` padding.
func base64urlencode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// base64urldecode decodes the byte slice b using unpadded base64 url
// decoding. It also allows the characters from standard base64 to be
// compatible with the mega decoder.
func base64urldecode(s string) ([]byte, error) {
	enc := base64.RawURLEncoding
	// mega base64 decoder accepts the characters from both URLEncoding and StdEncoding
	// though nearly all strings are URL encoded
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return enc.DecodeString(s)
}

// a32_to_base64 converts uint32 slice to base64 encoded byte slice.
func a32_to_base64(a []uint32) (string, error) {
	d, err := a32_to_bytes(a)
	if err != nil {
		return "", err
	}
	return base64urlencode(d), nil
}

// paddnull pads byte slice b such that the size of resulting byte
// slice is a multiple of q.
func paddnull(b []byte, q int) []byte {
	if rem := len(b) % q; rem != 0 {
		l := q - rem

		for i := 0; i < l; i++ {
			b = append(b, 0)
		}
	}

	return b
}

// password_key calculates password hash from the user password.
func password_key(p string) ([]byte, error) {
	a, err := bytes_to_a32(paddnull([]byte(p), 4))
	if err != nil {
		return nil, err
	}

	pkey, err := a32_to_bytes([]uint32{0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56})
	if err != nil {
		return nil, err
	}

	n := (len(a) + 3) / 4

	ciphers := make([]cipher.Block, n)

	for j := 0; j < len(a); j += 4 {
		key := []uint32{0, 0, 0, 0}
		for k := 0; k < 4; k++ {
			if j+k < len(a) {
				key[k] = a[k+j]
			}
		}
		bkey, err := a32_to_bytes(key)
		if err != nil {
			return nil, err
		}
		ciphers[j/4], err = aes.NewCipher(bkey) // Uses AES in ECB mode
		if err != nil {
			return nil, err
		}
	}

	for i := 65536; i > 0; i-- {
		for j := 0; j < n; j++ {
			ciphers[j].Encrypt(pkey, pkey)
		}
	}

	return pkey, nil
}

// stringhash computes generic string hash. Uses k as the key for AES
// cipher.
func stringhash(s string, k []byte) (string, error) {
	a, err := bytes_to_a32(paddnull([]byte(s), 4))
	if err != nil {
		return "", err
	}
	h := []uint32{0, 0, 0, 0}
	for i, v := range a {
		h[i&3] ^= v
	}

	hb, err := a32_to_bytes(h)
	if err != nil {
		return "", err
	}
	cipher, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	for i := 16384; i > 0; i-- {
		cipher.Encrypt(hb, hb)
	}
	ha, err := bytes_to_a32(paddnull(hb, 4))
	if err != nil {
		return "", err
	}

	return a32_to_base64([]uint32{ha[0], ha[2]})
}

// getMPI returns the length encoded Int and the next slice.
func getMPI(b []byte) (*big.Int, []byte) {
	p := new(big.Int)
	plen := (uint64(b[0])*256 + uint64(b[1]) + 7) >> 3
	p.SetBytes(b[2 : plen+2])
	b = b[plen+2:]
	return p, b
}

// getRSAKey decodes the RSA Key from the byte slice b.
func getRSAKey(b []byte) (*big.Int, *big.Int, *big.Int) {
	p, b := getMPI(b)
	q, b := getMPI(b)
	d, _ := getMPI(b)

	return p, q, d
}

// decryptRSA decrypts message m using RSA private key (p,q,d)
func decryptRSA(m, p, q, d *big.Int) []byte {
	n := new(big.Int)
	r := new(big.Int)
	n.Mul(p, q)
	r.Exp(m, d, n)

	return r.Bytes()
}

// blockDecrypt decrypts using the block cipher blk in ECB mode.
func blockDecrypt(blk cipher.Block, dst, src []byte) error {

	if len(src) > len(dst) || len(src)%blk.BlockSize() != 0 {
		return errors.New("Block decryption failed")
	}

	l := len(src) - blk.BlockSize()

	for i := 0; i <= l; i += blk.BlockSize() {
		blk.Decrypt(dst[i:], src[i:])
	}

	return nil
}

// blockEncrypt encrypts using the block cipher blk in ECB mode.
func blockEncrypt(blk cipher.Block, dst, src []byte) error {

	if len(src) > len(dst) || len(src)%blk.BlockSize() != 0 {
		return errors.New("Block encryption failed")
	}

	l := len(src) - blk.BlockSize()

	for i := 0; i <= l; i += blk.BlockSize() {
		blk.Encrypt(dst[i:], src[i:])
	}

	return nil
}

// decryptSeessionId decrypts the session id using the given private
// key.
func decryptSessionId(privk string, csid string, mk []byte) (string, error) {

	block, err := aes.NewCipher(mk)
	if err != nil {
		return "", err
	}
	pk, err := base64urldecode(privk)
	if err != nil {
		return "", err
	}
	err = blockDecrypt(block, pk, pk)
	if err != nil {
		return "", err
	}

	c, err := base64urldecode(csid)
	if err != nil {
		return "", err
	}

	m, _ := getMPI(c)

	p, q, d := getRSAKey(pk)
	r := decryptRSA(m, p, q, d)

	return base64urlencode(r[:43]), nil

}

// chunkSize describes a size and position of chunk
type chunkSize struct {
	position int64
	size     int
}

func getChunkSizes(size int64) (chunks []chunkSize) {
	p := int64(0)
	for i := 1; size > 0; i++ {
		var chunk int
		if i <= 8 {
			chunk = i * 131072
		} else {
			chunk = 1048576
		}
		if size < int64(chunk) {
			chunk = int(size)
		}
		chunks = append(chunks, chunkSize{position: p, size: chunk})
		p += int64(chunk)
		size -= int64(chunk)
	}
	return chunks
}

var attrMatch = regexp.MustCompile(`{".*"}`)

// decryptAttrMap decrypts and parses the encrypted attribute string
// of a node, returning the decrypted attribute map. Attributes that
// are unknown to this library are preserved so that they can be
// rewritten unmodified when the attributes of a node are updated.
func decryptAttrMap(key []byte, data string) (map[string]string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv, err := a32_to_bytes([]uint32{0, 0, 0, 0})
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	ddata, err := base64urldecode(data)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(ddata))
	mode.CryptBlocks(buf, ddata)

	if string(buf[:4]) != "MEGA" {
		return nil, errors.New("invalid attribute magic")
	}
	str := strings.TrimRight(string(buf[4:]), "\x00")
	trimmed := attrMatch.FindString(str)
	if trimmed != "" {
		str = trimmed
	}
	attrs := make(map[string]string)
	err = json.Unmarshal([]byte(str), &attrs)
	if err != nil {
		return nil, err
	}
	return attrs, nil
}

func decryptAttr(key []byte, data string) (attr FileAttr, err error) {
	attrs, err := decryptAttrMap(key, data)
	if err != nil {
		return attr, err
	}
	attr.Name = attrs["n"]
	attr.C = attrs["c"]
	return attr, nil
}

// encryptAttrMap encrypts a node attribute map in the wire format
// used by the MEGA API: a "MEGA" magic prefix followed by the JSON
// encoded attributes, zero padded to a multiple of the AES block size
// and encrypted with AES-CBC using a zero IV.
func encryptAttrMap(key []byte, attrs map[string]string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return "", err
	}
	attrib := []byte("MEGA")
	attrib = append(attrib, data...)
	attrib = paddnull(attrib, 16)

	iv, err := a32_to_bytes([]uint32{0, 0, 0, 0})
	if err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(attrib, attrib)

	return base64urlencode(attrib), nil
}

func encryptAttr(key []byte, attr FileAttr) (b string, err error) {
	attrs := map[string]string{"n": attr.Name}
	if attr.C != "" {
		attrs["c"] = attr.C
	}
	return encryptAttrMap(key, attrs)
}

// serialize64 encodes v in the format used by the MEGA SDK for the
// modification time stored in file fingerprints: one length byte
// (0-8) followed by that many bytes of the value in little endian
// order.
func serialize64(v uint64) []byte {
	payload := make([]byte, 0, 8)
	for v > 0 {
		payload = append(payload, byte(v))
		v >>= 8
	}
	return append([]byte{byte(len(payload))}, payload...)
}

// unserialize64 decodes a value encoded with serialize64. It returns
// the value and the number of bytes consumed.
func unserialize64(b []byte) (uint64, int, error) {
	if len(b) == 0 || int(b[0]) > 8 || int(b[0])+1 > len(b) {
		return 0, 0, errors.New("invalid serialized value")
	}
	n := int(b[0])
	var v uint64
	for i := n; i > 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v, n + 1, nil
}

// The fingerprint CRC covers the full content of files up to this
// size. Larger files are sampled with sparse blocks.
const fingerprintMaxFull = 8192

const (
	// Size of the fingerprint CRC (4 CRC32 lanes of 4 bytes each).
	fingerprintCRCSize = 16
	// Number of sparse blocks read per CRC lane for large files.
	fingerprintSparseBlocks = 32
	// Size of each sparse block in bytes.
	fingerprintSparseBlock = 64
)

// fingerprintSparseOffset returns the file offset of the sparse
// fingerprint block with index idx (0..4*fingerprintSparseBlocks-1)
// in a file of size sz. It mirrors the offset computation of the
// official MEGA SDK.
func fingerprintSparseOffset(sz int64, idx int) int64 {
	denom := int64(4*fingerprintSparseBlocks - 1)
	off := (sz - fingerprintSparseBlock) * int64(idx) / denom
	if off > sz-fingerprintSparseBlock {
		off = sz - fingerprintSparseBlock
	}
	return off
}

// fingerprintCRC computes the 16 byte CRC part of a MEGA file
// fingerprint. The required byte ranges are collected from write()
// calls, which may arrive at arbitrary offsets in arbitrary order
// (and may partially cover the required blocks), and the CRC is
// assembled in sum(). Once sum() has been called the collector must
// not be used anymore.
type fingerprintCRC struct {
	size    int64
	buf     []byte   // content of files up to fingerprintMaxFull bytes
	offsets []int64  // required sparse block offsets (ascending)
	blocks  [][]byte // sparse block buffers, aligned with offsets
	filled  []int    // number of bytes collected per sparse block
}

func newFingerprintCRC(size int64) *fingerprintCRC {
	f := &fingerprintCRC{size: size}
	if size <= fingerprintMaxFull {
		f.buf = make([]byte, size)
	} else {
		f.offsets = make([]int64, 4*fingerprintSparseBlocks)
		f.blocks = make([][]byte, 4*fingerprintSparseBlocks)
		f.filled = make([]int, 4*fingerprintSparseBlocks)
		for i := range f.offsets {
			f.offsets[i] = fingerprintSparseOffset(size, i)
		}
	}
	return f
}

// write records the bytes of data located at file offset pos.
func (f *fingerprintCRC) write(pos int64, data []byte) {
	if len(data) == 0 {
		return
	}
	if f.buf != nil {
		start := pos
		if start < 0 {
			start = 0
		}
		end := pos + int64(len(data))
		if end > f.size {
			end = f.size
		}
		if start < end {
			copy(f.buf[start:end], data[start-pos:end-pos])
		}
		return
	}
	// Sparse mode: record the overlap of [pos, pos+len(data)) with
	// each required block. Blocks may be covered by several write
	// calls, so partial fills are accumulated.
	end := pos + int64(len(data))
	for i := range f.offsets {
		bStart, bEnd := f.offsets[i], f.offsets[i]+int64(fingerprintSparseBlock)
		s, e := bStart, bEnd
		if s < pos {
			s = pos
		}
		if e > end {
			e = end
		}
		if s >= e {
			continue
		}
		if f.blocks[i] == nil {
			f.blocks[i] = make([]byte, fingerprintSparseBlock)
		}
		copy(f.blocks[i][s-bStart:e-bStart], data[s-pos:e-pos])
		f.filled[i] += int(e - s)
	}
}

// sum assembles the CRC lanes and returns the fingerprint CRC. It
// fails if the required byte ranges have not been collected.
func (f *fingerprintCRC) sum() ([16]byte, error) {
	var crc [16]byte
	if f.buf != nil {
		if f.size <= fingerprintCRCSize {
			// Tiny files: the CRC is the file content itself,
			// zero padded.
			copy(crc[:], f.buf)
			return crc, nil
		}
		for i := 0; i < 4; i++ {
			h := crc32.NewIEEE()
			begin := f.size * int64(i) / 4
			end := f.size * int64(i+1) / 4
			h.Write(f.buf[begin:end])
			binary.BigEndian.PutUint32(crc[i*4:], h.Sum32())
		}
		return crc, nil
	}
	for i := range f.blocks {
		if f.blocks[i] == nil || f.filled[i] != fingerprintSparseBlock {
			return crc, errors.New("fingerprint data incomplete")
		}
	}
	for i := 0; i < 4; i++ {
		h := crc32.NewIEEE()
		for j := 0; j < fingerprintSparseBlocks; j++ {
			h.Write(f.blocks[i*fingerprintSparseBlocks+j])
		}
		binary.BigEndian.PutUint32(crc[i*4:], h.Sum32())
	}
	return crc, nil
}

// fingerprintCRCFromReader computes the fingerprint CRC of a file of
// the given size by reading only the byte ranges required by the CRC
// algorithm from r.
func fingerprintCRCFromReader(r io.ReaderAt, size int64) ([16]byte, error) {
	var crc [16]byte
	if size < 0 {
		return crc, errors.New("invalid file size")
	}
	f := newFingerprintCRC(size)
	if f.buf != nil {
		if len(f.buf) > 0 {
			if _, err := r.ReadAt(f.buf, 0); err != nil && err != io.EOF {
				return crc, err
			}
		}
	} else {
		for i, off := range f.offsets {
			f.blocks[i] = make([]byte, fingerprintSparseBlock)
			if _, err := r.ReadAt(f.blocks[i], off); err != nil && err != io.EOF {
				return crc, err
			}
			f.filled[i] = fingerprintSparseBlock
		}
	}
	return f.sum()
}

// serializeFingerprint serializes a fingerprint CRC and a modification
// time (in seconds) into the base64 encoded value of the node
// fingerprint attribute ("c").
func serializeFingerprint(crc [16]byte, mtime uint64) string {
	buf := make([]byte, 0, fingerprintCRCSize+9)
	buf = append(buf, crc[:]...)
	buf = append(buf, serialize64(mtime)...)
	return base64urlencode(buf)
}

// unserializeFingerprint parses the value of a node fingerprint
// attribute ("c") into its CRC part and modification time in seconds.
func unserializeFingerprint(s string) (crc [16]byte, mtime uint64, err error) {
	data, err := base64urldecode(s)
	if err != nil {
		return crc, 0, err
	}
	if len(data) < fingerprintCRCSize+1 {
		return crc, 0, errors.New("fingerprint too short")
	}
	copy(crc[:], data[:fingerprintCRCSize])
	mtime, _, err = unserialize64(data[fingerprintCRCSize:])
	if err != nil {
		return [16]byte{}, 0, err
	}
	return crc, mtime, nil
}

func randString(l int) (string, error) {
	encoding := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+"
	b := make([]byte, l)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	enc := base64.NewEncoding(encoding)
	d := make([]byte, enc.EncodedLen(len(b)))
	enc.Encode(d, b)
	d = d[:l]
	return strings.NewReplacer("/", "A", "+", "B").Replace(string(d)), nil
}

// halfCPUCores returns half the number of logical CPU cores available.
// The return value is always at least 1, even if the system reports fewer than 2 cores.
func halfCPUCores() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	return n
}
