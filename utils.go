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
	"math/big"
	"net"
	"net/http"
	"regexp"
	"runtime"
	"strings"
	"sync"
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

func decryptAttr(key []byte, data string) (attr FileAttr, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return attr, err
	}
	iv, err := a32_to_bytes([]uint32{0, 0, 0, 0})
	if err != nil {
		return attr, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	buf := make([]byte, len(data))
	ddata, err := base64urldecode(data)
	if err != nil {
		return attr, err
	}
	mode.CryptBlocks(buf, ddata)

	if string(buf[:4]) == "MEGA" {
		str := strings.TrimRight(string(buf[4:]), "\x00")
		trimmed := attrMatch.FindString(str)
		if trimmed != "" {
			str = trimmed
		}
		err = json.Unmarshal([]byte(str), &attr)
	}
	return attr, err
}

func encryptAttr(key []byte, attr FileAttr) (b string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(attr)
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

	b = base64urlencode(attrib)
	return b, nil
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

// --- MEGA file fingerprint ("c" node attribute) ---
//
// Official MEGA clients store a "quick fingerprint" on every file, in the
// node's "c" attribute: 4 big-endian CRC32 words (16 bytes) computed over a
// handful of sampled regions of the file, immediately followed by a
// variable-length serialized last-modification time. This is documented
// (informally) by other MEGA client implementations, e.g.:
//   - https://github.com/meganz/sdk/blob/master/src/filefingerprint.cpp
//   - https://github.com/gpailler/MegaApiClient/blob/master/MegaApiClient/Serialization/Attributes.cs
//
// The functions below (de)serialize this attribute, and fingerprintAccumulator
// computes the CRC32 words incrementally from the plaintext chunk stream
// that Upload.UploadChunk already sees - without ever seeking or re-reading
// the original source. This means it works for any source (a local file, a
// crypt-wrapped remote, another cloud remote, stdin, ...), unlike an
// implementation based on re-opening a local path.

const (
	maxFull        = 8192 // files up to this size are read in full
	crcArrayLength = 4    // number of CRC32 words in a fingerprint
	crcSize        = 4 * crcArrayLength
	fpMaxLen       = crcSize + 1 + 8 // crc words + 1 length byte + up to 8 mtime bytes
)

// serializeFingerprint builds the base64-encoded "c" attribute value from 4
// CRC32 words and a unix modification time.
func serializeFingerprint(crc []uint32, mtime int64) string {
	buf := make([]byte, crcSize)
	for i := 0; i < crcArrayLength && i < len(crc); i++ {
		binary.BigEndian.PutUint32(buf[i*4:], crc[i])
	}
	dateBytes := serializeInt64(mtime)
	out := make([]byte, 0, fpMaxLen)
	out = append(out, buf...)
	out = append(out, dateBytes...)
	return base64.StdEncoding.EncodeToString(out)
}

// deserializeFingerprint parses a "c" attribute value, returning the raw
// (still-encoded) fingerprint string unchanged - so it can be round-tripped
// through Rename without altering it - and the modification time it
// encodes, if any. If fp is empty or malformed, it returns ("", zero Time),
// and callers should fall back to the node's ordinary timestamp.
func deserializeFingerprint(fp string) (raw string, mtime time.Time) {
	if fp == "" {
		return "", time.Time{}
	}
	data, err := base64.StdEncoding.DecodeString(fp)
	if err != nil || len(data) < crcSize+1 {
		return fp, time.Time{}
	}
	t, err := deserializeInt64(data[crcSize:])
	if err != nil {
		return fp, time.Time{}
	}
	return fp, time.Unix(t, 0)
}

// serializeInt64 encodes val as [length byte][value bytes, little-endian],
// using the minimum number of bytes. This is the format MEGA uses to pack
// a modification time after the CRC32 words in the "c" attribute.
func serializeInt64(val int64) []byte {
	out := make([]byte, 9) // 1 length byte + up to 8 value bytes
	n := 0
	for val != 0 {
		n++
		out[n] = byte(val & 0xFF)
		val >>= 8
	}
	out[0] = byte(n)
	return out[:n+1]
}

// deserializeInt64 is the inverse of serializeInt64.
func deserializeInt64(val []byte) (int64, error) {
	if len(val) == 0 {
		return 0, errors.New("mega: empty mtime attribute")
	}
	n := int(val[0])
	if n > 8 || n >= len(val) {
		return 0, errors.New("mega: invalid mtime attribute")
	}
	var result int64
	for i := n; i > 0; i-- {
		result = (result << 8) | int64(val[i])
	}
	return result, nil
}

// window describes one fixed-size sample window that must be CRC32-folded
// into a particular group (0..crcArrayLength-1), at a fixed absolute file
// offset. Only used for files bigger than maxFull.
type window struct {
	offset int64
	length int
	group  int
}

// computeSampleWindows returns every byte range that MEGA's "large file"
// fingerprint algorithm samples. Because fileSize is known upfront (rclone
// and go-mega both know the size before uploading starts), this can be
// precomputed once instead of requiring random access into the file's
// content while uploading.
func computeSampleWindows(fileSize int64) []window {
	blockLen := 4 * crcSize
	blocksPerGroup := maxFull / (blockLen * crcArrayLength)
	windows := make([]window, 0, crcArrayLength*blocksPerGroup)
	for g := 0; g < crcArrayLength; g++ {
		for i := 0; i < blocksPerGroup; i++ {
			combined := g*blocksPerGroup + i
			offset := (fileSize - int64(blockLen)) * int64(combined) / int64(crcArrayLength*blocksPerGroup-1)
			windows = append(windows, window{offset: offset, length: blockLen, group: g})
		}
	}
	return windows
}

// fingerprintAccumulator computes MEGA's "quick fingerprint" CRC32 words
// incrementally, fed by the plaintext bytes of each upload chunk as it is
// sent (see Upload.UploadChunk). It never seeks or re-reads the source, so
// it works for any source (a local file, a crypt-wrapped remote, another
// cloud remote, stdin, ...). Chunks may be delivered in any order and, since
// Upload supports uploading with multiple concurrent workers, may even
// arrive concurrently: each sample window is a fixed, small (<=64 byte)
// buffer addressed by absolute file offset, so out-of-order or concurrent
// delivery still reconstructs every window correctly as long as each byte
// of the file is written exactly once (which UploadChunk's chunking already
// guarantees). Write is safe for concurrent use.
type fingerprintAccumulator struct {
	mutex sync.Mutex

	mode int // 0 = tiny (fileSize<=crcSize), 1 = small (fileSize<=maxFull), 2 = large

	buf []byte // tiny/small mode: whole file content, buffered (at most maxFull bytes)

	windows  []window // large mode only
	winBuf   [][]byte // large mode only: one fixed-size buffer per window
	winSeen  []int    // large mode only: bytes written so far into each window
	groupCRC [crcArrayLength]uint32
}

func newFingerprintAccumulator(fileSize int64) *fingerprintAccumulator {
	fa := &fingerprintAccumulator{}
	switch {
	case fileSize <= crcSize:
		fa.mode = 0
		fa.buf = make([]byte, crcSize) // zero-padded if the file is shorter
	case fileSize <= maxFull:
		fa.mode = 1
		fa.buf = make([]byte, fileSize)
	default:
		fa.mode = 2
		fa.windows = computeSampleWindows(fileSize)
		fa.winBuf = make([][]byte, len(fa.windows))
		fa.winSeen = make([]int, len(fa.windows))
		for i, w := range fa.windows {
			fa.winBuf[i] = make([]byte, w.length)
		}
	}
	return fa
}

// Write feeds fileOffset..fileOffset+len(data) of plaintext file content
// into the accumulator. data is a contiguous, non-overlapping slice of the
// file; different Write calls (i.e. different upload chunks) may arrive in
// any order, and even concurrently.
func (fa *fingerprintAccumulator) Write(fileOffset int64, data []byte) {
	if fa == nil || len(data) == 0 {
		return
	}
	fa.mutex.Lock()
	defer fa.mutex.Unlock()

	switch fa.mode {
	case 0, 1:
		end := fileOffset + int64(len(data))
		if end > int64(len(fa.buf)) {
			end = int64(len(fa.buf))
		}
		if end <= fileOffset {
			return
		}
		copy(fa.buf[fileOffset:end], data[:end-fileOffset])
	default:
		fa.writeLarge(fileOffset, data)
	}
}

func (fa *fingerprintAccumulator) writeLarge(fileOffset int64, data []byte) {
	// Only bookkeeping happens here: copy whichever bytes of this piece
	// belong to a not-yet-complete window into that window's buffer.
	// crc32.Update is deliberately NOT called here: a crc32.Update chain
	// is order-dependent (it computes the CRC of a concatenation, not an
	// order-independent combination), so folding a window in as soon as
	// it happens to complete would make the result depend on chunk
	// upload/arrival order - which, since Upload supports multiple
	// concurrent workers (see UploadFile), is not guaranteed. Instead
	// every window is folded into its group's CRC in one fixed pass, in
	// Finish, below.
	chunkStart := fileOffset
	chunkEnd := fileOffset + int64(len(data))
	for i, w := range fa.windows {
		if fa.winSeen[i] >= w.length {
			continue // already complete
		}
		wStart, wEnd := w.offset, w.offset+int64(w.length)
		start := wStart
		if start < chunkStart {
			start = chunkStart
		}
		end := wEnd
		if end > chunkEnd {
			end = chunkEnd
		}
		if end <= start {
			continue // no overlap with this chunk
		}
		copy(fa.winBuf[i][start-wStart:end-wStart], data[start-chunkStart:end-chunkStart])
		fa.winSeen[i] += int(end - start)
	}
}

// Finish returns the 4 CRC32 fingerprint words. Any window that never
// received its full content (should only happen if UploadChunk was never
// called for part of the file) is folded in as-is (zero-padded).
func (fa *fingerprintAccumulator) Finish() []uint32 {
	fa.mutex.Lock()
	defer fa.mutex.Unlock()

	crc := make([]uint32, crcArrayLength)
	switch fa.mode {
	case 0:
		for i := 0; i < crcArrayLength; i++ {
			crc[i] = binary.BigEndian.Uint32(fa.buf[i*4:])
		}
	case 1:
		fileSize := int64(len(fa.buf))
		for i := 0; i < crcArrayLength; i++ {
			begin := int64(i) * fileSize / crcArrayLength
			end := (int64(i) + 1) * fileSize / crcArrayLength
			crc[i] = htonl(crc32.ChecksumIEEE(fa.buf[begin:end]))
		}
	default:
		// Fold every window into its group's CRC in the fixed canonical
		// order (fa.windows is laid out group-by-group, each group's
		// windows in ascending sample order - see computeSampleWindows),
		// regardless of the order in which windows actually became
		// complete while uploading.
		for i, w := range fa.windows {
			fa.groupCRC[w.group] = crc32.Update(fa.groupCRC[w.group], crc32.IEEETable, fa.winBuf[i])
		}
		for i := 0; i < crcArrayLength; i++ {
			crc[i] = htonl(fa.groupCRC[i])
		}
	}
	return crc
}

// htonl mirrors the (host-endianness-dependent) byte order used by the
// reference implementations linked above, so that fingerprints produced by
// this library match those produced by official MEGA clients on the same
// (near-universally little-endian) platforms.
func htonl(val uint32) uint32 {
	tmp := make([]byte, 4)
	binary.NativeEndian.PutUint32(tmp, val)
	return binary.BigEndian.Uint32(tmp)
}
