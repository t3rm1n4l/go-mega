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
	"math/big"
	"net"
	"net/http"
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

func bytes_to_a32(b []byte) []uint32 {
	length := len(b) + 3
	a := make([]uint32, length/4)
	buf := bytes.NewBuffer(b)
	for i, _ := range a {
		binary.Read(buf, binary.BigEndian, &a[i])
	}

	return a
}

func a32_to_bytes(a []uint32) []byte {
	buf := new(bytes.Buffer)
	for _, v := range a {
		binary.Write(buf, binary.BigEndian, v)
	}

	return buf.Bytes()
}

func base64urlencode(b []byte) []byte {
	enc := base64.URLEncoding
	encSize := enc.EncodedLen(len(b))
	buf := make([]byte, encSize)
	enc.Encode(buf, b)

	paddSize := 3 - len(b)%3
	if paddSize < 3 {
		encSize -= paddSize
		buf =  buf[:encSize]
	}

	return buf
}

func base64urldecode(b []byte) []byte {
	enc := base64.URLEncoding
	padSize := 4 - len(b)%4

	switch {
	case padSize == 1:
		b = append(b, '=')
		break
	case padSize == 2:
		b = append(b, '=', '=')
		break
	}

	decSize := enc.DecodedLen(len(b))
	buf := make([]byte, decSize)
	n, _ := enc.Decode(buf, b)
	return buf[:n]
}

func base64_to_a32(b []byte) []uint32 {
	return bytes_to_a32(base64urldecode(b))
}

func a32_to_base64(a []uint32) []byte {
	return base64urlencode(a32_to_bytes(a))
}

func paddnull(b []byte, q int) []byte {
	l := len(b)
	l = q - l%q

	if l%q == 0 {
		l = 0
	}

	for i := 0; i < l; i++ {
		b = append(b, 0)
	}

	return b
}

func password_key(p string) []byte {
	a := bytes_to_a32(paddnull([]byte(p), 4))
	pkey := a32_to_bytes([]uint32{0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56})

	for i := 65536; i > 0; i-- {
		for j := 0; j < len(a); j += 4 {
			key := []uint32{0, 0, 0, 0}
			for k := 0; k < 4; k++ {
				if j+k < len(a) {
					key[k] = a[k+j]
				}
			}
			cipher, _ := aes.NewCipher(a32_to_bytes(key))
			cipher.Encrypt(pkey, pkey)
		}
	}

	return pkey
}

func stringhash(s string, k []byte) []byte {
	a := bytes_to_a32(paddnull([]byte(s), 4))
	h := []uint32{0, 0, 0, 0}
	for i, v := range a {
		h[i&3] ^= v
	}

	hb := a32_to_bytes(h)
	cipher, _ := aes.NewCipher(k)
	for i := 16384; i > 0; i-- {
		cipher.Encrypt(hb, hb)
	}
	ha := bytes_to_a32(paddnull(hb, 4))

	return a32_to_base64([]uint32{ha[0], ha[2]})
}

func getMPILen(b []byte) uint64 {
	return (uint64(b[0])*256 + uint64(b[1]) + 7) >> 3
}

func getRSAKey(b []byte) (*big.Int, *big.Int, *big.Int) {
	p := new(big.Int)
	q := new(big.Int)
	d := new(big.Int)
	plen := getMPILen(b)
	p.SetBytes(b[2 : plen+2])
	b = b[plen+2:]

	qlen := getMPILen(b)

	q.SetBytes(b[2 : qlen+2])
	b = b[qlen+2:]

	dlen := getMPILen(b)

	d.SetBytes(b[2 : dlen+2])

	return p, q, d
}

func decryptRSA(m, p, q, d *big.Int) []byte {
	n := new(big.Int)
	r := new(big.Int)
	n.Mul(p, q)
	r.Exp(m, d, n)

	return r.Bytes()
}

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

func decryptSessionId(privk []byte, csid []byte, mk []byte) []byte {

	block, _ := aes.NewCipher(mk)
	pk := base64urldecode(privk)
	blockDecrypt(block, pk, pk)

	c := base64urldecode(csid)

	l := getMPILen(c)
	m := new(big.Int)

	padded := c[2 : l+2]
	m.SetBytes(padded)
	p, q, d := getRSAKey(pk)
	r := decryptRSA(m, p, q, d)

	return base64urlencode(r[:43])

}

func getChunkSizes(size int) map[int]int {
	chunks := make(map[int]int)
	i := 0
	p := 0
	pp := 0
	for i <= 8 && p < size-i*131072 {
		chunks[p] = i * 131072
		pp = p
		p += chunks[p]
		i++
	}

	for p < size {
		chunks[p] = 1048576
		pp = p
		p += chunks[p]
	}

	chunks[pp] = size - pp
	if chunks[pp] == 0 {
		delete(chunks, pp)
	}

	return chunks
}

func decryptAttr(key []byte, data []byte) (attr FileAttr, err error) {
	err = EBADATTR
	defer func() {
		recover()
	}()
	block, _ := aes.NewCipher(key)
	iv := a32_to_bytes([]uint32{0, 0, 0, 0})
	mode := cipher.NewCBCDecrypter(block, iv)
	buf := make([]byte, len(data))
	mode.CryptBlocks(buf, base64urldecode([]byte(data)))

	if string(buf[:4]) == "MEGA" {
		str := strings.TrimRight(string(buf[4:]), "\x00")
		err = json.Unmarshal([]byte(str), &attr)
	}
	return
}

func encryptAttr(key []byte, attr FileAttr) (b []byte, err error) {
	err = EBADATTR
	defer func() {
		recover()
	}()
	block, _ := aes.NewCipher(key)
	data, _ := json.Marshal(attr)
	attrib := []byte("MEGA")
	attrib = append(attrib, data...)

	length := len(attrib)
	if length%16 != 0 {
		padding := 16 - length%16
		for i := 0; i < padding; i++ {
			attrib = append(attrib, 0)
		}
	}

	iv := a32_to_bytes([]uint32{0, 0, 0, 0})
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(attrib, attrib)

	b = base64urlencode(attrib)
	err = nil
	return
}

func randString(l int) string {
	encoding := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"
	b := make([]byte, l)
	rand.Read(b)
	enc := base64.NewEncoding(encoding)
	d := make([]byte, enc.EncodedLen(len(b))*2)
	enc.Encode(d, b)
	d = d[:l]
	return string(d)
}
