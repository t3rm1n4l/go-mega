package mega

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	API_URL          = "https://eu.api.mega.co.nz/cs"
	RETRIES          = 5
	DOWNLOAD_WORKERS = 6
	UPLOAD_WORKERS   = 6
)

type Mega struct {
	// Sequence number
	sn int64
	// Session ID
	sid []byte
	// Master key
	k []byte
	// User handle
	uh []byte
	// Filesystem object
	fs MegaFS
}

// Filesystem node types
const (
	FILE   = 0
	FOLDER = 1
	ROOT   = 2
	INBOX  = 3
	TRASH  = 4
)

// Filesystem node
type Node struct {
	name     string
	hash     string
	parent   *Node
	children []*Node
	ntype    int
	meta     NodeMeta
}

func (n *Node) RemoveChild(c *Node) bool {
	index := -1
	for i, v := range n.children {
		if v == c {
			index = i
			break
		}
	}

	if index >= 0 {
		n.children[index] = n.children[len(n.children)-1]
		n.children = n.children[:len(n.children)-1]
		return true
	}

	return false
}

func (n *Node) AddChild(c *Node) {
	n.children = append(n.children, c)
}

type NodeMeta struct {
	key     []byte
	compkey []byte
	iv      []byte
	mac     []byte
}

// Mega filesystem object
type MegaFS struct {
	root   *Node
	trash  *Node
	inbox  *Node
	sroots []*Node
	lookup map[string]*Node
	skmap  map[string]string
}

func New() *Mega {
	max := big.NewInt(0x100000000)
	bigx, _ := rand.Int(rand.Reader, max)
	m := &Mega{bigx.Int64(), nil, nil, nil, MegaFS{nil, nil, nil, []*Node{}, map[string]*Node{}, map[string]string{}}}
	return m
}

// API request method
func (m *Mega) api_request(r []byte) ([]byte, error) {
	var err error
	var resp *http.Response
	var buf []byte
	url := fmt.Sprintf("%s?id=%d", API_URL, m.sn)

	if m.sid != nil {
		url = fmt.Sprintf("%s&sid=%s", url, string(m.sid))
	}

	for i := 0; i < RETRIES; i++ {
		resp, err = http.Post(url, "application/json", bytes.NewBuffer(r))
		if err == nil {
			if resp.StatusCode == 200 {
				goto success
			}
			err = errors.New("Http Status:" + resp.Status)
		}

		if err != nil {
			return nil, err
		}

	success:
		buf, _ = ioutil.ReadAll(resp.Body)

		if len(buf) < 6 {
			var emsg [1]ErrorMsg
			err := json.Unmarshal(buf, &emsg)
			if err != nil {
				json.Unmarshal(buf, &emsg[0])
			}
			err = parseError(emsg[0])
			if err == EAGAIN {
				continue
			}

			if err != nil {
				return nil, err
			}
		}
	}

	m.sn++
	return buf, nil
}

// Authenticate and start a session
func (m *Mega) Login(email string, passwd string) error {
	var msg [1]LoginMsg
	var res [1]LoginResp
	var err error
	var result []byte

	passkey := password_key(passwd)
	uhandle := stringhash(email, passkey)
	m.uh = make([]byte, len(uhandle))
	copy(m.uh, uhandle)

	msg[0].Cmd = "us"
	msg[0].User = email
	msg[0].Handle = string(uhandle)

	req, _ := json.Marshal(msg)
	result, err = m.api_request(req)

	if err != nil {
		return err
	}

	json.Unmarshal(result, &res)
	m.k = base64urldecode([]byte(res[0].Key))
	cipher, err := aes.NewCipher(passkey)
	cipher.Decrypt(m.k, m.k)
	m.sid = decryptSessionId([]byte(res[0].Privk), []byte(res[0].Csid), m.k)

	return err
}

// Get user information
func (m Mega) GetUser() (UserResp, error) {
	var msg [1]UserMsg
	var res [1]UserResp

	msg[0].Cmd = "ug"

	req, _ := json.Marshal(msg)
	result, err := m.api_request(req)

	if err != nil {
		return res[0], err
	}

	json.Unmarshal(result, &res)
	return res[0], nil
}

// Add a node into filesystem
func (m *Mega) AddFSNode(itm FSNode) (*Node, error) {
	var compkey, key []uint32
	var attr FileAttr
	var node, parent *Node
	var err error

	master_aes, _ := aes.NewCipher(m.k)

	switch {
	case itm.T == FOLDER || itm.T == FILE:
		args := strings.Split(itm.Key, ":")

		switch {
		// File or folder owned by current user
		case args[0] == itm.User:
			buf := base64urldecode([]byte(args[1]))
			blockDecrypt(master_aes, buf, buf)
			compkey = bytes_to_a32(buf)
			// Shared folder
		case itm.SUser != "" && itm.SKey != "":
			sk := base64urldecode([]byte(itm.SKey))
			blockDecrypt(master_aes, sk, sk)
			sk_aes, _ := aes.NewCipher(sk)

			m.fs.skmap[itm.Hash] = itm.SKey
			buf := base64urldecode([]byte(args[1]))
			blockDecrypt(sk_aes, buf, buf)
			compkey = bytes_to_a32(buf)
			// Shared file
		default:
			k := m.fs.skmap[args[0]]
			b := base64urldecode([]byte(k))
			blockDecrypt(master_aes, b, b)
			block, _ := aes.NewCipher(b)
			buf := base64urldecode([]byte(args[1]))
			blockDecrypt(block, buf, buf)
			compkey = bytes_to_a32(buf)
		}

		switch {
		case itm.T == FILE:
			key = []uint32{compkey[0] ^ compkey[4], compkey[1] ^ compkey[5], compkey[2] ^ compkey[6], compkey[3] ^ compkey[7]}
		default:
			key = compkey
		}

		attr, err = decryptAttr(a32_to_bytes(key), []byte(itm.Attr))
		// FIXME:
		if err != nil {
			attr.Name = "UNKNOWN"
		}
	}

	n, ok := m.fs.lookup[itm.Hash]
	switch {
	case ok:
		node = n
	default:
		node = &Node{"", "", nil, []*Node{}, itm.T, NodeMeta{[]byte{}, []byte{}, []byte{}, []byte{}}}
		m.fs.lookup[itm.Hash] = node
	}

	n, ok = m.fs.lookup[itm.Parent]
	switch {
	case ok:
		parent = n
		parent.AddChild(node)
	default:
		parent = nil
		if itm.Parent != "" {
			parent = &Node{"", "", nil, []*Node{node}, FOLDER, NodeMeta{[]byte{}, []byte{}, []byte{}, []byte{}}}
			m.fs.lookup[itm.Parent] = parent
		}
	}

	switch {
	case itm.T == FILE:
		var meta NodeMeta
		meta.key = a32_to_bytes(key)
		meta.iv = a32_to_bytes([]uint32{compkey[4], compkey[5], 0, 0})
		meta.mac = a32_to_bytes([]uint32{compkey[6], compkey[7]})
		meta.compkey = a32_to_bytes(compkey)
		node.meta = meta
	case itm.T == ROOT:
		attr.Name = "Cloud Drive"
		m.fs.root = node
	case itm.T == INBOX:
		attr.Name = "InBox"
		m.fs.inbox = node
	case itm.T == TRASH:
		attr.Name = "Trash"
		m.fs.trash = node
	}

	// Shared directories
	if itm.SUser != "" && itm.SKey != "" {
		m.fs.sroots = append(m.fs.sroots, node)
	}

	node.name = attr.Name
	node.hash = itm.Hash
	node.parent = parent
	node.ntype = itm.T

	return node, nil
}

// Get all nodes from filesystem
func (m *Mega) GetFileSystem() error {
	var msg [1]FilesMsg
	var res [1]FilesResp

	msg[0].Cmd = "f"
	msg[0].C = 1

	req, _ := json.Marshal(msg)
	result, err := m.api_request(req)

	if err != nil {
		return err
	}

	json.Unmarshal(result, &res)
	for _, sk := range res[0].Ok {
		m.fs.skmap[sk.Hash] = sk.Key
	}

	for _, itm := range res[0].F {
		m.AddFSNode(itm)
	}

	return nil
}

// Download file from filesystem
func (m Mega) DownloadFile(src *Node, dstpath string) error {
	var msg [1]DownloadMsg
	var res [1]DownloadResp
	var outfile *os.File
	var mutex sync.Mutex

	_, err := os.Stat(dstpath)
	if os.IsExist(err) {
		os.Remove(dstpath)
	}

	outfile, err = os.OpenFile(dstpath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	msg[0].Cmd = "g"
	msg[0].G = 1
	msg[0].N = src.hash

	request, _ := json.Marshal(msg)
	result, err := m.api_request(request)
	if err != nil {
		return err
	}

	json.Unmarshal(result, &res)
	resourceUrl := res[0].G

	_, err = decryptAttr(src.meta.key, []byte(res[0].Attr))

	aes_block, _ := aes.NewCipher(src.meta.key)

	mac_data := a32_to_bytes([]uint32{0, 0, 0, 0})
	mac_enc := cipher.NewCBCEncrypter(aes_block, mac_data)
	t := bytes_to_a32(src.meta.iv)
	iv := a32_to_bytes([]uint32{t[0], t[1], t[0], t[1]})

	sorted_chunks := []int{}
	chunks := getChunkSizes(int(res[0].Size))
	chunk_macs := make([][]byte, len(chunks))

	for k, _ := range chunks {
		sorted_chunks = append(sorted_chunks, k)
	}
	sort.Ints(sorted_chunks)

	workch := make(chan int)
	wg := sync.WaitGroup{}

	// Fire chunk download workers
	for w := 0; w < DOWNLOAD_WORKERS; w++ {
		go func() {
			var id int
			var live bool
			for {
				// Wait for work blocked on channel
				select {
				case id, live = <-workch:
					if !live {
						return
					}
				}

				var resource *http.Response
				mutex.Lock()
				chk_start := sorted_chunks[id]
				chk_size := chunks[chk_start]
				mutex.Unlock()
				chunk_url := fmt.Sprintf("%s/%d-%d", resourceUrl, chk_start, chk_start+chk_size-1)
				for retry := 0; retry < RETRIES; retry++ {
					resource, err = http.Get(chunk_url)
					if err == nil {
						break
					}
				}

				ctr_iv := bytes_to_a32(src.meta.iv)
				ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
				ctr_iv[3] = uint32(chk_start / 0x10)
				ctr_aes := cipher.NewCTR(aes_block, a32_to_bytes(ctr_iv))
				chunk, _ := ioutil.ReadAll(resource.Body)
				ctr_aes.XORKeyStream(chunk, chunk)
				outfile.WriteAt(chunk, int64(chk_start))

				enc := cipher.NewCBCEncrypter(aes_block, iv)
				i := 0
				block := []byte{}
				chunk = paddnull(chunk, 16)
				for i = 0; i < len(chunk); i += 16 {
					block = chunk[i : i+16]
					enc.CryptBlocks(block, block)
				}

				mutex.Lock()
				chunk_macs[id] = make([]byte, 16)
				copy(chunk_macs[id], block)
				mutex.Unlock()
				wg.Done()
			}
		}()
	}

	// Place works to the channel
	for id := 0; id < len(chunks); id++ {
		wg.Add(1)
		workch <- id
	}

	// Wait for chunk downloads to complete
	wg.Wait()
	close(workch)

	for _, v := range chunk_macs {
		mac_enc.CryptBlocks(mac_data, v)
	}

	outfile.Close()
	tmac := bytes_to_a32(mac_data)
	if bytes.Equal(a32_to_bytes([]uint32{tmac[0] ^ tmac[1], tmac[2] ^ tmac[3]}), src.meta.mac) == false {
		return errors.New("MAC Mismatch")
	}

	return nil
}

// Upload a file to the filesystem
func (m Mega) UploadFile(srcpath string, parent *Node) (*Node, error) {
	var msg [1]UploadMsg
	var res [1]UploadResp
	var cmsg [1]UploadCompleteMsg
	var cres [1]UploadCompleteResp
	var infile *os.File
	var fileSize int64
	var mutex sync.Mutex

	parenthash := parent.hash
	info, err := os.Stat(srcpath)
	if err == nil {
		fileSize = info.Size()
	}

	infile, err = os.OpenFile(srcpath, os.O_RDONLY, 0666)
	if err != nil {
		return nil, err
	}

	msg[0].Cmd = "u"
	msg[0].S = fileSize
	completion_handle := []byte{}

	request, _ := json.Marshal(msg)
	result, err := m.api_request(request)
	if err != nil {
		return nil, err
	}
	json.Unmarshal(result, &res)

	uploadUrl := res[0].P
	ukey := []uint32{0, 0, 0, 0, 0, 0}
	for i, _ := range ukey {
		ukey[i] = uint32(mrand.Int31())

	}

	kbytes := a32_to_bytes(ukey[:4])
	kiv := a32_to_bytes([]uint32{ukey[4], ukey[5], 0, 0})
	aes_block, _ := aes.NewCipher(kbytes)

	mac_data := a32_to_bytes([]uint32{0, 0, 0, 0})
	mac_enc := cipher.NewCBCEncrypter(aes_block, mac_data)
	iv := a32_to_bytes([]uint32{ukey[4], ukey[5], ukey[4], ukey[5]})

	client := &http.Client{}

	sorted_chunks := []int{}
	chunks := getChunkSizes(int(fileSize))
	chunk_macs := make([][]byte, len(chunks))

	for k, _ := range chunks {
		sorted_chunks = append(sorted_chunks, k)
	}
	sort.Ints(sorted_chunks)
	workch := make(chan int)
	wg := sync.WaitGroup{}

	for w := 0; w < UPLOAD_WORKERS; w++ {
		go func() {
			var id int
			var live bool
			for {
				select {
				case id, live = <-workch:
					if !live {
						return
					}
				}

				mutex.Lock()
				chk_start := sorted_chunks[id]
				chk_size := chunks[chk_start]
				mutex.Unlock()
				ctr_iv := bytes_to_a32(kiv)
				ctr_iv[2] = uint32(uint64(chk_start) / 0x1000000000)
				ctr_iv[3] = uint32(chk_start / 0x10)
				ctr_aes := cipher.NewCTR(aes_block, a32_to_bytes(ctr_iv))

				chunk := make([]byte, chk_size)
				n, _ := infile.ReadAt(chunk, int64(chk_start))
				chunk = chunk[:n]

				enc := cipher.NewCBCEncrypter(aes_block, iv)

				i := 0
				block := make([]byte, 16)
				paddedchunk := paddnull(chunk, 16)
				for i = 0; i < len(paddedchunk); i += 16 {
					copy(block[0:16], paddedchunk[i:i+16])
					enc.CryptBlocks(block, block)
				}

				mutex.Lock()
				chunk_macs[id] = make([]byte, 16)
				copy(chunk_macs[id], block)
				mutex.Unlock()

				ctr_aes.XORKeyStream(chunk, chunk)

				chk_url := fmt.Sprintf("%s/%d", uploadUrl, chk_start)
				reader := bytes.NewBuffer(chunk)
				req, _ := http.NewRequest("POST", chk_url, reader)
				rsp, _ := client.Do(req)
				chunk_resp, _ := ioutil.ReadAll(rsp.Body)
				if bytes.Equal(chunk_resp, nil) == false {
					mutex.Lock()
					completion_handle = chunk_resp
					mutex.Unlock()

				}
				wg.Done()
			}
		}()
	}

	// Place chunk upload jobs to chan
	for id := 0; id < len(chunks); id++ {
		wg.Add(1)
		workch <- id
	}

	wg.Wait()
	close(workch)

	for _, v := range chunk_macs {
		mac_enc.CryptBlocks(mac_data, v)
	}

	t := bytes_to_a32(mac_data)
	meta_mac := []uint32{t[0] ^ t[1], t[2] ^ t[3]}

	filename := filepath.Base(srcpath)
	attr := FileAttr{filename}

	attr_data, _ := encryptAttr(kbytes, attr)

	key := []uint32{ukey[0] ^ ukey[4], ukey[1] ^ ukey[5],
		ukey[2] ^ meta_mac[0], ukey[3] ^ meta_mac[1],
		ukey[4], ukey[5], meta_mac[0], meta_mac[1]}

	buf := a32_to_bytes(key)
	master_aes, _ := aes.NewCipher(m.k)
	iv = a32_to_bytes([]uint32{0, 0, 0, 0})
	enc := cipher.NewCBCEncrypter(master_aes, iv)
	enc.CryptBlocks(buf[:16], buf[:16])
	enc = cipher.NewCBCEncrypter(master_aes, iv)
	enc.CryptBlocks(buf[16:], buf[16:])

	cmsg[0].Cmd = "p"
	cmsg[0].T = parenthash
	cmsg[0].N[0].H = string(completion_handle)
	cmsg[0].N[0].T = FILE
	cmsg[0].N[0].A = string(attr_data)
	cmsg[0].N[0].K = string(base64urlencode(buf))

	request, _ = json.Marshal(cmsg)
	result, err = m.api_request(request)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(result, &cres)
	node, err := m.AddFSNode(cres[0].F[0])

	return node, err
}

// Move a file from one location to another
func (m Mega) Move(src *Node, parent *Node) error {
	var msg [1]MoveFileMsg

	msg[0].Cmd = "m"
	msg[0].N = src.hash
	msg[0].T = parent.hash
	msg[0].I = randString(10)

	request, _ := json.Marshal(msg)
	_, err := m.api_request(request)

	if err != nil {
		return err
	}

	if node, ok := m.fs.lookup[src.parent.hash]; ok {
		node.RemoveChild(node)
		parent.AddChild(src)
		src.parent = parent
	}

	return nil
}

// Rename a file or folder
func (m Mega) Rename(src *Node, name string) error {
	var msg [1]FileAttrMsg

	master_aes, _ := aes.NewCipher(m.k)
	attr := FileAttr{name}
	attr_data, _ := encryptAttr(src.meta.key, attr)
	key := make([]byte, len(src.meta.compkey))
	blockEncrypt(master_aes, key, src.meta.compkey)

	msg[0].Cmd = "a"
	msg[0].Attr = string(attr_data)
	msg[0].Key = string(base64urlencode(key))
	msg[0].N = src.hash
	msg[0].I = randString(10)

	req, _ := json.Marshal(msg)
	_, err := m.api_request(req)

	return err
}

// Create a directory in the filesystem
func (m Mega) CreateDir(name string, parent *Node) (*Node, error) {
	var msg [1]UploadCompleteMsg
	var res [1]UploadCompleteResp

	compkey := []uint32{0, 0, 0, 0, 0, 0}
	for i, _ := range compkey {
		compkey[i] = uint32(mrand.Int31())
	}

	master_aes, _ := aes.NewCipher(m.k)
	attr := FileAttr{name}
	ukey := a32_to_bytes(compkey[:4])
	attr_data, _ := encryptAttr(ukey, attr)
	key := make([]byte, len(ukey))
	blockEncrypt(master_aes, key, ukey)

	msg[0].Cmd = "p"
	msg[0].T = parent.hash
	msg[0].N[0].H = "xxxxxxxx"
	msg[0].N[0].T = FOLDER
	msg[0].N[0].A = string(attr_data)
	msg[0].N[0].K = string(base64urlencode(key))
	msg[0].I = randString(10)

	req, _ := json.Marshal(msg)
	result, err := m.api_request(req)

	if err != nil {
		return nil, err
	}

	json.Unmarshal(result, &res)
	node, err := m.AddFSNode(res[0].F[0])

	return node, err
}

// Delete a file or directory from filesystem
func (m Mega) Delete(node *Node, destroy bool) error {
	if destroy == false {
		m.Move(node, m.fs.trash)
		return nil
	}

	var msg [1]FileDeleteMsg
	msg[0].Cmd = "d"
	msg[0].N = node.hash
	msg[0].I = randString(10)

	req, _ := json.Marshal(msg)
	_, err := m.api_request(req)

	parent := m.fs.lookup[node.hash]
	parent.RemoveChild(node)
	delete(m.fs.lookup, node.hash)

	return err
}
