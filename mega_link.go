package mega

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type MegaLink struct {
	Type     MegaLinkType
	Key      string
	Handle   string
	Specific string
}

type MegaLinkType int

const (
	LinkNone MegaLinkType = iota
	LinkFile
	LinkFolder
)

var linkRegexes = []struct {
	Patter *regexp.Regexp
	Type   MegaLinkType
}{
	{regexp.MustCompile(`^(?i)https?://mega(?:\.co)?\.nz/#!([a-z-1-9_-]{8})!([a-z0-9_=-]{43}={0,2})$`), LinkFile},
	{regexp.MustCompile(`^(?i)https?://mega\.nz/file/([a-z-1-9_-]{8})#([a-z0-9_-]{43}={0,2})$`), LinkFile},
	{regexp.MustCompile(`^(?i)https?://mega(?:\.co)?\.nz/#F!([a-z-1-9_-]{8})!([a-z0-9_-]{22})(?:[!?]([a-z0-9_-]{8}))?$`), LinkFolder},
	{regexp.MustCompile(`^(?i)https?://mega\.nz/folder/([a-z-1-9_-]{8})#([a-z0-9_-]{22})/file/([a-z0-9_-]{8})$`), LinkFolder},
	{regexp.MustCompile(`^(?i)https?://mega\.nz/folder/([a-z-1-9_-]{8})#([a-z0-9_-]{22})/folder/([a-z0-9_-]{8})$`), LinkFolder},
	{regexp.MustCompile(`^(?i)https?://mega\.nz/folder/([a-z-1-9_-]{8})#([a-z0-9_-]{22})$`), LinkFolder},
}

func parseLink(url string) (MegaLink, error) {
	link := MegaLink{}

	for _, linkRegex := range linkRegexes {
		matches := linkRegex.Patter.FindStringSubmatch(url)
		if matches != nil {
			link.Type = linkRegex.Type
			link.Handle = matches[1]
			link.Key = matches[2]
			if len(matches) == 4 {
				link.Specific = matches[3]
			}

			return link, nil
		}
	}

	return link, fmt.Errorf(`invalid Mega download link: %s\n"`, url)
}

// Get all nodes from public link to session filesystem
func (m *Mega) getLinkFileSystem(parsedLink MegaLink) error {
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()

	var err error

	if parsedLink.Type != LinkFolder {
		return EARGS
	}

	m.n = parsedLink.Handle
	m.k, err = base64urldecode(parsedLink.Key)
	if err != nil {
		return err
	}

	var msg [1]FilesMsg
	var res [1]FilesResp

	msg[0].Cmd = "f"
	msg[0].C = 1

	req, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	result, err := m.api_request(req)
	if err != nil {
		return err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return err
	}

	for i, itm := range res[0].F {
		if i == 0 {
			m.FS.skmap[itm.Hash] = parsedLink.Key
		}

		_, err = m.addFSNode(itm)
		if err != nil {
			m.debugf("couldn't decode FSNode %#v: %v ", itm, err)
			continue
		}
	}

	m.ssn = res[0].Sn

	go m.pollEvents()

	return nil
}

func (m *Mega) NewLinkDownload(parsedLink MegaLink) (*Download, error) {
	var msg [1]DownloadMsg
	var res [1]DownloadResp

	m.FS.mutex.Lock()
	msg[0].Cmd = "g"
	msg[0].G = 1
	msg[0].P = parsedLink.Handle
	if m.config.https {
		msg[0].SSL = 2
	}
	ukey, err := base64urldecode(parsedLink.Key)
	if err != nil {
		return nil, err
	}

	compkey, err := bytes_to_a32(ukey)
	if err != nil {
		return nil, err
	}

	key, err := a32_to_bytes([]uint32{
		compkey[0] ^ compkey[4],
		compkey[1] ^ compkey[5],
		compkey[2] ^ compkey[6],
		compkey[3] ^ compkey[7],
	})
	if err != nil {
		return nil, err
	}

	m.FS.mutex.Unlock()

	request, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	result, err := m.api_request(request)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(result, &res)
	if err != nil {
		return nil, err
	}

	// DownloadResp has an embedded error in it for some reason
	if res[0].Err != 0 {
		return nil, parseError(res[0].Err)
	}

	fileAttr, err := decryptAttr(key, res[0].Attr)
	if err != nil {
		return nil, err
	}

	chunks := getChunkSizes(int64(res[0].Size))

	aes_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mac_enc := cipher.NewCBCEncrypter(aes_block, zero_iv)
	m.FS.mutex.Lock()

	meta, err := buildMeta(FILE, key, compkey)
	if err != nil {
		return nil, err
	}

	iv, err := a32_to_bytes([]uint32{compkey[4], compkey[5], 0, 0})
	if err != nil {
		return nil, err
	}
	t, err := bytes_to_a32(iv)
	m.FS.mutex.Unlock()
	if err != nil {
		return nil, err
	}
	iv, err = a32_to_bytes([]uint32{t[0], t[1], t[0], t[1]})
	if err != nil {
		return nil, err
	}

	downloadUrl := res[0].G
	if m.config.https && strings.HasPrefix(downloadUrl, "http://") {
		downloadUrl = "https://" + strings.TrimPrefix(downloadUrl, "http://")
	}

	d := &Download{
		m: m,
		src: &Node{
			fs:   m.FS,
			name: fileAttr.Name,
			size: int64(res[0].Size),
			meta: meta,
		},
		resourceUrl: downloadUrl,
		aes_block:   aes_block,
		iv:          iv,
		mac_enc:     mac_enc,
		chunks:      chunks,
		chunk_macs:  make([][]byte, len(chunks)),
	}
	return d, nil
}
