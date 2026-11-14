package mega

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

// FetchNodesContext loads the account tree on demand, without background polling.
// Call before concurrent uploads that need the account root.
func (m *Mega) FetchNodesContext(ctx context.Context) error {
	payload, _ := json.Marshal([]FilesMsg{{Cmd: "f", C: 1, R: 1}})
	body, err := m.apiRequest(ctx, payload, "")
	if err != nil {
		return err
	}
	var response [1]FilesResp
	if json.Unmarshal(body, &response) != nil {
		return EBADRESP
	}
	m.FS.mutex.Lock()
	defer m.FS.mutex.Unlock()
	for _, key := range response[0].Ok {
		m.FS.skmap[key.Hash] = key.Key
	}
	for _, raw := range response[0].F {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		node, err := m.addFSNode(raw)
		if err != nil {
			return fmt.Errorf("account node decoding: %w", err)
		}
		if node == nil {
			return EBADRESP
		}
	}
	if m.FS.root == nil {
		return EBADRESP
	}
	return nil
}

// AccountInfo is raw account data suitable for formatting by the consuming app.
// A zero transfer allowance means unspecified, not necessarily unlimited.
type AccountInfo struct {
	Email                       string
	StorageUsed, StorageTotal   uint64
	TransferUsed, TransferTotal uint64
	Plan                        int
	ExpiresAt                   time.Time
	Files, Folders              int64
}

func (m *Mega) AccountInfo(ctx context.Context) (AccountInfo, error) {
	user, err := m.GetUserContext(ctx)
	if err != nil {
		return AccountInfo{}, err
	}
	quota, err := m.GetQuotaContext(ctx)
	if err != nil {
		return AccountInfo{}, err
	}
	info := AccountInfo{Email: user.Email, StorageUsed: quota.Cstrg, StorageTotal: quota.Mstrg, TransferTotal: quota.Mxfer, Plan: quota.ProLevel}
	if quota.Caxfer > math.MaxUint64-quota.Csxfer {
		return AccountInfo{}, EBADRESP
	}
	info.TransferUsed = quota.Caxfer + quota.Csxfer
	if quota.ProExpires > 0 {
		info.ExpiresAt = time.Unix(quota.ProExpires, 0)
	}
	for _, usage := range quota.Cstrgn {
		if len(usage) >= 3 {
			info.Files += usage[1]
			info.Folders += usage[2]
		}
	}
	return info, nil
}

type sessionFile struct {
	SessionID string `json:"session_id"`
	MasterKey []byte `json:"master_key"`
}

// SaveSession writes credentials equivalent to a password. Keep the file outside
// source control. Configure OS ACLs on Windows, where mode 0600 is not an ACL.
func (m *Mega) SaveSession(path string) error {
	if m.sid == "" || len(m.k) != 16 {
		return ESID
	}
	data, err := json.Marshal(sessionFile{m.sid, m.k})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mega-session-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// LoadSession restores and validates an account session without fetching its tree.
// Authenticate/restore before sharing the client with other operations.
func (m *Mega) LoadSession(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return err
	}
	if len(data) > 8192 {
		return EARGS
	}
	var session sessionFile
	if json.Unmarshal(data, &session) != nil || len(session.MasterKey) != 16 {
		return EARGS
	}
	decoded, err := base64urldecode(session.SessionID)
	if err != nil || len(decoded) != 43 {
		return ESID
	}
	oldSID, oldKey := m.sid, m.k
	m.sid = session.SessionID
	m.k = append([]byte(nil), session.MasterKey...)
	if _, err = m.GetUserContext(ctx); err != nil {
		m.sid, m.k = oldSID, oldKey
		return err
	}
	return nil
}

// ExportContext exports an owned file or folder. Folder exports establish a
// read-only share and distribute every descendant's key before creating its URL.
func (m *Mega) ExportContext(ctx context.Context, node *Node) (string, error) {
	if node == nil || node.fs != m.FS {
		return "", EARGS
	}
	select {
	case m.exportGate <- struct{}{}:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	defer func() { <-m.exportGate }()
	kind := node.GetType()
	if kind != FILE && kind != FOLDER {
		return "", EARGS
	}
	m.FS.mutex.Lock()
	hash := node.hash
	key := append([]byte(nil), node.meta.compkey...)
	m.FS.mutex.Unlock()
	if kind == FOLDER {
		master, err := aes.NewCipher(m.k)
		if err != nil {
			return "", err
		}
		m.FS.mutex.Lock()
		stored, exists := m.FS.skmap[hash]
		m.FS.mutex.Unlock()
		share := make([]byte, 16)
		if exists {
			share, err = base64urldecode(stored)
			if err == nil {
				err = blockDecrypt(master, share, share)
			}
			if err != nil || len(share) != 16 {
				return "", EKEY
			}
		} else {
			if _, err = rand.Read(share); err != nil {
				return "", err
			}
		}
		share, secure, err := m.secureShareKey(ctx, hash, share)
		if err != nil {
			return "", fmt.Errorf("folder share key repository: %w", err)
		}
		block, _ := aes.NewCipher(share)
		var handles []string
		var encryptedKeys []any
		m.FS.mutex.Lock()
		var collect func(*Node) error
		seen := make(map[*Node]bool)
		collect = func(n *Node) error {
			if seen[n] {
				return ECIRCULAR
			}
			seen[n] = true
			k := make([]byte, len(n.meta.compkey))
			if len(k) != 16 && len(k) != 32 {
				return EKEY
			}
			if err := blockEncrypt(block, k, n.meta.compkey); err != nil {
				return err
			}
			index := len(handles)
			handles = append(handles, n.hash)
			encryptedKeys = append(encryptedKeys, 0, index, base64urlencode(k))
			for _, child := range n.children {
				if err := collect(child); err != nil {
					return err
				}
			}
			return nil
		}
		err = collect(node)
		m.FS.mutex.Unlock()
		if err != nil {
			return "", err
		}
		ownerKey := make([]byte, 16)
		if err = blockEncrypt(master, ownerKey, share); err != nil {
			return "", err
		}
		if len(hash) != 8 {
			return "", EARGS
		}
		auth := make([]byte, 16)
		if err = blockEncrypt(master, auth, []byte(hash+hash)); err != nil {
			return "", err
		}
		request := map[string]any{"a": "s2", "n": hash, "ok": base64urlencode(ownerKey), "ha": base64urlencode(auth), "s": []any{map[string]any{"u": "EXP", "r": 0}}}
		if secure {
			request["ok"] = base64urlencode(make([]byte, 16))
			request["ha"] = base64urlencode(make([]byte, 16))
		}
		if !exists || secure {
			request["cr"] = []any{[]string{hash}, handles, encryptedKeys}
		}
		payload, _ := json.Marshal([]any{request})
		body, err := m.apiRequest(ctx, payload, "")
		if err != nil {
			return "", fmt.Errorf("establish folder share: %w", err)
		}
		var response [1]struct {
			R  []ErrorMsg      `json:"r"`
			OK json.RawMessage `json:"ok"`
		}
		if json.Unmarshal(body, &response) != nil || len(response[0].R) != 1 {
			return "", EBADRESP
		}
		if len(response[0].OK) > 0 {
			return "", EKEY
		}
		if err = parseError(response[0].R[0]); err != nil {
			return "", fmt.Errorf("folder share response: %w", err)
		}
		m.FS.mutex.Lock()
		m.FS.skmap[hash] = base64urlencode(ownerKey)
		m.FS.mutex.Unlock()
		key = share
	}
	payload, _ := json.Marshal([]GetLinkMsg{{Cmd: "l", N: hash}})
	body, err := m.apiRequest(ctx, payload, "")
	if err != nil {
		return "", fmt.Errorf("export public link: %w", err)
	}
	var response [1]string
	if json.Unmarshal(body, &response) != nil || !validHandle(response[0]) {
		return "", EBADRESP
	}
	prefix := "file"
	if kind == FOLDER {
		prefix = "folder"
	}
	return "https://mega.nz/" + prefix + "/" + response[0] + "#" + base64urlencode(key), nil
}

// UploadResult is also returned on a partial failure, so callers can inspect or
// explicitly remove the new remote root. Existing account data is never deleted.
type UploadResult struct {
	Node *Node
	Name string
	Size int64
	Link string
}

// UploadPath uploads a file or directory, then exports its new root. Parent must
// belong to this account; load the tree once with FetchNodesContext beforehand.
func (m *Mega) UploadPath(ctx context.Context, path string, parent *Node, progress ProgressFunc) (result UploadResult, err error) {
	if parent == nil || parent.fs != m.FS || parent.GetType() == FILE {
		return result, EARGS
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return result, err
	}
	name := filepath.Base(path)
	if !safeName(name) {
		return result, EARGS
	}
	result.Name = name
	var entries []string
	var infos []os.FileInfo
	err = filepath.Walk(path, func(p string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !safeName(info.Name()) || (!info.IsDir() && !info.Mode().IsRegular()) {
			return EARGS
		}
		entries = append(entries, p)
		infos = append(infos, info)
		if !info.IsDir() {
			if info.Size() > math.MaxInt64-result.Size {
				return EARGS
			}
			result.Size += info.Size()
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	reporter := &progressReporter{name: name, total: result.Size, start: time.Now(), callback: progress}
	reporter.add(0)
	if !infos[0].IsDir() {
		result.Node, err = m.UploadFileContext(ctx, path, parent, name, reporter.add)
	} else {
		dirs := map[string]*Node{filepath.Dir(path): parent}
		for i, p := range entries {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			var node *Node
			if infos[i].IsDir() {
				node, err = m.CreateDirContext(ctx, infos[i].Name(), dirs[filepath.Dir(p)])
				dirs[p] = node
			} else {
				node, err = m.UploadFileContext(ctx, p, dirs[filepath.Dir(p)], infos[i].Name(), reporter.add)
			}
			if i == 0 {
				result.Node = node
			}
			if err != nil {
				return result, fmt.Errorf("MEGA upload: %w", err)
			}
		}
	}
	if err != nil {
		return result, err
	}
	result.Link, err = m.ExportContext(ctx, result.Node)
	return result, err
}

// EstimateFreeTransferQuota returns MEGA's numeric qbq response for these file
// handles. Positive values are advisory states, not API errors. Pro clients
// should inspect AccountInfo instead. Runtime quota errors remain authoritative.
func (m *Mega) EstimateFreeTransferQuota(ctx context.Context, own, public []string, activeRemaining int64) (int, error) {
	if (len(own) == 0 && len(public) == 0) || activeRemaining < 0 {
		return 0, EARGS
	}
	for _, list := range [][]string{own, public} {
		for _, handle := range list {
			if !validHandle(handle) {
				return 0, EARGS
			}
		}
	}
	request := map[string]any{"a": "qbq"}
	if len(own) > 0 {
		request["n"] = own
	}
	if len(public) > 0 {
		request["p"] = public
	}
	if activeRemaining > 0 {
		request["s"] = activeRemaining
	}
	payload, _ := json.Marshal([]any{request})
	body, err := m.apiRequest(ctx, payload, "")
	if err != nil {
		return 0, err
	}
	var response [1]int
	if json.Unmarshal(body, &response) != nil {
		return 0, EBADRESP
	}
	return response[0], nil
}
