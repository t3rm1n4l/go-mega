// Wrappers to make Mega match various fs.FS interfaces
package mega

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
)

type megaFile struct {
	mega        *Mega
	node        *Node
	download    *Download
	downloadPos int64
	mutex       sync.Mutex
}

// Compile time type check to make sure we implement all the various fs.FS interfaces
var _ fs.FS = (*Mega)(nil)
var _ fs.ReadDirFS = (*Mega)(nil)
var _ fs.ReadFileFS = (*Mega)(nil)
var _ fs.StatFS = (*Mega)(nil)

func (m *Mega) fullPathLookup(path string) (*Node, error) {
	parent := m.FS.GetRoot()
	if path == "." || path == "/" || path == "" {
		return parent, nil
	}
	dirs := strings.Split(path, "/")
	paths, err := m.FS.PathLookup(parent, dirs)
	if err != nil {
		return nil, err
	}
	if len(paths) != len(dirs) {
		return nil, fmt.Errorf("couldn't walk %s", path)
	}
	return paths[len(paths)-1], nil
}

func (m *Mega) Open(name string) (fs.File, error) {
	node, err := m.fullPathLookup(name)
	if err != nil {
		return nil, err
	}
	return &megaFile{mega: m, node: node}, nil
}

func (m *Mega) ReadDir(name string) ([]fs.DirEntry, error) {
	node, err := m.fullPathLookup(name)
	if err != nil {
		return nil, err
	}
	children, err := m.FS.GetChildren(node)
	if err != nil {
		return nil, fmt.Errorf("cannot get children from %s: %s", node.GetName(), err)
	}
	var entries []fs.DirEntry

	for _, c := range children {
		entries = append(entries, &megaFile{mega: m, node: c})
	}
	return entries, nil
}

func (m *Mega) ReadFile(name string) ([]byte, error) {
	node, err := m.fullPathLookup(name)
	if err != nil {
		return nil, err
	}
	mf := &megaFile{mega: m, node: node}
	return io.ReadAll(mf)
}

func (m *Mega) Stat(name string) (fs.FileInfo, error) {
	node, err := m.fullPathLookup(name)
	if err != nil {
		return nil, err
	}
	mf := &megaFile{mega: m, node: node}
	return mf.Stat()
}

func (m *megaFile) Close() error {
	if m.download != nil {
		return m.download.Finish()
	}
	return nil
}

func (m *megaFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !m.IsDir() {
		return nil, fmt.Errorf("not a directory")
	}
	children, err := m.mega.FS.GetChildren(m.node)
	if err != nil {
		return nil, fmt.Errorf("cannot get children from %s: %s", m.Name(), err)
	}
	var entries []fs.DirEntry

	for _, c := range children {
		entries = append(entries, &megaFile{mega: m.mega, node: c})
	}
	if n >= 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries, nil
}

func (m *megaFile) Read(buf []byte) (int, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// todo: should have locking
	if m.IsDir() {
		return 0, fmt.Errorf("%s is a directory", m.Name())
	}
	if m.download == nil {
		d, err := m.mega.NewDownload(m.node)
		if err != nil {
			return 0, err
		}
		m.download = d
	}
	chunks := m.download.Chunks()
	length := 0
	for i := 0; i < chunks; i++ {
		pos, size, err := m.download.ChunkLocation(i)
		if err != nil {
			return length, err
		}
		if pos+int64(size) < m.downloadPos {
			continue
		}
		data, err := m.download.DownloadChunk(i)
		if err != nil {
			return length, err
		}
		offset := m.downloadPos - pos
		thisLength := copy(buf[length:], data[offset:])
		length += thisLength
		m.downloadPos += int64(thisLength)
		if length == len(buf) {
			break
		}
	}

	return length, nil
}

func (m *megaFile) Stat() (fs.FileInfo, error) {
	return m, nil
}
func (m *megaFile) Info() (fs.FileInfo, error) {
	return m, nil
}
func (m *megaFile) Type() fs.FileMode {
	var mode fs.FileMode
	if m.IsDir() {
		mode = fs.ModeDir
	}
	return mode
}

// fs.FileInfo implementation
func (m *megaFile) Name() string {
	return m.node.GetName()
}
func (m *megaFile) Size() int64 {
	return m.node.GetSize()
}
func (m *megaFile) Mode() fs.FileMode {
	if m.IsDir() {
		return 0777
	}
	return 0666
}
func (m *megaFile) ModTime() time.Time {
	return m.node.GetTimeStamp()
}
func (m *megaFile) IsDir() bool {
	t := m.node.GetType()
	return (t == FOLDER || t == ROOT)
}
func (m *megaFile) Sys() interface{} {
	return nil
}
