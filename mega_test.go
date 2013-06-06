package mega

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

var USER string = os.Getenv("MEGA_USER")
var PASSWORD string = os.Getenv("MEGA_PASSWD")

func initSession() *Mega {
	m := New()
	err := m.Login(USER, PASSWORD)
	if err == nil {
		return m
	}

	fmt.Println("Unable to initialize session")
	os.Exit(1)
	return nil
}

func createFile(size int64) (string, string) {
	b := make([]byte, size)
	rand.Read(b)
	file, _ := ioutil.TempFile("/tmp/", "gomega-")
	file.Write(b)
	h := md5.New()
	h.Write(b)
	return file.Name(), fmt.Sprintf("%x", h.Sum(nil))
}

func fileMD5(name string) string {
	file, _ := os.Open(name)
	b, _ := ioutil.ReadAll(file)
	h := md5.New()
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestLogin(t *testing.T) {
	m := New()
	err := m.Login(USER, PASSWORD)
	if err != nil {
		t.Error("Login failed", err)
	}
}

func TestGetUser(t *testing.T) {
	session := initSession()
	_, err := session.GetUser()
	if err != nil {
		t.Fatal("GetUser failed", err)
	}
}

func TestGetFileSystem(t *testing.T) {
	session := initSession()
	err := session.GetFileSystem()
	if err != nil {
		t.Fatal("GetFileSystem failed", err)
	}
}

func TestUploadDownload(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, h1 := createFile(314573)
	node, err := session.UploadFile(name, session.FS.root, "", nil)
	os.Remove(name)
	if err != nil {
		t.Fatal("Upload failed", err)
	}

	if node == nil {
		t.Error("Failed to obtain node after upload")
	}

	phash := session.FS.root.hash
	session.GetFileSystem()
	n := session.FS.lookup[node.hash]
	if n.parent.hash != phash {
		t.Error("Parent of uploaded file mismatch")
	}

	err = session.DownloadFile(node, name, nil)
	if err != nil {
		t.Fatal("Download failed", err)
	}

	h2 := fileMD5(name)
	os.Remove(name)

	if h1 != h2 {
		t.Error("MD5 mismatch for downloaded file")
	}
}

func TestMove(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, _ := createFile(31)
	node, err := session.UploadFile(name, session.FS.root, "", nil)
	os.Remove(name)

	hash := node.hash
	phash := session.FS.trash.hash
	err = session.Move(node, session.FS.trash)
	if err != nil {
		t.Fatal("Move failed", err)
	}

	session.GetFileSystem()
	n := session.FS.lookup[hash]
	if n.parent.hash != phash {
		t.Error("Move happened to wrong parent", phash, n.parent.hash)
	}
}

func TestRename(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, _ := createFile(31)
	node, err := session.UploadFile(name, session.FS.root, "", nil)
	os.Remove(name)

	err = session.Rename(node, "newname.txt")
	if err != nil {
		t.Fatal("Rename failed", err)
	}

	session.GetFileSystem()
	newname := session.FS.lookup[node.hash].name
	if newname != "newname.txt" {
		t.Error("Renamed to wrong name", newname)
	}
}

func TestDelete(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, _ := createFile(31)
	node, _ := session.UploadFile(name, session.FS.root, "", nil)
	os.Remove(name)

	err := session.Delete(node, false)
	if err != nil {
		t.Fatal("Soft delete failed", err)
	}

	session.GetFileSystem()
	node = session.FS.lookup[node.hash]
	if node.parent != session.FS.trash {
		t.Error("Expects file to be moved to trash")
	}

	err = session.Delete(node, true)
	if err != nil {
		t.Fatal("Hard delete failed", err)
	}

	session.GetFileSystem()
	if _, ok := session.FS.lookup[node.hash]; ok {
		t.Error("Expects file to be dissapeared")
	}
}

func TestCreateDir(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	node, err := session.CreateDir("testdir1", session.FS.root)
	if err != nil {
		t.Fatal("Failed to create directory-1", err)
	}

	node2, err := session.CreateDir("testdir2", node)
	if err != nil {
		t.Fatal("Failed to create directory-2", err)
	}

	session.GetFileSystem()
	nnode2 := session.FS.lookup[node2.hash]
	if nnode2.parent.hash != node.hash {
		t.Error("Wrong directory parent")
	}
}

func TestConfig(t *testing.T) {
	m := New()
	m.SetAPIUrl("http://example.com")
	err := m.Login(USER, PASSWORD)
	if err == nil {
		t.Error("API Url: Expected failure")
	}

	err = m.SetDownloadWorkers(100)
	if err != EWORKER_LIMIT_EXCEEDED {
		t.Error("Download: Expected EWORKER_LIMIT_EXCEEDED error")
	}

	err = m.SetUploadWorkers(100)
	if err != EWORKER_LIMIT_EXCEEDED {
		t.Error("Upload: Expected EWORKER_LIMIT_EXCEEDED error")
	}

	// TODO: Add timeout test cases

}

func TestPathLookup(t *testing.T) {
	session := initSession()
	session.GetFileSystem()

	rs := randString(5)
	node1, err := session.CreateDir("dir-1-"+rs, session.FS.root)
	if err != nil {
		t.Fatal("Failed to create directory-1", err)
	}

	node21, err := session.CreateDir("dir-2-1-"+rs, node1)
	if err != nil {
		t.Fatal("Failed to create directory-2-1", err)
	}

	node22, err := session.CreateDir("dir-2-2-"+rs, node1)
	if err != nil {
		t.Fatal("Failed to create directory-2-2", err)
	}

	node31, err := session.CreateDir("dir-3-1-"+rs, node21)
	if err != nil {
		t.Fatal("Failed to create directory-3-1", err)
	}

	node32, err := session.CreateDir("dir-3-2-"+rs, node22)
	_ = node32
	if err != nil {
		t.Fatal("Failed to create directory-3-2", err)
	}

	// FIXME: Fix this hack when update listener is implemented
	session.GetFileSystem()
	name1, _ := createFile(31)
	_, err = session.UploadFile(name1, node31, "", nil)
	os.Remove(name1)

	if err != nil {
		t.Fatal("Failed to upload file name1", err)
	}

	session.GetFileSystem()
	name2, _ := createFile(31)
	_, err = session.UploadFile(name2, node31, "", nil)
	os.Remove(name2)

	if err != nil {
		t.Fatal("Failed to upload file name2", err)
	}

	session.GetFileSystem()
	name3, _ := createFile(31)
	_, err = session.UploadFile(name3, node22, "", nil)
	os.Remove(name3)

	if err != nil {
		t.Fatal("Failed to upload file name3", err)
	}

	testpaths := [][]string{
		{"dir-1-" + rs, "dir-2-2-" + rs, path.Base(name3)},
		{"dir-1-" + rs, "dir-2-1-" + rs, "dir-3-1-" + rs},
		{"dir-1-" + rs, "dir-2-1-" + rs, "dir-3-1-" + rs, path.Base(name1)},
		{"dir-1-" + rs, "dir-2-1-" + rs, "none"},
	}

	results := []error{nil, nil, nil, ENOENT}

	for i, tst := range testpaths {
		ns, e := session.FS.PathLookup(session.FS.root, tst)
		switch {
		case e != results[i]:
			t.Errorf("Test %d failed: wrong result", i)
		default:
			if results[i] == nil && len(tst) != len(ns) {
				t.Errorf("Test %d failed: result array len (%d) mismatch", i, len(ns))

			}

			arr := []string{}
			for n := range ns {
				if tst[n] != ns[n].name {
					t.Errorf("Test %d failed: result node mismatches (%v) and (%v)", i, tst, arr)
					break
				}
				arr = append(arr, tst[n])
			}
		}
	}
}
