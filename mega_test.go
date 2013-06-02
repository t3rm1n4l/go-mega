package mega

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

const (
	USER     = "someaccount"
	PASSWORD = "password"
)

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
	node, err := session.UploadFile(name, session.fs.root)
	os.Remove(name)
	if err != nil {
		t.Fatal("Upload failed", err)
	}

	if node == nil {
		t.Error("Failed to obtain node after upload")
	}

	phash := session.fs.root.hash
	session.GetFileSystem()
	n := session.fs.lookup[node.hash]
	if n.parent.hash != phash {
		t.Error("Parent of uploaded file mismatch")
	}

	err = session.DownloadFile(node, name)
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
	node, err := session.UploadFile(name, session.fs.root)
	os.Remove(name)

	hash := node.hash
	phash := session.fs.trash.hash
	err = session.Move(node, session.fs.trash)
	if err != nil {
		t.Fatal("Move failed", err)
	}

	session.GetFileSystem()
	n := session.fs.lookup[hash]
	if n.parent.hash != phash {
		t.Error("Move happened to wrong parent", phash, n.parent.hash)
	}
}

func TestRename(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, _ := createFile(31)
	node, err := session.UploadFile(name, session.fs.root)
	os.Remove(name)

	err = session.Rename(node, "newname.txt")
	if err != nil {
		t.Fatal("Rename failed", err)
	}

	session.GetFileSystem()
	newname := session.fs.lookup[node.hash].name
	if newname != "newname.txt" {
		t.Error("Renamed to wrong name", newname)
	}
}

func TestDelete(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	name, _ := createFile(31)
	node, _ := session.UploadFile(name, session.fs.root)
	os.Remove(name)

	err := session.Delete(node, false)
	if err != nil {
		t.Fatal("Soft delete failed", err)
	}

	session.GetFileSystem()
	node = session.fs.lookup[node.hash]
	if node.parent != session.fs.trash {
		t.Error("Expects file to be moved to trash")
	}

	err = session.Delete(node, true)
	if err != nil {
		t.Fatal("Hard delete failed", err)
	}

	session.GetFileSystem()
	if _, ok := session.fs.lookup[node.hash]; ok {
		t.Error("Expects file to be dissapeared")
	}
}

func TestCreateDir(t *testing.T) {
	session := initSession()
	session.GetFileSystem()
	node, err := session.CreateDir("testdir1", session.fs.root)
	if err != nil {
		t.Fatal("Failed to create directory-1", err)
	}

	node2, err := session.CreateDir("testdir2", node)
	if err != nil {
		t.Fatal("Failed to create directory-2", err)
	}

	session.GetFileSystem()
	nnode2 := session.fs.lookup[node2.hash]
	if nnode2.parent.hash != node.hash {
		t.Error("Wrong directory parent")
	}
}
