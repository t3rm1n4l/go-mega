package mega

import (
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// Credentials for non MFA-enabled accounts
var USER string = os.Getenv("MEGA_USER")
var PASSWORD string = os.Getenv("MEGA_PASSWD")

// Credentials for MFA-enabled accounts
var USER_MFA = os.Getenv("MEGA_USER_MFA")
var PASSWORD_MFA string = os.Getenv("MEGA_PASSWD_MFA")
var SECRET_MFA string = os.Getenv("MEGA_SECRET_MFA")

// retry runs fn until it succeeds, using what to log and retrying on
// EAGAIN.  It uses exponential backoff
func retry(t *testing.T, what string, fn func() error) {
	const maxTries = 10
	var err error
	sleep := 100 * time.Millisecond
	for i := 1; i <= maxTries; i++ {
		err = fn()
		if err == nil {
			return
		}
		if err != EAGAIN {
			break
		}
		t.Logf("%s failed %d/%d - retrying after %v sleep", what, i, maxTries, sleep)
		time.Sleep(sleep)
		sleep *= 2
	}
	t.Fatalf("%s failed: %v", what, err)
}

type CredentialType int

const (
	Credentials CredentialType = iota
	MfaCredentials
	AnyCredentials
)

// getMfaCode generates an MFA code using the provided secret and the current time.
// If the code cannot be generated, it returns an error.
func getMfaCode(secret string) (string, error) {
	return totp.GenerateCode(secret, time.Now())
}

// getCredentials retrieves credentials for an MFA-enabled account from predefined variables set from the environment.
// If either the user, password or MFA secret are not set, or if an MFA code cannot be successfully generated from the given secret, it returns an error indicating that the credentials are missing or invalid.
func getMfaCredentials() (string, string, string, error) {
	if USER_MFA == "" || PASSWORD_MFA == "" || SECRET_MFA == "" {
		return "", "", "", fmt.Errorf("MEGA_USER_MFA, MEGA_PASSWD_MFA or MEGA_SECRET_MFA not set.")
	}

	mfa_code, mfa_code_err := getMfaCode(SECRET_MFA)
	if mfa_code_err != nil {
		return "", "", "", fmt.Errorf("Generating MFA code failed: %w", mfa_code_err)
	}

	return USER_MFA, PASSWORD_MFA, mfa_code, nil
}

// getCredentials retrieves credentials for a non MFA-enabled account from predefined variables set from the environment.
// If either the user or password are not set, it returns an error indicating that the credentials are missing.
func getCredentials() (string, string, error) {
	if USER == "" || PASSWORD == "" {
		return "", "", fmt.Errorf("MEGA_USER or MEGA_PASSWD not set.")
	}
	return USER, PASSWORD, nil
}

// getCredentialsOrSkip retrieves user credentials based on the specified CredentialType.
// It supports both standard and MFA-enabled credentials.
// If the requested credentials are missing or invalid, the function skips the test with an appropriate message.
func getCredentialsOrSkip(t *testing.T, credentialsType CredentialType) (string, string, string) {

	switch credentialsType {
	case Credentials:
		user, password, err := getCredentials()
		if err != nil {
			t.Skipf("Skipping test due to credentials error: %v", err)
		}
		return user, password, ""
	case MfaCredentials:
		user, password, mfa_code, err := getMfaCredentials()
		if err != nil {
			t.Skipf("Skipping test due to credentials error: %v", err)
		}
		return user, password, mfa_code
	case AnyCredentials:
		user, password, err := getCredentials()
		if err != nil {
			t.Logf("Trying with MFA credentials instead, getting other credentials failed with error: %v", err)
		} else {
			return user, password, ""
		}
		user, password, mfa_code, err := getMfaCredentials()
		if err != nil {
			t.Skipf("Skipping test due to credentials error: %v", err)
		}
		return user, password, mfa_code
	default:
		t.Fatal("Invalid credentials type")
	}

	t.Fatal("Unreachable!")
	return "", "", ""
}

func initSession(t *testing.T) *Mega {
	user, password, mfa_code := getCredentialsOrSkip(t, AnyCredentials)
	m := New()
	// m.SetDebugger(log.Printf)
	retry(t, "Login", func() error {
		if mfa_code != "" {
			return m.MultiFactorLogin(user, password, mfa_code)
		}
		return m.Login(user, password)
	})
	return m
}

func endSession(t *testing.T, session *Mega) {
	retry(t, "Logout", func() error {
		return session.Logout()
	})
}

// createFile creates a temporary file of a given size along with its MD5SUM
func createFile(t *testing.T, size int64) (string, string) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("Error reading rand: %v", err)
	}
	file, err:= os.CreateTemp("/tmp/", "gomega-")
	if err != nil {
		t.Fatalf("Error creating temp file: %v", err)
	}
	_, err = file.Write(b)
	if err != nil {
		t.Fatalf("Error writing temp file: %v", err)
	}
	h := md5.New()
	_, err = h.Write(b)
	if err != nil {
		t.Fatalf("Error on Write while writing temp file: %v", err)
	}
	return file.Name(), fmt.Sprintf("%x", h.Sum(nil))
}

// uploadFile uploads a temporary file of a given size returning the
// node, name and its MD5SUM
func uploadFile(t *testing.T, session *Mega, size int64, parent *Node) (node *Node, name string, md5sum string) {
	name, md5sum = createFile(t, size)
	defer func() {
		_ = os.Remove(name)
	}()
	var err error
	retry(t, fmt.Sprintf("Upload %q", name), func() error {
		node, err = session.UploadFile(name, parent, "", nil)
		return err
	})
	if node == nil {
		t.Fatalf("Failed to obtain node after upload for %q", name)
	}
	return node, name, md5sum
}

// createDir creates a directory under parent
func createDir(t *testing.T, session *Mega, name string, parent *Node) (node *Node) {
	var err error
	retry(t, fmt.Sprintf("Create directory %q", name), func() error {
		node, err = session.CreateDir(name, parent)
		return err
	})
	return node
}

func fileMD5(t *testing.T, name string) string {
	file, err := os.Open(name)
	if err != nil {
		t.Fatalf("Failed to open %q: %v", name, err)
	}
	b, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("Failed to read all %q: %v", name, err)
	}
	h := md5.New()
	_, err = h.Write(b)
	if err != nil {
		t.Fatalf("Error on hash in fileMD5: %v", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestLogin(t *testing.T) {
	user, password, _ := getCredentialsOrSkip(t, Credentials)

	m := New()
	retry(t, "Login", func() error {
		return m.Login(user, password)
	})

	endSession(t, m)
}

func TestMfaLogin(t *testing.T) {
	user, password, mfa_code := getCredentialsOrSkip(t, MfaCredentials)

	m := New()
	retry(t, "MfaLogin", func() error {
		return m.MultiFactorLogin(user, password, mfa_code)
	})

	endSession(t, m)
}

func TestLogout(t *testing.T) {
	session := initSession(t)
	endSession(t, session)
}

func TestGetUser(t *testing.T) {
	session := initSession(t)
	_, err := session.GetUser()
	if err != nil {
		t.Fatal("GetUser failed", err)
	}
	endSession(t, session)
}

func TestUploadDownload(t *testing.T) {
	session := initSession(t)
	for i := range []int{0, 1} {
		if i == 0 {
			t.Log("HTTP Test")
			session.SetHTTPS(false)
		} else {
			t.Log("HTTPS Test")
			session.SetHTTPS(true)
		}

		node, name, h1 := uploadFile(t, session, 314573, session.FS.root)

		session.FS.mutex.Lock()
		phash := session.FS.root.hash
		n := session.FS.lookup[node.hash]
		if n.parent.hash != phash {
			t.Error("Parent of uploaded file mismatch")
		}
		session.FS.mutex.Unlock()

		err := session.DownloadFile(node, name, nil)
		if err != nil {
			t.Fatal("Download failed", err)
		}

		h2 := fileMD5(t, name)
		err = os.Remove(name)
		if err != nil {
			t.Error("Failed to remove file", err)
		}

		if h1 != h2 {
			t.Error("MD5 mismatch for downloaded file")
		}
	}
	session.SetHTTPS(false)
	endSession(t, session)
}

func TestMove(t *testing.T) {
	session := initSession(t)
	node, _, _ := uploadFile(t, session, 31, session.FS.root)

	hash := node.hash
	phash := session.FS.trash.hash
	err := session.Move(node, session.FS.trash)
	if err != nil {
		t.Fatal("Move failed", err)
	}

	session.FS.mutex.Lock()
	n := session.FS.lookup[hash]
	if n.parent.hash != phash {
		t.Error("Move happened to wrong parent", phash, n.parent.hash)
	}
	session.FS.mutex.Unlock()

	endSession(t, session)
}

func TestRename(t *testing.T) {
	session := initSession(t)
	node, _, _ := uploadFile(t, session, 31, session.FS.root)

	err := session.Rename(node, "newname.txt")
	if err != nil {
		t.Fatal("Rename failed", err)
	}

	session.FS.mutex.Lock()
	newname := session.FS.lookup[node.hash].name
	if newname != "newname.txt" {
		t.Error("Renamed to wrong name", newname)
	}
	session.FS.mutex.Unlock()
	endSession(t, session)
}

func TestDelete(t *testing.T) {
	session := initSession(t)
	node, _, _ := uploadFile(t, session, 31, session.FS.root)

	retry(t, "Soft delete", func() error {
		return session.Delete(node, false)
	})

	session.FS.mutex.Lock()
	node = session.FS.lookup[node.hash]
	if node.parent != session.FS.trash {
		t.Error("Expects file to be moved to trash")
	}
	session.FS.mutex.Unlock()

	retry(t, "Hard delete", func() error {
		return session.Delete(node, true)
	})

	time.Sleep(1 * time.Second) // wait for the event

	session.FS.mutex.Lock()
	if _, ok := session.FS.lookup[node.hash]; ok {
		t.Error("Expects file to be dissapeared")
	}
	session.FS.mutex.Unlock()
	endSession(t, session)
}

func TestGetUserSessions(t *testing.T) {
	session := initSession(t)
	_, err := session.GetUserSessions()
	if err != nil {
		t.Fatal("GetUserSessions failed", err)
	}
	endSession(t, session)
}

func TestCreateDir(t *testing.T) {
	session := initSession(t)
	node := createDir(t, session, "testdir1", session.FS.root)
	node2 := createDir(t, session, "testdir2", node)

	session.FS.mutex.Lock()
	nnode2 := session.FS.lookup[node2.hash]
	if nnode2.parent.hash != node.hash {
		t.Error("Wrong directory parent")
	}
	session.FS.mutex.Unlock()
	endSession(t, session)
}

func TestConfig(t *testing.T) {
	user, password, mfa_code := getCredentialsOrSkip(t, AnyCredentials)

	m := New()
	m.SetAPIUrl("http://invalid.domain")
	err := func() error {
		if mfa_code != "" {
			return m.MultiFactorLogin(user, password, mfa_code)
		}
		return m.Login(user, password)
	}()

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
	session := initSession(t)

	rs, err := randString(5)
	if err != nil {
		t.Fatalf("failed to make random string: %v", err)
	}
	node1 := createDir(t, session, "dir-1-"+rs, session.FS.root)
	node21 := createDir(t, session, "dir-2-1-"+rs, node1)
	node22 := createDir(t, session, "dir-2-2-"+rs, node1)
	node31 := createDir(t, session, "dir-3-1-"+rs, node21)
	node32 := createDir(t, session, "dir-3-2-"+rs, node22)
	_ = node32

	_, name1, _ := uploadFile(t, session, 31, node31)
	_, _, _ = uploadFile(t, session, 31, node31)
	_, name3, _ := uploadFile(t, session, 31, node22)

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
	endSession(t, session)
}

func TestEventNotify(t *testing.T) {
	session1 := initSession(t)
	session2 := initSession(t)

	node, _, _ := uploadFile(t, session1, 31, session1.FS.root)

	for i := 0; i < 60; i++ {
		time.Sleep(time.Second * 1)
		node = session2.FS.HashLookup(node.GetHash())
		if node != nil {
			break
		}
	}

	if node == nil {
		t.Fatal("Expects file to found in second client's FS")
	}

	retry(t, "Delete", func() error {
		return session2.Delete(node, true)
	})

	time.Sleep(time.Second * 5)
	node = session1.FS.HashLookup(node.hash)
	if node != nil {
		t.Fatal("Expects file to not-found in first client's FS")
	}
	endSession(t, session1)
	endSession(t, session2)
}

func TestExportLink(t *testing.T) {
	session := initSession(t)
	node, _, _ := uploadFile(t, session, 31, session.FS.root)

	// Don't include decryption key
	retry(t, "Failed to export link (key not included)", func() error {
		_, err := session.Link(node, false)
		return err
	})

	// Do include decryption key
	retry(t, "Failed to export link (key included)", func() error {
		_, err := session.Link(node, true)
		return err
	})
	endSession(t, session)
}

func TestWaitEvents(t *testing.T) {
	m := &Mega{}
	m.SetLogger(t.Logf)
	m.SetDebugger(t.Logf)
	var wg sync.WaitGroup
	// in the background fire the event timer after 100mS
	wg.Add(1)
	go func() {
		time.Sleep(100 * time.Millisecond)
		m.waitEventsFire()
		wg.Done()
	}()
	wait := func(d time.Duration, pb *bool) {
		e := m.WaitEventsStart()
		*pb = m.WaitEvents(e, d)
		wg.Done()
	}
	// wait for each event in a separate goroutine
	var b1, b2, b3 bool
	wg.Add(3)
	go wait(10*time.Second, &b1)
	go wait(2*time.Second, &b2)
	go wait(1*time.Millisecond, &b3)
	wg.Wait()
	if b1 != false {
		t.Errorf("Unexpected timeout for b1")
	}
	if b2 != false {
		t.Errorf("Unexpected timeout for b2")
	}
	if b3 != true {
		t.Errorf("Unexpected event for b3")
	}
	if m.waitEvents != nil {
		t.Errorf("Expecting waitEvents to be empty")
	}
	// Check nothing happens if we fire the event with no listeners
	m.waitEventsFire()
}
