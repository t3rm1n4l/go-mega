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

func retrySetup(what string, fn func() error) {
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
		fmt.Printf("%s failed %d/%d - retrying after %v sleep", what, i, maxTries, sleep)
		time.Sleep(sleep)
		sleep *= 2
	}
	fmt.Printf("%s failed: %v", what, err)
	os.Exit(1)
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
func getCredentialsOrSkip(credentialsType CredentialType) (string, string, string, error) {

	switch credentialsType {
	case Credentials:
		user, password, err := getCredentials()
		if err != nil {
			return "", "", "", fmt.Errorf("Skipping test due to credentials error: %v", err)
		}
		return user, password, "", nil
	case MfaCredentials:
		user, password, mfa_code, err := getMfaCredentials()
		if err != nil {

			return "", "", "", fmt.Errorf("Skipping test due to credentials error: %v", err)
		}
		return user, password, mfa_code, nil
	case AnyCredentials:
		user, password, err := getCredentials()
		if err != nil {
			fmt.Printf("Trying with MFA credentials instead, getting other credentials failed with error: %v", err)
		} else {
			return user, password, "", nil
		}
		user, password, mfa_code, err := getMfaCredentials()
		if err != nil {

			return "", "", "", fmt.Errorf("Skipping test due to credentials error: %v", err)
		}
		return user, password, mfa_code, nil
	default:
		return "", "", "", fmt.Errorf("Invalid credentials type")
	}
}

func trySessionLogin(m *Mega, mandatory bool) error {
	if _, err := os.Stat("session.txt"); err == nil {
		session_file, err := os.ReadFile("session.txt")
		if err != nil {
			return fmt.Errorf("Error reading session file")
		} else {
			session := string(session_file)
			err = m.SessionLogin(session)
			if err != nil {
				return fmt.Errorf("can't perform session login")
			}
			fmt.Printf("Using session: %s\n", session)
			return nil
		}
	}
	if (mandatory){
	return fmt.Errorf("Session file not found")
	}
	return nil
}

func setup() error {

	m := New()

	err := trySessionLogin(m, false)
	if err != nil {
		return err
	}

	user, password, mfa_code, err := getCredentialsOrSkip(AnyCredentials)
	if err != nil {
		return fmt.Errorf("error getting credentials for login")
	}
	retrySetup("Login", func() error {
		if mfa_code != "" {
			return m.MultiFactorLogin(user, password, mfa_code)
		}
		return m.Login(user, password)
	})

	// dump session to file
	session, err := m.DumpSession()
	if err != nil {
		return fmt.Errorf("Error dumping session")
	}
	fmt.Printf("Using session: %s\n", session)
	err = os.WriteFile("session.txt", []byte(session), 0644)
	if err != nil {
		return fmt.Errorf("Error writing session file")
	}

	return nil
}

func teardown() error{

	fmt.Println("Logging out and removing session file.")

	m := New()
	err := trySessionLogin(m, true)
	if err != nil {
		return err
	}

	retrySetup("Logout", func() error {
		return m.Logout()
	})
	_ = os.Remove("session.txt")
	return nil
}

func TestMain(m *testing.M) {
	err:=setup()
	if err != nil {
		os.Exit(1)
	}
	exitCode := m.Run()
	err=teardown()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(exitCode)
}

func initTest(t *testing.T) *Mega {
	m := New()

	err := trySessionLogin(m, true)
	if err != nil {
		t.Fatal(err)
	}

	return m
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

func TestGetUser(t *testing.T) {
	m := initTest(t)
	_, err := m.GetUser()
	if err != nil {
		t.Fatal("GetUser failed", err)
	}
}

func TestUploadDownload(t *testing.T) {
	m := initTest(t)
	for i := range []int{0, 1} {
		if i == 0 {
			t.Log("HTTP Test")
			m.SetHTTPS(false)
		} else {
			t.Log("HTTPS Test")
			m.SetHTTPS(true)
		}

		node, name, h1 := uploadFile(t, m, 314573, m.FS.root)

		m.FS.mutex.Lock()
		phash := m.FS.root.hash
		n := m.FS.lookup[node.hash]
		if n.parent.hash != phash {
			t.Error("Parent of uploaded file mismatch")
		}
		m.FS.mutex.Unlock()

		err := m.DownloadFile(node, name, nil)
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
	m.SetHTTPS(false)
}

func TestMove(t *testing.T) {
	m := initTest(t)
	node, _, _ := uploadFile(t, m, 31, m.FS.root)

	hash := node.hash
	phash := m.FS.trash.hash
	err := m.Move(node, m.FS.trash)
	if err != nil {
		t.Fatal("Move failed", err)
	}

	m.FS.mutex.Lock()
	n := m.FS.lookup[hash]
	if n.parent.hash != phash {
		t.Error("Move happened to wrong parent", phash, n.parent.hash)
	}
	m.FS.mutex.Unlock()
}

func TestRename(t *testing.T) {
	m := initTest(t)
	node, _, _ := uploadFile(t, m, 31, m.FS.root)

	err := m.Rename(node, "newname.txt")
	if err != nil {
		t.Fatal("Rename failed", err)
	}

	m.FS.mutex.Lock()
	newname := m.FS.lookup[node.hash].name
	if newname != "newname.txt" {
		t.Error("Renamed to wrong name", newname)
	}
	m.FS.mutex.Unlock()
}

func TestDelete(t *testing.T) {
	m := initTest(t)
	node, _, _ := uploadFile(t, m, 31, m.FS.root)

	retry(t, "Soft delete", func() error {
		return m.Delete(node, false)
	})

	m.FS.mutex.Lock()
	node = m.FS.lookup[node.hash]
	if node.parent != m.FS.trash {
		t.Error("Expects file to be moved to trash")
	}
	m.FS.mutex.Unlock()

	retry(t, "Hard delete", func() error {
		return m.Delete(node, true)
	})

	time.Sleep(1 * time.Second) // wait for the event

	m.FS.mutex.Lock()
	if _, ok := m.FS.lookup[node.hash]; ok {
		t.Error("Expects file to be dissapeared")
	}
	m.FS.mutex.Unlock()
}

func TestGetUserSessions(t *testing.T) {
	m := initTest(t)
	_, err := m.GetUserSessions()
	if err != nil {
		t.Fatal("GetUserSessions failed", err)
	}
}

func TestCreateDir(t *testing.T) {
	m := initTest(t)
	node := createDir(t, m, "testdir1", m.FS.root)
	node2 := createDir(t, m, "testdir2", node)

	m.FS.mutex.Lock()
	nnode2 := m.FS.lookup[node2.hash]
	if nnode2.parent.hash != node.hash {
		t.Error("Wrong directory parent")
	}
	m.FS.mutex.Unlock()
}

func TestConfig(t *testing.T) {
	user, password, mfa_code := "foo", "bar", "012345"

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
	m := initTest(t)

	rs, err := randString(5)
	if err != nil {
		t.Fatalf("failed to make random string: %v", err)
	}
	node1 := createDir(t, m, "dir-1-"+rs, m.FS.root)
	node21 := createDir(t, m, "dir-2-1-"+rs, node1)
	node22 := createDir(t, m, "dir-2-2-"+rs, node1)
	node31 := createDir(t, m, "dir-3-1-"+rs, node21)
	node32 := createDir(t, m, "dir-3-2-"+rs, node22)
	_ = node32

	_, name1, _ := uploadFile(t, m, 31, node31)
	_, _, _ = uploadFile(t, m, 31, node31)
	_, name3, _ := uploadFile(t, m, 31, node22)

	testpaths := [][]string{
		{"dir-1-" + rs, "dir-2-2-" + rs, path.Base(name3)},
		{"dir-1-" + rs, "dir-2-1-" + rs, "dir-3-1-" + rs},
		{"dir-1-" + rs, "dir-2-1-" + rs, "dir-3-1-" + rs, path.Base(name1)},
		{"dir-1-" + rs, "dir-2-1-" + rs, "none"},
	}

	results := []error{nil, nil, nil, ENOENT}

	for i, tst := range testpaths {
		ns, e := m.FS.PathLookup(m.FS.root, tst)
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

func TestEventNotify(t *testing.T) {
	t.Skipf("TODO: reimplement this test")

	session1 := initTest(t)
	session2 := initTest(t)

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
}

func TestExportLink(t *testing.T) {
	m := initTest(t)
	node, _, _ := uploadFile(t, m, 31, m.FS.root)

	// Don't include decryption key
	retry(t, "Failed to export link (key not included)", func() error {
		_, err := m.Link(node, false)
		return err
	})

	// Do include decryption key
	retry(t, "Failed to export link (key included)", func() error {
		_, err := m.Link(node, true)
		return err
	})
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
