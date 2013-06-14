go-mega
=======

A client library in go for mega.co.nz storage service.

An implementation of command-line utility can be found at [https://github.com/t3rm1n4l/megacmd](https://github.com/t3rm1n4l/megacmd)

[![Build Status](https://secure.travis-ci.org/t3rm1n4l/go-mega.png?branch=master)](http://travis-ci.org/t3rm1n4l/go-mega)

### What can i do with this library?
This is an API client library for MEGA storage service. Currently, the library supports the basic APIs and operations as follows:
  - User login
  - Fetch filesystem tree
  - Upload file
  - Download file
  - Create directory
  - Move file or directory
  - Rename file or directory
  - Delete file or directory
  - Parallel split download and upload
  - Filesystem events auto sync
  - Unit tests

### API methods

Please find full doc at [http://godoc.org/github.com/t3rm1n4l/go-mega](http://godoc.org/github.com/t3rm1n4l/go-mega)

    type Mega struct {

        // Filesystem object
        FS *MegaFS
        // contains filtered or unexported fields
    }


    func New() *Mega


    func (m *Mega) CreateDir(name string, parent *Node) (*Node, error)
        Create a directory in the filesystem

    func (m *Mega) Delete(node *Node, destroy bool) error
        Delete a file or directory from filesystem

    func (m Mega) DownloadFile(src *Node, dstpath string, progress *chan int) error
        Download file from filesystem

    func (m Mega) GetUser() (UserResp, error)
        Get user information

    func (m *Mega) Login(email string, passwd string) error
        Authenticate and start a session

    func (m *Mega) Move(src *Node, parent *Node) error
        Move a file from one location to another

    func (m *Mega) Rename(src *Node, name string) error
        Rename a file or folder

    func (c *Mega) SetAPIUrl(u string)
        Set mega service base url

    func (c *Mega) SetDownloadWorkers(w int) error
        Set concurrent download workers

    func (c *Mega) SetRetries(r int)
        Set number of retries for api calls

    func (c *Mega) SetTimeOut(t time.Duration)
        Set connection timeout

    func (c *Mega) SetUploadWorkers(w int) error
        Set concurrent upload workers

    func (m *Mega) UploadFile(srcpath string, parent *Node, name string, progress *chan int) (*Node, error)
        Upload a file to the filesystem


    type MegaFS struct {
        // contains filtered or unexported fields
    }
        Mega filesystem object


    func (fs MegaFS) GetChildren(n *Node) ([]*Node, error)
        Get the list of child nodes for a given node

    func (fs MegaFS) GetInbox() *Node
        Get inbox node

    func (fs MegaFS) GetRoot() *Node
        Get filesystem root node

    func (fs MegaFS) GetSharedRoots() []*Node
        Get top level directory nodes shared by other users

    func (fs MegaFS) GetTrash() *Node
        Get filesystem trash node

    func (fs MegaFS) HashLookup(h string) *Node
        Get a node pointer from its hash

    func (fs MegaFS) PathLookup(root *Node, ns []string) ([]*Node, error)
        Retreive all the nodes in the given node tree path by name This method
        returns array of nodes upto the matched subpath (in same order as input
        names array) even if the target node is not located.


    type Node struct {
        // contains filtered or unexported fields
    }
        Filesystem node


    func (n Node) GetName() string

    func (n Node) GetSize() int64

    func (n Node) GetTimeStamp() time.Time

    func (n Node) GetType() int

### TODO
  - Implement APIs for public download url generation
  - Implement download from public url
  - Add shared user content management APIs
  - Add contact list management APIs

### License

MIT
