go-mega
=======

A client library in go for mega.co.nz storage service

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
  - Unit tests

### API methods
    type Mega struct {

        // Filesystem object
        FS *MegaFS
        // contains filtered or unexported fields
    }


    func New() *Mega


    func (m *Mega) AddFSNode(itm FSNode) (*Node, error)
        Add a node into filesystem

    func (m Mega) CreateDir(name string, parent *Node) (*Node, error)
        Create a directory in the filesystem

    func (m Mega) Delete(node *Node, destroy bool) error
        Delete a file or directory from filesystem

    func (m Mega) DownloadFile(src *Node, dstpath string) error
        Download file from filesystem

    func (m *Mega) GetFileSystem() error
        Get all nodes from filesystem

    func (m Mega) GetUser() (UserResp, error)
        Get user information

    func (m *Mega) Login(email string, passwd string) error
        Authenticate and start a session

    func (m Mega) Move(src *Node, parent *Node) error
        Move a file from one location to another

    func (m Mega) Rename(src *Node, name string) error
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

    func (m Mega) UploadFile(srcpath string, parent *Node) (*Node, error)
        Upload a file to the filesystem


    type MegaFS struct {
        // contains filtered or unexported fields
    }
        Mega filesystem object


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
        
### TODO
  - Implement APIs for public download url generation
  - Implement download from public url
  - Improve usability of API and design
  - Add shared user content management APIs
  - Add contact list management APIs
