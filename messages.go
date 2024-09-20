package mega

import "encoding/json"

type PreloginMsg struct {
	Cmd  APICommand `json:"a"`
	User string `json:"user"`
}

type PreloginResp struct {
	Version int    `json:"v"`
	Salt    string `json:"s"`
}

type LoginMsg struct {
	Cmd        APICommand `json:"a"`
	User       string `json:"user"`
	Handle     string `json:"uh"`
	SessionKey string `json:"sek,omitempty"`
	Si         string `json:"si,omitempty"`
	Mfa        string `json:"mfa,omitempty"`
}

type LoginResp struct {
	Csid       string `json:"csid"`
	Privk      string `json:"privk"`
	Key        string `json:"k"`
	Ach        int    `json:"ach"`
	SessionKey string `json:"sek"`
	U          string `json:"u"`
}

type SessionLoginMsg struct {
	Cmd        APICommand `json:"a"`
	Sek string `json:"sek"`
}

type SessionLoginResp struct {
	Privk      string `json:"privk"`
	Ach        int    `json:"ach"`
	SessionKey string `json:"sek"`
	U          string `json:"u"`
}

type LogoutMsg struct {
	// "a" should be "sml" for logout
	Cmd APICommand `json:"a"`
}

type UserMsg struct {
	Cmd APICommand `json:"a"`
}

type UserResp struct {
	U     string `json:"u"`
	S     int    `json:"s"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Key   string `json:"k"`
	C     int    `json:"c"`
	Pubk  string `json:"pubk"`
	Privk string `json:"privk"`
	Terms string `json:"terms"`
	TS    string `json:"ts"`
}

type QuotaMsg struct {
	// Action, should be "uq" for quota request
	Cmd APICommand `json:"a"`
	// xfer should be 1
	Xfer int `json:"xfer"`
	// Without strg=1 only reports total capacity for account
	Strg int `json:"strg,omitempty"`
}

type QuotaResp struct {
	// Mstrg is total capacity in bytes
	Mstrg uint64 `json:"mstrg"`
	// Cstrg is used capacity in bytes
	Cstrg uint64 `json:"cstrg"`
	// Per folder usage in bytes?
	Cstrgn map[string][]int64 `json:"cstrgn"`
}

type FilesMsg struct {
	Cmd APICommand `json:"a"`
	C   int    `json:"c"`
}

type FSNode struct {
	Hash   string `json:"h"`
	Parent string `json:"p"`
	User   string `json:"u"`
	T      int    `json:"t"`
	Attr   string `json:"a"`
	Key    string `json:"k"`
	Ts     int64  `json:"ts"`
	SUser  string `json:"su"`
	SKey   string `json:"sk"`
	Sz     int64  `json:"s"`
}

type FilesResp struct {
	F []FSNode `json:"f"`

	Ok []struct {
		Hash string `json:"h"`
		Key  string `json:"k"`
	} `json:"ok"`

	S []struct {
		Hash string `json:"h"`
		User string `json:"u"`
	} `json:"s"`
	User []struct {
		User  string `json:"u"`
		C     int    `json:"c"`
		Email string `json:"m"`
	} `json:"u"`
	Sn string `json:"sn"`
}

type FileAttr struct {
	Name string `json:"n"`
}

type GetLinkMsg struct {
	Cmd APICommand `json:"a"`
	N   string `json:"n"`
}

type DownloadMsg struct {
	Cmd APICommand `json:"a"`
	G   int    `json:"g"`
	P   string `json:"p,omitempty"`
	N   string `json:"n,omitempty"`
	SSL int    `json:"ssl,omitempty"`
}

type DownloadResp struct {
	G    string   `json:"g"`
	Size uint64   `json:"s"`
	Attr string   `json:"at"`
	Err  ErrorMsg `json:"e"`
}

type UploadMsg struct {
	Cmd APICommand `json:"a"`
	S   int64  `json:"s"`
	SSL int    `json:"ssl,omitempty"`
}

type UploadResp struct {
	P string `json:"p"`
}

type UploadCompleteMsg struct {
	Cmd APICommand `json:"a"`
	T   string `json:"t"`
	N   [1]struct {
		H string `json:"h"`
		T int    `json:"t"`
		A string `json:"a"`
		K string `json:"k"`
	} `json:"n"`
	I string `json:"i,omitempty"`
}

type UploadCompleteResp struct {
	F []FSNode `json:"f"`
}

type FileInfoMsg struct {
	Cmd APICommand `json:"a"`
	F   int    `json:"f"`
	P   string `json:"p"`
}

type MoveFileMsg struct {
	Cmd APICommand `json:"a"`
	N   string `json:"n"`
	T   string `json:"t"`
	I   string `json:"i"`
}

type FileAttrMsg struct {
	Cmd  APICommand `json:"a"`
	Attr string `json:"attr"`
	Key  string `json:"key"`
	N    string `json:"n"`
	I    string `json:"i"`
}

type FileDeleteMsg struct {
	Cmd APICommand `json:"a"`
	N   string `json:"n"`
	I   string `json:"i"`
}

type GetUserSessionsMsg struct {
	Cmd APICommand `json:"a"`
	IdAndAliveInfo   int    `json:"x"`
	DeviceIDInfo   int    `json:"d"`
}

type GetUserSessionsResp struct {
	DateTime int
	Unused int
	UserAgent string
	IPAddress string
	Country string
	IsCurrent int
	SessionID string
	IsActive int
	DeviceID int
}

type getUserSessionsError struct {
	message string
}

func (e *getUserSessionsError) Error() string {
	return e.message
}

func (n *GetUserSessionsResp) UnmarshalJSON(buf []byte) error {
	tmp := []interface{}{&n.DateTime, &n.Unused, &n.UserAgent, &n.IPAddress, &n.Country, &n.IsCurrent, &n.SessionID, &n.IsActive, &n.DeviceID}
	wantLen := len(tmp)
	if err := json.Unmarshal(buf, &tmp); err != nil {
		return err
	}
	if g, e := len(tmp), wantLen; g != e {
		return &getUserSessionsError{message: "wrong number of fields in GetUserSessionsResp"}
	}
	return nil
}

// GenericEvent is a generic event for parsing the Cmd type before
// decoding more specifically
type GenericEvent struct {
	GEventType string `json:"a"`
}

// FSEvent - event for various file system events
//
// Delete (a=d)
// Update attr (a=u)
// New nodes (a=t)
type FSEvent struct {
	FSEventType string `json:"a"`

	T struct {
		Files []FSNode `json:"f"`
	} `json:"t"`
	Owner string `json:"ou"`

	N    string `json:"n"`
	User string `json:"u"`
	Attr string `json:"at"`
	Key  string `json:"k"`
	Ts   int64  `json:"ts"`
	I    string `json:"i"`
}

// Events is received from a poll of the server to read the events
//
// Each event can be an error message or a different field so we delay
// decoding
type Events struct {
	W  string            `json:"w"`
	Sn string            `json:"sn"`
	E  []json.RawMessage `json:"a"`
}
