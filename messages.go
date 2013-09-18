package mega

type LoginMsg struct {
	Cmd    string `json:"a"`
	User   string `json:"user"`
	Handle string `json:"uh"`
}

type LoginResp struct {
	Csid  string `json:"csid"`
	Privk string `json:"privk"`
	Key   string `json:"k"`
}

type UserMsg struct {
	Cmd string `json:"a"`
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
	Terms string `json: "terms"`
	TS    string `json:"ts"`
}

type FilesMsg struct {
	Cmd string `json:"a"`
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
	Cmd string `json:"a"`
	N   string `json:"n"`
}

type DownloadMsg struct {
	Cmd string `json:"a"`
	G   int    `json:"g"`
	P   string `json:"p,omitempty"`
	N   string `json:"n,omitempty"`
}

type DownloadResp struct {
	G    string `json:"g"`
	Size uint64 `json:"s"`
	Attr string `json:"at"`
	Err  uint32 `json:"e"`
}

type UploadMsg struct {
	Cmd string `json:"a"`
	S   int64  `json:"s"`
}

type UploadResp struct {
	P string `json:"p"`
}

type UploadCompleteMsg struct {
	Cmd string `json:"a"`
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
	Cmd string `json:"a"`
	F   int    `json:"f"`
	P   string `json:"p"`
}

type MoveFileMsg struct {
	Cmd string `json:"a"`
	N   string `json:"n"`
	T   string `json:"t"`
	I   string `json:"i"`
}

type FileAttrMsg struct {
	Cmd  string `json:"a"`
	Attr string `json:"attr"`
	Key  string `json:"key"`
	N    string `json:"n"`
	I    string `json:"i"`
}

type FileDeleteMsg struct {
	Cmd string `json:"a"`
	N   string `json:"n"`
	I   string `json:"i"`
}

type Event struct {
	Cmd string `json:"a"`
	/*
		// Delete (a=d)
		delEvent
		// Update attr (a=u)
		updateEvent
		// New nodes (a=t)
		createEvent
	*/
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

type EventMsg struct {
	W  string  `json:"w"`
	Sn string  `json:"sn"`
	E  []Event `json:"a"`
}
