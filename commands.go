package mega

type APICommand string

const (
	COMMAND_PRELOGIN APICommand = "us0"
	COMMAND_LOGIN APICommand = "us"
    COMMAND_LOGOUT APICommand = "sml"
	COMMAND_GET_USER APICommand = "ug"
	COMMAND_GET_USER_QUOTA APICommand = "uq"
	COMMAND_FILES APICommand = "f"
	COMMAND_DOWNLOAD APICommand = "g"
	COMMAND_UPLOAD APICommand = "u"
	COMMAND_UPLOAD_COMPLETE APICommand = "p"
	COMMAND_MOVE APICommand = "m"
	COMMAND_RENAME APICommand = "a"
	COMMAND_DELETE APICommand = "d"
	COMMAND_GET_LINK APICommand = "l"
)
