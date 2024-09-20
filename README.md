# go-mega

A client library in go for mega.co.nz storage service.

An implementation of command-line utility can be found at [https://github.com/t3rm1n4l/megacmd](https://github.com/t3rm1n4l/megacmd)

[![Build Status](https://secure.travis-ci.org/t3rm1n4l/go-mega.png?branch=master)](http://travis-ci.org/t3rm1n4l/go-mega)

## What can i do with this library?

This is an API client library for MEGA storage service. Currently, the library supports the basic APIs and operations as follows:

- User login with email and password, with or without 2FA/MFA
- User login with session token
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

Please find full doc at [https://pkg.go.dev/github.com/t3rm1n4l/go-mega](https://pkg.go.dev/github.com/t3rm1n4l/go-mega)

### Testing

1. Export `MEGA_USER` and `MEGA_PASSWD` _or_ `MEGA_USER_MFA`, `MEGA_PASSWD_MFA` and `MEGA_SECRET_MFA` environment variables with your MEGA account credentials.
2. Run `go test -timeout 10m`.

    ```sh
    $ MEGA_USER_MFA=user@email.com
    $ MEGA_PASSWD_MFA="password"
    $ MEGA_SECRET_MFA="${BASE64_ENCODED_MFA_SECRET}"
    $ go test -timeout 10m
    ...
    ok      github.com/t3rm1n4l/go-mega 36.772s
    ```

A `session.txt` file will be created in the current directory with the session token during the tests.
It should be cleaned up after testing.

### TODO

- Implement APIs for public download url generation
- Implement download from public url
- Add shared user content management APIs
- Add contact list management APIs

### License

MIT
