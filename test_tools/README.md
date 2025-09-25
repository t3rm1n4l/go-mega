# HOW TO TEST

## ENV VARIABLES

- `X_MEGA_USER`: MEGA user email
- `X_MEGA_PASSWORD`: MEGA user password
- `X_MEGA_USER_AGENT`: HashcashDemo

## How to run tests

```bash
export X_MEGA_USER=<user_email>
export X_MEGA_PASSWORD=<user_passwd>
export X_MEGA_USER_AGENT=HashcashDemo
go build test_real_api.go
./test_real_api
```