build:
	go build

test:
	go test -cpu 4 -v -race -args -https=0
	go test -cpu 4 -v -race -args -https=1

# Get the build dependencies
build_dep:
	go get -u github.com/kisielk/errcheck
	go get -u golang.org/x/tools/cmd/goimports
	-#go get -u github.com/golang/lint/golint

# Do source code quality checks
check:
	go vet
	errcheck
	goimports -d . | grep . ; test $$? -eq 1
	-#golint
