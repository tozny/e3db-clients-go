export GO111MODULE=on

all: clean build test

.PHONY: build test lint clean

lint :
	go vet ./...

build : lint
	go build ./...

test : lint
	go test -count=1 -v -cover --race ./...

clean :
	go clean ./...
	go mod tidy
