export GO111MODULE=on

all: build test

.PHONY: build test lint

lint :
	go vet ./...
	go mod tidy

build : lint
	go build ./...

test : lint
	go test -count=1 -v -cover --race ./...
