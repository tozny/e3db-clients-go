# Import environment file
include .env
# Source all variables in environment file
# This only runs in the make command shell
# so won't muddy up, e.g. your login shell
export $(shell sed 's/=.*//' .env)
# Require TOZNY_PLATFORM_DIR as it is needed to run test
ifndef TOZNY_PLATFORM_DIR
$(error TOZNY_PLATFORM_DIR is not set)
endif

export GO111MODULE=on

all: clean build up test down

.PHONY: build test lint clean up down restart testone

lint :
	go vet ./...
	go mod tidy

build : lint
	go build ./...

up :
	cd $(TOZNY_PLATFORM_DIR) && \
	docker-compose up -d

down :
	cd $(TOZNY_PLATFORM_DIR) && \
	docker-compose down || true

restart : down up

test : lint
	go test -count=1 -v -cover --race ./...

testone: lint
	TEST_SERVICE_API=$(serviceApi) TEST_LOGFILE=$(log) LOG_QUERIES=$(qlog) PARATEST=$(paratest) go test -v -race -count=1 ./... -run "^($(method))$$"

clean :
	go clean ./...
	go mod tidy

# target for tagging and publishing a new version of the SDK
# run like make version=X.Y.Z
version:
	git tag v${version}
	git push origin v${version}

it : lint
	go test -count=1 -v -cover --race ./... -run=TestGetToznyHostedBrokerInfo

# Run all Identity Integration tests
test-identity:
	go test  -v  identityClient/identityClient_test.go identityClient/identityClient.go identityClient/api.go 

# Run Internal Identity Integration Tests
test-intenal-identity:
	go test  -v  identityClient/identityClient_internal_test.go identityClient/identityClient.go identityClient/api.go 

# Run all Storage Integration tests
test-storage:
	go test -count=1 -v storageClient/storageClient_test.go
# Run all Account-V2 Integration tests
test-account-v2:
	go test -count=1 -v accountClient/accountClientV2_test.go
