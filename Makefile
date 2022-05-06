# Make commands for testing should have the following pattern:
# `test-{service}` should run tests that use only external-facing client functions
# `test-internal-{service}` should run all tests, including ones calling internal endpoints
# Tests that make use of internal endpoints must be prefixed "TestInternal".

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
export NONINTERNAL_PATTERN='^Test[^(Internal)]'

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
	go test -timeout 20m -v identityClient/identityClient_test.go identityClient/test_helpers_test.go identityClient/identityClient.go identityClient/api.go

# Run Internal Identity Integration Tests
test-internal-identity:
	go test -v identityClient/identityClient_test.go identityClient/identityClient_internal_test.go identityClient/test_helpers_test.go identityClient/identityClient.go identityClient/api.go

# Run Federation Identity Integration Tests
test-federation-identity:
	go test  -v  identityClient/identityClient_federation_test.go identityClient/test_helpers_test.go identityClient/identityClient.go identityClient/api.go

# Run all Storage Integration tests
test-storage:
	go test -count=1 -v storageClient/storageClient_test.go
test-storage-internal:
	go test -count=1 -v storageClient/storageClient_internal_test.go

# Run all Account-V1 Integration tests
test-account:
	go test -count=1 -v accountClient/accountClient_test.go -run ${NONINTERNAL_PATTERN}
test-internal-account:
	go test -count=1 -v accountClient/accountClient_test.go

# Run all Account-V2 Integration tests
test-account-v2:
	go test -count=1 -v accountClient/accountClientV2_test.go

# Run all Storage-V1 (PDS) Integration tests
test-pds:
	go test -count=1 -v pdsClient/pdsClient_test.go -run ${NONINTERNAL_PATTERN}
test-internal-pds:
	go test -count=1 -v pdsClient/pdsClient_test.go

# Run all KeycloakClient Integration tests
test-keycloak:
	go test -count=1 -v KeycloakClient/keycloakClient_test.go KeycloakClient/KeycloakClient.go KeycloakClient/api.go

# Run all SecureCompute integration test 
test-secure:
	go test -count=1 -v secureComputeClient/secureComputeClient_test.go secureComputeClient/secureComputeClient.go
