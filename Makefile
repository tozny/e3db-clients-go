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

all: clean build test up down restart

.PHONY: build test lint clean

lint :
	go vet ./...

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

clean :
	go clean ./...
	go mod tidy
