#!/bin/sh
echo Running all tests

go test -count=1 -v -timeout 99999s -cover --race ./... -json | go-test-report -t 'E3DB Clients Test Report' -o /data/e3db-test-report.html