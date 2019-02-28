# Copyright (c) 2017 Tim Heckman
# Use of this source code is governed by the MIT License that can be found in
# the LICENSE file at the root of this repository.

test: vet lint megacheck tests

prebuild:
	go get -v -u github.com/golang/dep/cmd/dep \
		golang.org/x/lint/golint \
		honnef.co/go/tools/cmd/megacheck \
		golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow

vet:
	go vet ./...
	go vet -vettool=$(shell which shadow) ./...

lint:
	golint -set_exit_status

megacheck:
	megacheck ./...

tests:
	go test -v ./...

.PHONY: test prebuild vet lint megacheck tests
