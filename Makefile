# Copyright (c) 2017, 2019 Tim Heckman
# Use of this source code is governed by the MIT License that can be found in
# the LICENSE file at the root of this repository.

test: vet staticcheck tests

vet:
	go vet ./...

staticcheck:
	staticcheck ./...

tests:
	go test -race -covermode atomic -cover -coverprofile profile.out ./...
	go tool cover -func=profile.out

.PHONY: test vet staticcheck tests
