VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")

.PHONY: build build-linux

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o lss-backup-server ./cmd/server

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o lss-backup-server ./cmd/server
