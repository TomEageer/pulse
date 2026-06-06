.PHONY: build test vet fmt scan

build:
	go build -o warden ./cmd/warden

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go fmt ./...
