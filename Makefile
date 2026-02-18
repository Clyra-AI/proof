BINARY := proof

.PHONY: fmt lint test build tidy

fmt:
	gofmt -w .

lint:
	go vet ./...

gotest:
	go test ./...

test: gotest

build:
	go build ./cmd/$(BINARY)

tidy:
	go mod tidy
