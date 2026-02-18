BINARY := proof

.PHONY: fmt lint test build tidy contract

fmt:
	gofmt -w .

lint:
	go vet ./...

gotest:
	go test ./...

test: gotest

contract:
	./scripts/test_contract_exitcodes.sh

build:
	go build ./cmd/$(BINARY)

tidy:
	go mod tidy
