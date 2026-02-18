BINARY := proof
GOLANGCI_LINT_VERSION := v2.0.1
GOSEC_VERSION := v2.23.0
GOVULNCHECK_VERSION := v1.1.4

.PHONY: fmt lint lint-full test build tidy contract coverage hooks prepush prepush-full test-integration test-e2e test-acceptance test-hardening test-chaos test-performance test-soak test-scenarios test-uat-local

fmt:
	gofmt -w .

lint:
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint run ./...; fi

lint-full:
	go vet ./...
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) && golangci-lint run ./...
	go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION) && gosec ./...
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) && govulncheck ./...

gotest:
	go test ./...

test: gotest

contract:
	./scripts/test_contract_exitcodes.sh

coverage:
	go test ./... -coverprofile=coverage.out
	./scripts/check_go_coverage.py coverage.out 75
	./scripts/check_go_package_coverage.py coverage.out 85 github.com/Clyra-AI/proof/core/exitcode,github.com/Clyra-AI/proof/internal/testutil
	./scripts/check_go_package_coverage.py coverage.out 75 github.com/Clyra-AI/proof/core/exitcode

build:
	go build ./cmd/$(BINARY)

tidy:
	go mod tidy

hooks:
	git config core.hooksPath .githooks

prepush:
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) test

prepush-full:
	$(MAKE) fmt
	$(MAKE) lint
	$(MAKE) test
	$(MAKE) coverage
	$(MAKE) contract
	$(MAKE) test-integration
	$(MAKE) test-e2e
	$(MAKE) test-acceptance
	$(MAKE) test-hardening
	$(MAKE) test-chaos
	$(MAKE) test-performance
	$(MAKE) test-soak
	$(MAKE) test-scenarios

test-integration:
	./scripts/test_integration.sh

test-e2e:
	./scripts/test_e2e.sh

test-acceptance:
	./scripts/test_acceptance.sh

test-hardening:
	./scripts/test_hardening.sh

test-chaos:
	./scripts/test_chaos.sh

test-performance:
	./scripts/test_performance.sh

test-soak:
	./scripts/test_soak.sh

test-scenarios:
	go test ./internal/scenarios -count=1 -tags=scenario -v

test-uat-local:
	./scripts/test_uat_local.sh
