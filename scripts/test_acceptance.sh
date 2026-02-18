#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./scripts/test_contract_exitcodes.sh
go test ./cmd/proof -run 'Test(CLIVerifyChain|ExitCode|VerifyRecordCommand|FrameworksListCommand)' -count=1
