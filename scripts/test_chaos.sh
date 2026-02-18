#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
go test ./core/chain -run 'Test(VerifyRangeUsesFullChainIntegrity|VerifyNilAndHeadMismatch)' -count=3
