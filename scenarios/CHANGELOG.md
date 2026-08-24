# Scenario Changelog

## 2026-08-24

- Added: action-contract-lifecycle-conformance (validates pinned Wrkr/Gait/Axym lifecycle integrity, fixture-authority quarantine, and evidence-set determinism)

## 2026-02-20

- Added: compiled-action-chain-round-trip (validates compiled_action record verification in chain mode)

## 2026-02-18

- Added: chain-round-trip (validates basic chain append + verify)
- Added: chain-tamper-detection (validates integrity break on modified record)
- Added: signing-verify-round-trip (validates Ed25519 sign + verify cycle)
- Added: schema-validation-reject (validates exit code 6 on invalid input)
- Added: cross-product-mixed-chain (validates mixed-source chain integrity)
- Author: @davidahmann
