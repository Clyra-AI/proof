# Scenarios

Scenario fixtures for acceptance and regression checks.

- Source of truth for expected outcomes lives in each scenario `expected.yaml`.
- Scenario tests run with `make test-scenarios`.
- Changes to expected outcomes require explicit human review (see `CODEOWNERS`).
- `cross-product-mixed-chain` and the three-record Action Contract lifecycle
  fixture are legacy synthetic/quarantined compatibility checks, not final
  released Wrkr/Gait/Axym conformance. Final imports use the explicit contract
  in `docs/fixture-import.md`.
