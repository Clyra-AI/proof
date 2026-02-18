# Proof

`github.com/Clyra-AI/proof` is the shared primitive for tamper-evident governance records.

## Scope

- Deterministic record creation
- Hash-chain append/verification
- Ed25519 signing/verification
- Offline verification CLI
- JSON Schemas and framework definition assets

## Build

```bash
go build ./cmd/proof
```

## CLI

```bash
proof verify <path>
proof verify --chain <path>
proof verify --signatures --public-key <hex-ed25519-pub> <path>
proof verify --signatures --cosign-key <cosign-pub-key-path> <path>
proof verify --revocation-list ./revocations.json --revocation-key <hex-ed25519-pub> <path>
proof chain verify --from 2026-01-01T00:00:00Z --to 2026-12-31T23:59:59Z <path>
proof inspect <path>
proof types list
proof types validate ./custom.schema.json
proof frameworks list
proof frameworks show eu-ai-act
```

## Exit Codes

- `0` success
- `1` internal/runtime failure
- `2` verification failure
- `3` policy/schema violation
- `4` approval required
- `5` regression drift detected
- `6` invalid input
- `7` dependency missing
- `8` unsafe operation blocked

## API Quickstart

```go
record, _ := proof.NewRecord(proof.RecordOpts{
  Source: "example",
  SourceProduct: "third-party",
  Type: "tool_invocation",
  Event: map[string]any{"tool":"postgres_query"},
})

chain := proof.NewChain("default")
_ = proof.AppendToChain(chain, record)
key, _ := proof.GenerateSigningKey()
_, _ = proof.Sign(&chain.Records[0], key)
_, _ = proof.VerifyChain(chain)
sig, _ := proof.SignChain(chain, key)
_ = proof.VerifyChainSignature(chain, sig, proof.PublicKey{Public: key.Public})
```
