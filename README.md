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

## Install

Current stable install path (works now):

```bash
go install github.com/Clyra-AI/proof/cmd/proof@latest
```

Binary location:

- If `GOBIN` is set: `$(go env GOBIN)/proof`
- Otherwise: `$(go env GOPATH)/bin/proof` (typically `~/go/bin/proof`)

Tagged release install path (enabled by `.github/workflows/release.yml` on `v*.*.*` tags; assets appear after the first release tag):

```bash
# Option A: GitHub CLI (recommended for release assets)
gh release download vX.Y.Z -R Clyra-AI/proof -D /tmp/proof-release

# Option B: curl (direct asset URLs)
curl -fL -o /tmp/proof-release/proof.tar.gz \
  https://github.com/Clyra-AI/proof/releases/download/vX.Y.Z/proof_X.Y.Z_<os>_<arch>.tar.gz
curl -fL -o /tmp/proof-release/checksums.txt \
  https://github.com/Clyra-AI/proof/releases/download/vX.Y.Z/checksums.txt
```

Verify release artifacts:

```bash
cd /tmp/proof-release
sha256sum -c checksums.txt

# Optional (if provided in the release and cosign is installed):
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

Then place `proof` on your PATH (for example `/usr/local/bin` or `~/.local/bin`).

## CLI

```bash
proof verify <path>
proof verify --chain <path>
proof verify --signatures --public-key <hex-or-base64-ed25519-pub> <path>
proof verify --signatures --cosign-key <cosign-pub-key-path> <path>
proof verify --signatures --cosign-cert ./checksums.pem --cosign-cert-identity <identity> --cosign-cert-issuer <issuer> <path>
proof verify --revocation-list ./revocations.json --revocation-key <hex-ed25519-pub> <path>
proof chain verify --from 2026-01-01T00:00:00Z --to 2026-12-31T23:59:59Z <path>
proof inspect <path>
proof types list
proof types validate ./custom.schema.json
proof frameworks list
proof frameworks show eu-ai-act
```

Gait compatibility:

```bash
proof verify ./gait-pack.zip
proof verify ./gait-runpack.zip
proof verify --signatures --public-key <hex-or-base64-ed25519-pub> ./gait-pack.zip
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
