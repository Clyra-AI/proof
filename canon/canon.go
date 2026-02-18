package canon

import corecanon "github.com/Clyra-AI/proof/core/canon"

// CanonicalizeJSON returns RFC 8785 canonical JSON bytes.
func CanonicalizeJSON(input []byte) ([]byte, error) {
	return corecanon.Canonicalize(input, corecanon.DomainJSON)
}

// DigestJCS canonicalizes JSON and returns a sha256 hex digest.
func DigestJCS(input []byte) (string, error) {
	return corecanon.DigestHex(input, corecanon.DomainJSON)
}
