package signing

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof/core/record"
)

type CosignVerifyOpts struct {
	KeyPath             string
	CertificatePath     string
	CertificateIdentity string
	CertificateIssuer   string
}

var cosignLookPath = exec.LookPath
var cosignRun = func(args ...string) ([]byte, error) {
	// #nosec G204 -- executable is fixed to cosign; args are assembled from controlled flags/paths.
	cmd := exec.Command("cosign", args...)
	return cmd.CombinedOutput()
}

func SignRecordCosign(r *record.Record, keyPath string) (*record.Record, error) {
	if r == nil {
		return nil, fmt.Errorf("record is nil")
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, fmt.Errorf("cosign key path is required")
	}
	if _, err := cosignLookPath("cosign"); err != nil {
		return nil, fmt.Errorf("cosign binary not found: %w", err)
	}
	if r.Integrity.RecordHash == "" {
		h, err := record.ComputeHash(r)
		if err != nil {
			return nil, err
		}
		r.Integrity.RecordHash = h
	}

	tmpDir, err := os.MkdirTemp("", "proof-cosign-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(r.Integrity.RecordHash), 0o600); err != nil {
		return nil, err
	}

	args := []string{"sign-blob", "--key", keyPath, "--output-signature", sigPath, blobPath}
	if out, err := cosignRun(args...); err != nil {
		return nil, fmt.Errorf("cosign sign-blob failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	// #nosec G304 -- signature path is generated in process-owned temp dir.
	rawSig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	r.Integrity.Signature = "cosign:" + strings.TrimSpace(string(rawSig))
	r.Integrity.SigningKeyID = "cosign:" + filepath.Base(keyPath)
	return r, nil
}

func VerifyRecordCosign(r *record.Record, opts CosignVerifyOpts) error {
	if r == nil {
		return fmt.Errorf("record is nil")
	}
	if _, err := cosignLookPath("cosign"); err != nil {
		return fmt.Errorf("cosign binary not found: %w", err)
	}
	if !strings.HasPrefix(r.Integrity.Signature, "cosign:") {
		return fmt.Errorf("record does not contain cosign signature")
	}
	expected, err := record.ComputeHash(r)
	if err != nil {
		return err
	}
	if expected != r.Integrity.RecordHash {
		return fmt.Errorf("record hash mismatch: expected %s got %s", expected, r.Integrity.RecordHash)
	}

	tmpDir, err := os.MkdirTemp("", "proof-cosign-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(r.Integrity.RecordHash), 0o600); err != nil {
		return err
	}
	sig := strings.TrimPrefix(r.Integrity.Signature, "cosign:")
	if err := os.WriteFile(sigPath, []byte(sig), 0o600); err != nil {
		return err
	}

	args := []string{"verify-blob", "--signature", sigPath}
	if strings.TrimSpace(opts.KeyPath) != "" {
		args = append(args, "--key", opts.KeyPath)
	}
	if strings.TrimSpace(opts.CertificatePath) != "" {
		args = append(args, "--certificate", opts.CertificatePath)
	}
	if strings.TrimSpace(opts.CertificateIdentity) != "" {
		args = append(args, "--certificate-identity", opts.CertificateIdentity)
	}
	if strings.TrimSpace(opts.CertificateIssuer) != "" {
		args = append(args, "--certificate-oidc-issuer", opts.CertificateIssuer)
	}
	if strings.TrimSpace(opts.KeyPath) == "" && strings.TrimSpace(opts.CertificatePath) == "" {
		return fmt.Errorf("cosign verification requires --cosign-key or --cosign-cert")
	}
	args = append(args, blobPath)

	if out, err := cosignRun(args...); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
