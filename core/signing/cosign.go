package signing

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof/core/record"
)

func SignRecordCosign(r *record.Record, keyPath string) (*record.Record, error) {
	if r == nil {
		return nil, fmt.Errorf("record is nil")
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, fmt.Errorf("cosign key path is required")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
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
	defer os.RemoveAll(tmpDir)

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(r.Integrity.RecordHash), 0o600); err != nil {
		return nil, err
	}

	cmd := exec.Command("cosign", "sign-blob", "--key", keyPath, "--output-signature", sigPath, blobPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("cosign sign-blob failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	rawSig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	r.Integrity.Signature = "cosign:" + strings.TrimSpace(string(rawSig))
	r.Integrity.SigningKeyID = "cosign:" + filepath.Base(keyPath)
	return r, nil
}

func VerifyRecordCosign(r *record.Record, keyPath string) error {
	if r == nil {
		return fmt.Errorf("record is nil")
	}
	if strings.TrimSpace(keyPath) == "" {
		return fmt.Errorf("cosign key path is required")
	}
	if _, err := exec.LookPath("cosign"); err != nil {
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
	defer os.RemoveAll(tmpDir)

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(r.Integrity.RecordHash), 0o600); err != nil {
		return err
	}
	sig := strings.TrimPrefix(r.Integrity.Signature, "cosign:")
	if err := os.WriteFile(sigPath, []byte(sig), 0o600); err != nil {
		return err
	}

	cmd := exec.Command("cosign", "verify-blob", "--key", keyPath, "--signature", sigPath, blobPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cosign verify-blob failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
