package signing

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	coreerr "github.com/Clyra-AI/proof/core/errors"
	"github.com/Clyra-AI/proof/core/record"
)

type CosignVerifyOpts struct {
	KeyPath             string
	CertificatePath     string
	CertificateIdentity string
	CertificateIssuer   string
}

var ErrDependencyMissing = errors.New("dependency missing")

var cosignLookPath = exec.LookPath
var cosignRun = func(args ...string) ([]byte, error) {
	// #nosec G204 -- executable is fixed to cosign; args are assembled from controlled flags/paths.
	cmd := exec.Command("cosign", args...)
	return cmd.CombinedOutput()
}

func IsDependencyMissing(err error) bool {
	if typed, ok := coreerr.As(err); ok && typed.Kind == coreerr.KindDependencyMissing {
		return true
	}
	return errors.Is(err, ErrDependencyMissing)
}

func SignRecordCosign(r *record.Record, keyPath string) (*record.Record, error) {
	if r == nil {
		return nil, coreerr.New(coreerr.KindInvalidInput, "signing.record_nil", "record is nil", coreerr.WithField("record"))
	}
	if strings.TrimSpace(keyPath) == "" {
		return nil, coreerr.New(coreerr.KindInvalidInput, "signing.cosign.key_path_required", "cosign key path is required", coreerr.WithField("key_path"))
	}
	if r.Integrity.RecordHash == "" {
		h, err := record.ComputeHash(r)
		if err != nil {
			return nil, err
		}
		r.Integrity.RecordHash = h
	}
	sig, err := SignDigestCosign(r.Integrity.RecordHash, keyPath)
	if err != nil {
		return nil, err
	}
	r.Integrity.Signature = "cosign:" + sig.Sig
	r.Integrity.SigningKeyID = sig.KeyID
	return r, nil
}

func SignDigestCosign(digest string, keyPath string) (Signature, error) {
	if strings.TrimSpace(keyPath) == "" {
		return Signature{}, coreerr.New(coreerr.KindInvalidInput, "signing.cosign.key_path_required", "cosign key path is required", coreerr.WithField("key_path"))
	}
	if _, err := cosignLookPath("cosign"); err != nil {
		return Signature{}, coreerr.Wrap(
			coreerr.KindDependencyMissing,
			"signing.cosign.binary_missing",
			"cosign binary not found",
			fmt.Errorf("%w: %v", ErrDependencyMissing, err),
		)
	}
	tmpDir, err := os.MkdirTemp("", "proof-cosign-")
	if err != nil {
		return Signature{}, err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(digest), 0o600); err != nil {
		return Signature{}, err
	}

	args := []string{"sign-blob", "--key", keyPath, "--output-signature", sigPath, blobPath}
	if out, err := cosignRun(args...); err != nil {
		return Signature{}, coreerr.New(
			coreerr.KindVerification,
			"signing.cosign.sign_blob_failed",
			fmt.Sprintf("cosign sign-blob failed: %v (%s)", err, strings.TrimSpace(string(out))),
		)
	}
	// #nosec G304 -- signature path is generated in process-owned temp dir.
	rawSig, err := os.ReadFile(sigPath)
	if err != nil {
		return Signature{}, err
	}
	return Signature{
		Alg:          "cosign",
		KeyID:        "cosign:" + filepath.Base(keyPath),
		Sig:          strings.TrimSpace(string(rawSig)),
		SignedDigest: digest,
	}, nil
}

func VerifyRecordCosign(r *record.Record, opts CosignVerifyOpts) error {
	if r == nil {
		return coreerr.New(coreerr.KindInvalidInput, "signing.record_nil", "record is nil", coreerr.WithField("record"))
	}
	if !strings.HasPrefix(r.Integrity.Signature, "cosign:") {
		return coreerr.New(coreerr.KindInvalidInput, "signing.cosign.signature_missing", "record does not contain cosign signature", coreerr.WithField("integrity.signature"))
	}
	expected, err := record.ComputeHash(r)
	if err != nil {
		return err
	}
	if expected != r.Integrity.RecordHash {
		return coreerr.New(
			coreerr.KindVerification,
			"signing.record_hash_mismatch",
			fmt.Sprintf("record hash mismatch: expected %s got %s", expected, r.Integrity.RecordHash),
			coreerr.WithField("integrity.record_hash"),
		)
	}
	sig := Signature{
		Alg:          "cosign",
		KeyID:        r.Integrity.SigningKeyID,
		Sig:          strings.TrimPrefix(r.Integrity.Signature, "cosign:"),
		SignedDigest: r.Integrity.RecordHash,
	}
	return VerifyDigestCosign(sig, r.Integrity.RecordHash, opts)
}

func VerifyDigestCosign(sig Signature, digest string, opts CosignVerifyOpts) error {
	if strings.TrimSpace(opts.KeyPath) == "" && strings.TrimSpace(opts.CertificatePath) == "" {
		return coreerr.New(
			coreerr.KindInvalidInput,
			"signing.cosign.verify_material_required",
			"cosign verification requires --cosign-key or --cosign-cert",
		)
	}
	if _, err := cosignLookPath("cosign"); err != nil {
		return coreerr.Wrap(
			coreerr.KindDependencyMissing,
			"signing.cosign.binary_missing",
			"cosign binary not found",
			fmt.Errorf("%w: %v", ErrDependencyMissing, err),
		)
	}
	if strings.TrimSpace(sig.SignedDigest) == "" {
		return coreerr.New(coreerr.KindInvalidInput, "signing.cosign.signed_digest_required", "signed digest is required", coreerr.WithField("signed_digest"))
	}
	if strings.TrimSpace(sig.SignedDigest) != strings.TrimSpace(digest) {
		return coreerr.New(
			coreerr.KindVerification,
			"signing.signed_digest_mismatch",
			fmt.Sprintf("signed digest mismatch: expected %s got %s", digest, sig.SignedDigest),
			coreerr.WithField("signed_digest"),
		)
	}
	tmpDir, err := os.MkdirTemp("", "proof-cosign-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	blobPath := filepath.Join(tmpDir, "digest.txt")
	sigPath := filepath.Join(tmpDir, "signature.sig")
	if err := os.WriteFile(blobPath, []byte(digest), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(sigPath, []byte(sig.Sig), 0o600); err != nil {
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
	args = append(args, blobPath)

	if out, err := cosignRun(args...); err != nil {
		return coreerr.New(
			coreerr.KindVerification,
			"signing.cosign.verify_blob_failed",
			fmt.Sprintf("cosign verify-blob failed: %v (%s)", err, strings.TrimSpace(string(out))),
		)
	}
	return nil
}
