package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/spf13/cobra"
)

func newVerifyCmd(opts *globalOpts) *cobra.Command {
	var verifyChain bool
	var verifySignatures bool
	var verifyBundleFlag bool
	var publicKeyHex string
	var cosignKeyPath string
	var cosignCertPath string
	var cosignCertIdentity string
	var cosignCertIssuer string
	var revocationListPath string
	var revocationKeyHex string

	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify record, chain, or bundle artifacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			kind, err := detectArtifact(path)
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}

			var revocationList *proof.RevocationList
			if revocationListPath != "" {
				// #nosec G304 -- CLI accepts explicit local file paths for revocation lists.
				raw, err := os.ReadFile(revocationListPath)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				var rl proof.RevocationList
				if err := json.Unmarshal(raw, &rl); err != nil {
					return newCLIError(exitcode.InvalidInput, fmt.Sprintf("invalid revocation list: %v", err))
				}
				if revocationKeyHex != "" {
					revPub, err := decodePublicKey(revocationKeyHex)
					if err != nil {
						return newCLIError(exitcode.InvalidInput, err.Error())
					}
					if err := proof.VerifyRevocationList(rl, revPub); err != nil {
						return newCLIError(exitcode.VerificationErr, fmt.Sprintf("revocation list verification failed: %v", err))
					}
				}
				revocationList = &rl
			}

			switch kind {
			case artifactRecord:
				r, err := loadRecord(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				if err := proof.ValidateRecord(r); err != nil {
					return newCLIError(exitcode.VerificationErr, fmt.Sprintf("record validation failed: %v", err))
				}
				hash, err := proof.ComputeRecordHash(r)
				if err != nil {
					return newCLIError(exitcode.InternalError, err.Error())
				}
				if hash != r.Integrity.RecordHash {
					return newCLIError(exitcode.VerificationErr, fmt.Sprintf("record hash mismatch: expected %s got %s", hash, r.Integrity.RecordHash))
				}
				if verifySignatures {
					if strings.HasPrefix(r.Integrity.Signature, "cosign:") {
						opts := proof.CosignVerifyOpts{
							KeyPath:             cosignKeyPath,
							CertificatePath:     cosignCertPath,
							CertificateIdentity: cosignCertIdentity,
							CertificateIssuer:   cosignCertIssuer,
						}
						if err := proof.VerifyCosignWithOptions(r, opts); err != nil {
							return newCLIError(exitcode.VerificationErr, err.Error())
						}
					} else {
						if publicKeyHex == "" {
							return newCLIError(exitcode.InvalidInput, "--public-key is required with --signatures")
						}
						pub, err := decodePublicKey(publicKeyHex)
						if err != nil {
							return newCLIError(exitcode.InvalidInput, err.Error())
						}
						if err := proof.Verify(r, pub); err != nil {
							return newCLIError(exitcode.VerificationErr, err.Error())
						}
					}
				}
				if revocationList != nil && proof.IsKeyRevoked(*revocationList, r.Integrity.SigningKeyID, r.Timestamp) {
					return newCLIError(exitcode.VerificationErr, fmt.Sprintf("record signing key is revoked: %s", r.Integrity.SigningKeyID))
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind, "record_id": r.RecordID}, "Record verified.")
				return nil
			case artifactChain:
				c, err := loadChain(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				v, err := proof.VerifyChain(c)
				if err != nil {
					return newCLIError(exitcode.InternalError, err.Error())
				}
				if !v.Intact {
					return newCLIError(exitcode.VerificationErr, fmt.Sprintf("chain verification failed at index %d record %s", v.BreakIndex, v.BreakPoint))
				}
				if verifySignatures {
					var pub proof.PublicKey
					if publicKeyHex != "" {
						pub, err = decodePublicKey(publicKeyHex)
					}
					if err != nil {
						return newCLIError(exitcode.InvalidInput, err.Error())
					}
					for i := range c.Records {
						if strings.HasPrefix(c.Records[i].Integrity.Signature, "cosign:") {
							opts := proof.CosignVerifyOpts{
								KeyPath:             cosignKeyPath,
								CertificatePath:     cosignCertPath,
								CertificateIdentity: cosignCertIdentity,
								CertificateIssuer:   cosignCertIssuer,
							}
							if err := proof.VerifyCosignWithOptions(&c.Records[i], opts); err != nil {
								return newCLIError(exitcode.VerificationErr, fmt.Sprintf("signature verification failed for record %s: %v", c.Records[i].RecordID, err))
							}
							continue
						}
						if publicKeyHex == "" {
							return newCLIError(exitcode.InvalidInput, "--public-key is required with --signatures for non-cosign signatures")
						}
						if err := proof.Verify(&c.Records[i], pub); err != nil {
							return newCLIError(exitcode.VerificationErr, fmt.Sprintf("signature verification failed for record %s: %v", c.Records[i].RecordID, err))
						}
					}
				}
				if revocationList != nil {
					for i := range c.Records {
						if proof.IsKeyRevoked(*revocationList, c.Records[i].Integrity.SigningKeyID, c.Records[i].Timestamp) {
							return newCLIError(exitcode.VerificationErr, fmt.Sprintf("record signing key is revoked: %s", c.Records[i].Integrity.SigningKeyID))
						}
					}
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind, "records": v.Count, "head_hash": v.HeadHash}, fmt.Sprintf("Chain intact. %d records. No gaps.", v.Count))
				return nil
			case artifactBundle:
				if verifyBundleFlag || !verifyChain {
					if err := verifyBundle(path); err != nil {
						return newCLIError(exitcode.VerificationErr, err.Error())
					}
				}
				if verifyChain {
					chainPath := filepath.Join(path, "chain.json")
					c, err := loadChain(chainPath)
					if err == nil {
						v, verr := proof.VerifyChain(c)
						if verr != nil || !v.Intact {
							return newCLIError(exitcode.VerificationErr, "bundle chain verification failed")
						}
					}
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind}, "Bundle verified.")
				return nil
			case artifactGaitPack:
				res, err := verifyGaitPack(path, verifySignatures, publicKeyHex)
				if err != nil {
					return newCLIError(exitcode.VerificationErr, err.Error())
				}
				printResult(opts, map[string]any{
					"ok":                     true,
					"kind":                   kind,
					"pack_id":                res.PackID,
					"pack_type":              res.PackType,
					"files_verified":         res.FilesVerified,
					"proof_records_verified": res.ProofRecordsVerified,
					"signatures_verified":    res.SignaturesVerified,
				}, fmt.Sprintf("Gait pack verified. Files: %d.", res.FilesVerified))
				return nil
			case artifactGaitRunpack:
				res, err := verifyGaitRunpack(path, verifySignatures, publicKeyHex)
				if err != nil {
					return newCLIError(exitcode.VerificationErr, err.Error())
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind, "run_id": res.RunID, "manifest_digest": res.ManifestDigest, "files_verified": res.FilesVerified, "signatures_verified": res.SignaturesVerified}, fmt.Sprintf("Gait runpack verified. Files: %d.", res.FilesVerified))
				return nil
			case artifactGaitSignedJSON:
				if verifySignatures {
					if err := verifyGaitSignedJSON(path, publicKeyHex); err != nil {
						return newCLIError(exitcode.VerificationErr, err.Error())
					}
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind}, "Gait signed artifact verified.")
				return nil
			default:
				return newCLIError(exitcode.InvalidInput, "unsupported artifact type")
			}
		},
	}

	cmd.Flags().BoolVar(&verifyChain, "chain", false, "Verify chain integrity")
	cmd.Flags().BoolVar(&verifySignatures, "signatures", false, "Verify signatures")
	cmd.Flags().BoolVar(&verifyBundleFlag, "bundle", false, "Verify bundle integrity")
	cmd.Flags().StringVar(&publicKeyHex, "public-key", "", "Ed25519 public key as hex or base64")
	cmd.Flags().StringVar(&cosignKeyPath, "cosign-key", "", "Path to cosign public key")
	cmd.Flags().StringVar(&cosignCertPath, "cosign-cert", "", "Path to cosign certificate")
	cmd.Flags().StringVar(&cosignCertIdentity, "cosign-cert-identity", "", "Expected cosign certificate identity")
	cmd.Flags().StringVar(&cosignCertIssuer, "cosign-cert-issuer", "", "Expected cosign certificate OIDC issuer")
	cmd.Flags().StringVar(&revocationListPath, "revocation-list", "", "Path to signed revocation list JSON")
	cmd.Flags().StringVar(&revocationKeyHex, "revocation-key", "", "Revocation list signer Ed25519 public key as hex")
	return cmd
}

func decodePublicKey(h string) (proof.PublicKey, error) {
	h = strings.TrimSpace(h)
	pub, err := decodePublicKeyValue(h)
	if err != nil {
		return proof.PublicKey{}, fmt.Errorf("invalid public key: %w", err)
	}
	return proof.PublicKey{Public: pub}, nil
}
