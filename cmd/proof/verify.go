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
	var customTypeSchemas []string
	var publicKeyHex string
	var cosignKeyPath string
	var cosignCertPath string
	var cosignCertIdentity string
	var cosignCertIssuer string
	var revocationListPath string
	var revocationKeyHex string
	var strict bool

	cmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify record, chain, or bundle artifacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			explainf(opts, "verifying artifact path=%s", path)
			if err := registerCustomTypeSchemas(customTypeSchemas); err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			kind, err := detectArtifact(path)
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			explainf(opts, "artifact kind=%s", kind)

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
				explainf(opts, "record verify: schema/hash/signature checks")
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
							return newCLIError(verificationErrorCode(err), err.Error())
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
				explainf(opts, "chain verify: integrity check")
				c, err := loadChain(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				if strict {
					if err := verifyDeclaredChainMetadata(path, c); err != nil {
						return newCLIError(verificationErrorCode(err), err.Error())
					}
				}
				v, err := proof.VerifyChainWithOptions(c, proof.ChainVerifyOpts{Strict: strict})
				if err != nil {
					return newCLIError(verificationErrorCode(err), err.Error())
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
								return newCLIError(verificationErrorCode(err), fmt.Sprintf("signature verification failed for record %s: %v", c.Records[i].RecordID, err))
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
				explainf(opts, "bundle verify: manifest hash checks")
				if verifyBundleFlag || !verifyChain {
					if err := verifyBundleWithStrict(path, verifySignatures, publicKeyHex, proof.CosignVerifyOpts{
						KeyPath:             cosignKeyPath,
						CertificatePath:     cosignCertPath,
						CertificateIdentity: cosignCertIdentity,
						CertificateIssuer:   cosignCertIssuer,
					}, strict); err != nil {
						return newCLIError(verificationErrorCode(err), err.Error())
					}
				}
				if verifyChain {
					chainPath := filepath.Join(path, "chain.json")
					c, err := loadChain(chainPath)
					if err == nil {
						v, verr := proof.VerifyChainWithOptions(c, proof.ChainVerifyOpts{Strict: strict})
						if verr != nil || !v.Intact {
							return newCLIError(exitcode.VerificationErr, "bundle chain verification failed")
						}
					}
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind}, "Bundle verified.")
				return nil
			case artifactGaitPack:
				explainf(opts, "gait pack verify: manifest + embedded artifacts")
				res, err := verifyGaitPackWithStrict(path, verifySignatures, publicKeyHex, proof.CosignVerifyOpts{
					KeyPath:             cosignKeyPath,
					CertificatePath:     cosignCertPath,
					CertificateIdentity: cosignCertIdentity,
					CertificateIssuer:   cosignCertIssuer,
				}, strict)
				if err != nil {
					return newCLIError(verificationErrorCode(err), err.Error())
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
				explainf(opts, "gait runpack verify: manifest + file integrity")
				res, err := verifyGaitRunpackWithStrict(path, verifySignatures, publicKeyHex, strict)
				if err != nil {
					return newCLIError(verificationErrorCode(err), err.Error())
				}
				printResult(opts, map[string]any{"ok": true, "kind": kind, "run_id": res.RunID, "manifest_digest": res.ManifestDigest, "files_verified": res.FilesVerified, "signatures_verified": res.SignaturesVerified}, fmt.Sprintf("Gait runpack verified. Files: %d.", res.FilesVerified))
				return nil
			case artifactGaitSignedJSON:
				explainf(opts, "gait signed JSON verify")
				if verifySignatures {
					if err := verifyGaitSignedJSON(path, publicKeyHex); err != nil {
						return newCLIError(verificationErrorCode(err), err.Error())
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
	cmd.Flags().StringArrayVar(&customTypeSchemas, "custom-type-schema", nil, "Custom type schema mapping record_type=/path/to/schema.json (repeatable)")
	cmd.Flags().StringVar(&publicKeyHex, "public-key", "", "Ed25519 public key as hex or base64")
	cmd.Flags().StringVar(&cosignKeyPath, "cosign-key", "", "Path to cosign public key")
	cmd.Flags().StringVar(&cosignCertPath, "cosign-cert", "", "Path to cosign certificate")
	cmd.Flags().StringVar(&cosignCertIdentity, "cosign-cert-identity", "", "Expected cosign certificate identity")
	cmd.Flags().StringVar(&cosignCertIssuer, "cosign-cert-issuer", "", "Expected cosign certificate OIDC issuer")
	cmd.Flags().StringVar(&revocationListPath, "revocation-list", "", "Path to signed revocation list JSON")
	cmd.Flags().StringVar(&revocationKeyHex, "revocation-key", "", "Revocation list signer Ed25519 public key as hex")
	cmd.Flags().BoolVar(&strict, "strict", false, "Reject structurally ambiguous artifacts and inconsistent chain metadata")
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

func registerCustomTypeSchemas(mappings []string) error {
	for _, mapping := range mappings {
		mapping = strings.TrimSpace(mapping)
		if mapping == "" {
			continue
		}
		parts := strings.SplitN(mapping, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid --custom-type-schema value %q: expected record_type=/path/to/schema.json", mapping)
		}
		recordType := strings.TrimSpace(parts[0])
		schemaPath := strings.TrimSpace(parts[1])
		if recordType == "" || schemaPath == "" {
			return fmt.Errorf("invalid --custom-type-schema value %q: record type and schema path are required", mapping)
		}
		if err := proof.RegisterCustomTypeSchema(recordType, schemaPath); err != nil {
			return fmt.Errorf("register custom type %s: %w", recordType, err)
		}
	}
	return nil
}
