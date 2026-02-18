package main

import (
	"fmt"
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

			switch kind {
			case artifactRecord:
				r, err := loadRecord(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				if err := proof.ValidateRecord(r); err != nil {
					return newCLIError(exitcode.VerificationErr, fmt.Sprintf("record validation failed: %v", err))
				}
				if verifySignatures {
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
			default:
				return newCLIError(exitcode.InvalidInput, "unsupported artifact type")
			}
		},
	}

	cmd.Flags().BoolVar(&verifyChain, "chain", false, "Verify chain integrity")
	cmd.Flags().BoolVar(&verifySignatures, "signatures", false, "Verify signatures")
	cmd.Flags().BoolVar(&verifyBundleFlag, "bundle", false, "Verify bundle integrity")
	cmd.Flags().StringVar(&publicKeyHex, "public-key", "", "Ed25519 public key as hex")
	return cmd
}

func decodePublicKey(h string) (proof.PublicKey, error) {
	h = strings.TrimSpace(h)
	pub, err := hexDecode(h)
	if err != nil {
		return proof.PublicKey{}, fmt.Errorf("invalid public key hex: %w", err)
	}
	return proof.PublicKey{Public: pub}, nil
}
