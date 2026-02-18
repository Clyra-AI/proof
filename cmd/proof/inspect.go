package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/spf13/cobra"
)

func newInspectCmd(opts *globalOpts) *cobra.Command {
	var recordID string
	cmd := &cobra.Command{
		Use:   "inspect <path>",
		Short: "Inspect proof artifacts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			explainf(opts, "inspect path=%s", path)
			kind, err := detectArtifact(path)
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			explainf(opts, "inspect artifact kind=%s", kind)
			switch kind {
			case artifactRecord:
				r, err := loadRecord(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				b, _ := json.MarshalIndent(r, "", "  ")
				printResult(opts, r, string(b))
			case artifactChain:
				c, err := loadChain(path)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				if recordID != "" {
					for _, r := range c.Records {
						if r.RecordID == recordID {
							b, _ := json.MarshalIndent(r, "", "  ")
							printResult(opts, r, string(b))
							return nil
						}
					}
					return newCLIError(exitcode.InvalidInput, fmt.Sprintf("record %s not found", recordID))
				}
				b, _ := json.MarshalIndent(c, "", "  ")
				printResult(opts, c, string(b))
			case artifactBundle:
				// #nosec G304 -- CLI accepts explicit local artifact paths.
				raw, err := os.ReadFile(path + "/manifest.json")
				if err != nil {
					return newCLIError(exitcode.InvalidInput, err.Error())
				}
				printResult(opts, map[string]any{"manifest": json.RawMessage(raw)}, string(raw))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&recordID, "record", "", "Inspect specific record by ID")
	return cmd
}
