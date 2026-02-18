package main

import (
	"fmt"
	"os"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/spf13/cobra"
)

func newTypesCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{Use: "types", Short: "Record type registry operations"}
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered record types",
		Run: func(cmd *cobra.Command, args []string) {
			explainf(opts, "types list")
			types := proof.ListRecordTypes()
			if opts.json {
				printResult(opts, types, "")
				return
			}
			for _, t := range types {
				fmt.Printf("%s\t%s\n", t.Name, t.Description)
			}
		},
	}
	validateCmd := &cobra.Command{
		Use:   "validate <schema-path>",
		Short: "Validate a custom record type schema",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			explainf(opts, "types validate schema=%s", args[0])
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			if err := proof.ValidateCustomTypeSchema(args[0]); err != nil {
				return newCLIError(exitcode.PolicyOrSchema, err.Error())
			}
			printResult(opts, map[string]any{"ok": true, "schema": args[0], "bytes": len(raw)}, "Schema is valid.")
			return nil
		},
	}
	cmd.AddCommand(listCmd, validateCmd)
	return cmd
}
