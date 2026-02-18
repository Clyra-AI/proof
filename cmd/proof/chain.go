package main

import (
	"fmt"
	"time"

	"github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/spf13/cobra"
)

func newChainCmd(opts *globalOpts) *cobra.Command {
	chainCmd := &cobra.Command{Use: "chain", Short: "Chain operations"}
	var fromStr, toStr string
	verifyCmd := &cobra.Command{
		Use:   "verify <path>",
		Short: "Verify chain integrity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := loadChain(args[0])
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			var from, to time.Time
			if fromStr != "" {
				from, err = time.Parse(time.RFC3339, fromStr)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, "--from must be RFC3339")
				}
			}
			if toStr != "" {
				to, err = time.Parse(time.RFC3339, toStr)
				if err != nil {
					return newCLIError(exitcode.InvalidInput, "--to must be RFC3339")
				}
			}
			v, err := proof.VerifyChainRange(c, from, to)
			if err != nil {
				return newCLIError(exitcode.InternalError, err.Error())
			}
			if !v.Intact {
				return newCLIError(exitcode.VerificationErr, fmt.Sprintf("chain verification failed at index %d record %s", v.BreakIndex, v.BreakPoint))
			}
			printResult(opts, v, fmt.Sprintf("Chain intact. %d records. No gaps.", v.Count))
			return nil
		},
	}
	verifyCmd.Flags().StringVar(&fromStr, "from", "", "Start timestamp (RFC3339)")
	verifyCmd.Flags().StringVar(&toStr, "to", "", "End timestamp (RFC3339)")
	chainCmd.AddCommand(verifyCmd)
	return chainCmd
}
