package main

import (
	"fmt"

	"github.com/Clyra-AI/proof/core/exitcode"
	"github.com/Clyra-AI/proof/core/framework"
	"github.com/spf13/cobra"
)

func newFrameworksCmd(opts *globalOpts) *cobra.Command {
	cmd := &cobra.Command{Use: "frameworks", Short: "Compliance framework definitions"}
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List available frameworks",
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := framework.List()
			if err != nil {
				return newCLIError(exitcode.InternalError, err.Error())
			}
			if opts.json {
				printResult(opts, list, "")
				return nil
			}
			for _, f := range list {
				fmt.Printf("%s\t%s\tcontrols=%d\n", f.ID, f.Version, f.ControlCount)
			}
			return nil
		},
	}
	showCmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show a framework definition",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := framework.Load(args[0])
			if err != nil {
				return newCLIError(exitcode.InvalidInput, err.Error())
			}
			printResult(opts, f, fmt.Sprintf("%s (%s)", f.Framework.Title, f.Framework.Version))
			return nil
		},
	}
	cmd.AddCommand(listCmd, showCmd)
	return cmd
}
