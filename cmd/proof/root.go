package main

import (
	"github.com/spf13/cobra"
)

type globalOpts struct {
	json    bool
	quiet   bool
	explain bool
}

func newRootCmd(version string) *cobra.Command {
	opts := &globalOpts{}
	cmd := &cobra.Command{
		Use:   "proof",
		Short: "Verify and inspect proof artifacts",
	}
	cmd.PersistentFlags().BoolVar(&opts.json, "json", false, "Machine-readable output")
	cmd.PersistentFlags().BoolVar(&opts.quiet, "quiet", false, "Exit codes only")
	cmd.PersistentFlags().BoolVar(&opts.explain, "explain", false, "Verbose diagnostic output")
	cmd.Version = version

	cmd.AddCommand(newVerifyCmd(opts))
	cmd.AddCommand(newInspectCmd(opts))
	cmd.AddCommand(newChainCmd(opts))
	cmd.AddCommand(newTypesCmd(opts))
	cmd.AddCommand(newFrameworksCmd(opts))

	return cmd
}
