package main

import (
	"fmt"
	"os"

	"github.com/Clyra-AI/proof/core/exitcode"
)

var version = "dev"

func main() {
	root := newRootCmd(version)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if ec, ok := err.(interface{ ExitCode() int }); ok {
			os.Exit(ec.ExitCode())
		}
		os.Exit(exitcode.InternalError)
	}
}
