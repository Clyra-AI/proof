package main

import (
	"fmt"
	"os"

	"github.com/Clyra-AI/proof/core/exitcode"
)

var version = "dev"
var exitFn = os.Exit

func main() {
	exitFn(run(os.Stderr))
}

func run(stderr *os.File) int {
	root := newRootCmd(version)
	if err := root.Execute(); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		if ec, ok := err.(interface{ ExitCode() int }); ok {
			return ec.ExitCode()
		}
		return exitcode.InternalError
	}
	return exitcode.Success
}
