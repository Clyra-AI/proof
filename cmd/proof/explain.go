package main

import (
	"fmt"
	"os"
)

func explainf(opts *globalOpts, format string, args ...any) {
	if opts == nil || !opts.explain || opts.quiet {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "explain: "+format+"\n", args...)
}
