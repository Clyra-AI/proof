package main

import (
	"encoding/json"
	"fmt"
)

func printResult(opts *globalOpts, v any, plain string) {
	if opts.quiet {
		return
	}
	if opts.json {
		raw, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(raw))
		return
	}
	fmt.Println(plain)
}
