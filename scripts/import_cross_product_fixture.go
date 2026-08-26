//go:build ignore

// Command import_cross_product_fixture stages exact Wrkr, Gait, and Axym
// release artifacts for Proof conformance. It never creates a producer
// artifact, normalized assessment, signature, or synthetic substitute.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Clyra-AI/proof/internal/fixtureimport"
)

var jsonMode bool

func main() {
	jsonMode = hasJSONFlag(os.Args[1:])
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "external release fixture root (required with --update)")
	contractPath := flags.String("contract", "", "import contract path (required with --update)")
	dest := flags.String("dest", "scenarios/proof/action-contract-final-conformance", "staged fixture destination")
	update := flags.Bool("update", false, "validate and stage exact source bytes")
	check := flags.Bool("check", false, "verify the committed staged bytes offline")
	flags.BoolVar(&jsonMode, "json", jsonMode, "emit a stable machine-readable result")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatalCode(6, "invalid invocation: %v", err)
	}
	if flags.NArg() != 0 {
		fatalCode(6, "invalid invocation: unexpected positional arguments")
	}
	if strings.TrimSpace(*dest) == "" {
		fatalCode(6, "--dest must not be empty")
	}
	if *update == *check {
		fatalCode(6, "exactly one of --update or --check is required")
	}
	if *check {
		if err := fixtureimport.Check(*dest); err != nil {
			var unsafeErr *fixtureimport.UnsafeError
			if errors.As(err, &unsafeErr) {
				fatalCode(8, "unsafe fixture destination: %v", err)
			}
			var runtimeErr *fixtureimport.RuntimeError
			if errors.As(err, &runtimeErr) {
				fatalCode(1, "fixture check runtime failure: %v", err)
			}
			var schemaErr *fixtureimport.SchemaError
			if errors.As(err, &schemaErr) {
				fatalCode(3, "offline fixture schema validation failed: %v", err)
			}
			var driftErr *fixtureimport.DriftError
			if errors.As(err, &driftErr) {
				fatalCode(5, "offline fixture drift detected: %v", err)
			}
			fatalCode(2, "offline fixture check failed: %v", err)
		}
		if jsonMode {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "command": "import_cross_product_fixture", "data": map[string]any{"mode": "check", "dest": *dest}})
		}
		return
	}
	if strings.TrimSpace(*source) == "" || strings.TrimSpace(*contractPath) == "" {
		fatalCode(6, "--source and --contract are required with --update")
	}
	raw, err := fixtureimport.ReadContractFile(*contractPath)
	if err != nil {
		var unsafeErr *fixtureimport.UnsafeError
		if errors.As(err, &unsafeErr) {
			fatalCode(8, "unsafe contract input: %v", err)
		}
		var runtimeErr *fixtureimport.RuntimeError
		if errors.As(err, &runtimeErr) {
			fatalCode(1, "%v", err)
		}
		fatalCode(1, "read import contract: %v", err)
	}
	contract, err := fixtureimport.LoadContract(raw)
	if err != nil {
		fatalCode(6, "invalid import contract: %v", err)
	}
	if err := fixtureimport.Update(*source, *dest, contract, raw); err != nil {
		var unsafeErr *fixtureimport.UnsafeError
		if errors.As(err, &unsafeErr) {
			fatalCode(8, "unsafe fixture destination: %v", err)
		}
		var runtimeErr *fixtureimport.RuntimeError
		if errors.As(err, &runtimeErr) {
			fatalCode(1, "fixture import runtime failure: %v", err)
		}
		var schemaErr *fixtureimport.SchemaError
		if errors.As(err, &schemaErr) {
			fatalCode(3, "fixture schema validation failed: %v", err)
		}
		fatalCode(2, "fixture import failed: %v", err)
	}
	encoded, err := fixtureimport.CanonicalContractBytes(contract)
	if err != nil {
		fatalCode(1, "encode staged import contract: %v", err)
	}
	if jsonMode {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "command": "import_cross_product_fixture", "data": map[string]any{"fixture_id": contract.FixtureID, "contract_bytes": len(encoded)}})
	} else {
		fmt.Printf("staged %s (%d contract bytes)\n", contract.FixtureID, len(encoded))
	}
}

func hasJSONFlag(args []string) bool {
	found := false
	enabled := false
	for _, arg := range args {
		switch arg {
		case "--json", "-json":
			found = true
			enabled = true
		case "--json=false", "-json=false":
			found = true
			enabled = false
		default:
			for _, prefix := range []string{"--json=", "-json="} {
				if !strings.HasPrefix(arg, prefix) {
					continue
				}
				found = true
				if value, err := strconv.ParseBool(strings.TrimPrefix(arg, prefix)); err == nil {
					enabled = value
				}
				break
			}
		}
	}
	return found && enabled
}

func fatalCode(code int, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	if jsonMode {
		reason := "internal_error"
		switch code {
		case 2:
			reason = "verification_failed"
		case 6:
			reason = "invalid_input"
		case 8:
			reason = "unsafe_operation"
		case 3:
			reason = "schema_violation"
		case 5:
			reason = "drift_detected"
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": false, "command": "import_cross_product_fixture", "error": map[string]any{"reason": reason, "message": message}})
	} else {
		fmt.Fprintln(os.Stderr, message)
	}
	os.Exit(code)
}
