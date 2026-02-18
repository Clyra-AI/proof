package exitcode

import "testing"

func TestCompatibilityAliases(t *testing.T) {
	if OK != 0 || VerificationFailure != 2 || UnsafeReplay != 8 {
		t.Fatalf("unexpected compatibility values")
	}
}
