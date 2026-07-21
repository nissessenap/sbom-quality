package pipeline

import (
	"strings"
	"testing"
)

// Source validation runs before any external tool, so this needs no binaries.
// The both-sources merge path needs trivy/gomod/sbomasm and is exercised by the
// sbomqs gate, not here.
func TestRunSourceValidation(t *testing.T) {
	_, err := Run(Config{SupplierName: "X"})
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("want 'at least one' error, got %v", err)
	}
}

// --go-mod and --sbom are mutually exclusive; the guard runs before any tool.
func TestRunGoModSBOMMutuallyExclusive(t *testing.T) {
	_, err := Run(Config{GoMod: "./x", SBOM: "y.json", SupplierName: "X"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want 'mutually exclusive' error, got %v", err)
	}
}
