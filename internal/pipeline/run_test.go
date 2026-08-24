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

// --go-main only means anything to cyclonedx-gomod, so it is rejected without
// --go-mod rather than silently ignored (#80).
func TestRunGoMainRequiresGoMod(t *testing.T) {
	_, err := Run(Config{SBOM: "y.json", GoMain: "./cmd/app", SupplierName: "X"})
	if err == nil || !strings.Contains(err.Error(), "--go-main requires --go-mod") {
		t.Fatalf("want '--go-main requires --go-mod' error, got %v", err)
	}
}

// --trivy-arg only means anything to trivy, so it is rejected without --image
// rather than silently ignored (#83).
func TestRunTrivyArgRequiresImage(t *testing.T) {
	_, err := Run(Config{SBOM: "y.json", TrivyArgs: []string{"--platform", "linux/amd64"}, SupplierName: "X"})
	if err == nil || !strings.Contains(err.Error(), "--trivy-arg requires --image") {
		t.Fatalf("want '--trivy-arg requires --image' error, got %v", err)
	}
}

// --go-mod and --sbom are mutually exclusive; the guard runs before any tool.
func TestRunGoModSBOMMutuallyExclusive(t *testing.T) {
	_, err := Run(Config{GoMod: "./x", SBOM: "y.json", SupplierName: "X"})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want 'mutually exclusive' error, got %v", err)
	}
}
