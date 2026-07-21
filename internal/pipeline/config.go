package pipeline

import (
	"fmt"
	"io"
)

// WarnMissingConfig writes a stderr warning for each absent optional document-identity
// field (SupplierName is required and enforced by kong, so it is not checked here).
// Nudges completeness without failing the run.
func WarnMissingConfig(w io.Writer, cfg Config) {
	warn := func(flag string) {
		fmt.Fprintf(w, "sbom-quality: warning: %s not set — document-identity metadata will be incomplete\n", flag)
	}
	if cfg.SupplierURL == "" {
		warn("--supplier-url")
	}
	if cfg.SupplierContact == "" {
		warn("--supplier-contact")
	}
	if len(cfg.Authors) == 0 {
		warn("--author")
	}
	if cfg.Manufacturer == "" {
		warn("--manufacturer")
	}
	if cfg.License == "" {
		warn("--license")
	}
	if cfg.Lifecycle == "" {
		warn("--lifecycle")
	}
}

// Config is the resolved CLI input for one pipeline run.
type Config struct {
	Image string // remote image ref: repo:tag or repo@sha256
	GoMod string // Go module path (directory) — XOR SBOM
	SBOM  string // BYO CycloneDX dependency SBOM file (e.g. cyclonedx-maven/gradle) — XOR GoMod

	// Document-identity metadata, applied by the augment stage. SupplierName is
	// required; the rest are optional (absent → stderr warning via WarnMissingConfig).
	SupplierName    string   // required
	SupplierURL     string   // metadata.supplier.url
	SupplierContact string   // metadata.supplier.contact (email if it contains '@', else name)
	Authors         []string // metadata.authors
	Manufacturer    string   // metadata.manufacturer.name
	License         string   // primary-component license (SPDX id/expression)
	Lifecycle       string   // metadata.lifecycles phase (defaults to "build")
	DataLicense     string   // metadata.licenses — the SBOM document's own data license (defaults to "CC0-1.0")

	NoCIAutodetect bool // disable GitHub CI-env VCS autodetect
	SkipEnrichment bool // opt out of the parlay enrich stage
}
