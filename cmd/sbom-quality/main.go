// Command sbom-quality orchestrates external tools into a high-quality
// CycloneDX 1.6 SBOM. This slice: trivy image → 1.6 down-convert → validate.
package main

import (
	"fmt"
	"os"

	"github.com/alecthomas/kong"

	"github.com/NissesSenap/sbom-quality/internal/pipeline"
)

type cli struct {
	Image           string   `help:"Remote image ref (repo:tag or repo@sha256). At least one of --image/--go-mod/--sbom is required."`
	GoMod           string   `name:"go-mod" help:"Go module path (directory). Mutually exclusive with --sbom."`
	SBOM            string   `name:"sbom" help:"Bring-your-own CycloneDX dependency SBOM file (e.g. cyclonedx-maven/gradle). Mutually exclusive with --go-mod."`
	SupplierName    string   `help:"Supplier name for document provenance." required:""`
	SupplierURL     string   `name:"supplier-url" help:"Supplier URL for document provenance."`
	SupplierContact string   `name:"supplier-contact" help:"Supplier contact (email or name) for document provenance."`
	Author          []string `help:"Document author (repeatable)."`
	Manufacturer    string   `help:"Manufacturer name for document-identity metadata."`
	License         string   `help:"Primary-component license (SPDX id or expression)."`
	Lifecycle       string   `help:"Lifecycle phase (e.g. build, post-build)." default:"build"`
	DataLicense     string   `name:"data-license" help:"SBOM document data license (SPDX id)." default:"CC0-1.0"`
	NoCIAutodetect  bool     `name:"no-ci-autodetect" help:"Disable GitHub CI-env VCS autodetect (url/commit/ref)."`
	SkipEnrichment  bool     `name:"skip-enrichment" help:"Skip the parlay enrich stage (supplier/license/VCS for Go/Maven components)."`
	Output          string   `name:"output" short:"o" help:"Write SBOM to a file instead of stdout."`
}

func main() {
	var c cli
	kong.Parse(&c,
		kong.Name("sbom-quality"),
		kong.Description("Orchestrate tools into a high-quality CycloneDX 1.6 SBOM."),
	)

	cfg := pipeline.Config{
		Image:           c.Image,
		GoMod:           c.GoMod,
		SBOM:            c.SBOM,
		SupplierName:    c.SupplierName,
		SupplierURL:     c.SupplierURL,
		SupplierContact: c.SupplierContact,
		Authors:         c.Author,
		Manufacturer:    c.Manufacturer,
		License:         c.License,
		Lifecycle:       c.Lifecycle,
		DataLicense:     c.DataLicense,
		NoCIAutodetect:  c.NoCIAutodetect,
		SkipEnrichment:  c.SkipEnrichment,
	}
	pipeline.WarnMissingConfig(os.Stderr, cfg)

	sbom, err := pipeline.Run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sbom-quality: %v\n", err)
		os.Exit(1)
	}

	if err := write(c.Output, sbom); err != nil {
		fmt.Fprintf(os.Stderr, "sbom-quality: %v\n", err)
		os.Exit(1)
	}
}

func write(path string, sbom []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(sbom)
		return err
	}
	return os.WriteFile(path, sbom, 0o644)
}
