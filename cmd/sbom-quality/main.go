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
	Image        string `help:"Remote image ref (repo:tag or repo@sha256). At least one of --image/--go-mod is required."`
	GoMod        string `name:"go-mod" help:"Go module path (directory). At least one of --image/--go-mod is required."`
	SupplierName string `help:"Supplier name for document provenance." required:""`
	Output       string `name:"output" short:"o" help:"Write SBOM to a file instead of stdout."`
}

func main() {
	var c cli
	kong.Parse(&c,
		kong.Name("sbom-quality"),
		kong.Description("Orchestrate tools into a high-quality CycloneDX 1.6 SBOM."),
	)

	sbom, err := pipeline.Run(pipeline.Config{
		Image:        c.Image,
		GoMod:        c.GoMod,
		SupplierName: c.SupplierName,
	})
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
