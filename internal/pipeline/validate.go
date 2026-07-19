package pipeline

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// validate writes the SBOM to a temp file and runs sbom-utility against it.
// A failed validation (or a missing sbom-utility) fails the run loudly.
func validate(sbom []byte) error {
	if _, err := exec.LookPath("sbom-utility"); err != nil {
		return fmt.Errorf("sbom-utility not found on PATH: %w", err)
	}

	f, err := os.CreateTemp("", "sbom-quality-*.cdx.json")
	if err != nil {
		return fmt.Errorf("create temp file for validation: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(sbom); err != nil {
		f.Close()
		return fmt.Errorf("write temp file for validation: %w", err)
	}
	f.Close()

	var stderr bytes.Buffer
	cmd := exec.Command("sbom-utility", "validate", "--input-file", f.Name())
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sbom-utility validation failed: %w\n%s", err, stderr.String())
	}
	return nil
}
