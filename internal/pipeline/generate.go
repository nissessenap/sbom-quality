package pipeline

import (
	"bytes"
	"fmt"
	"os/exec"
)

// generateImage runs trivy against a remote image ref and returns its CycloneDX
// JSON. --format cyclonedx puts trivy in SBOM-generation mode: image-pull only,
// no vulnerability DB. Modern trivy emits 1.7; the caller down-converts.
func generateImage(imageRef string) ([]byte, error) {
	return runTool("trivy", "image", imageRef, "--format", "cyclonedx")
}

// generateGoMod runs cyclonedx-gomod against a Go module and returns its
// CycloneDX 1.6 JSON. The app subcommand builds the real build graph (honoring
// tags/replace); module grain (no -packages) keeps PURLs aligned with trivy's
// Go entries for a later merge. gomod emits 1.6 natively, so no down-convert.
func generateGoMod(modPath string) ([]byte, error) {
	return runTool("cyclonedx-gomod", "app", "-json", "-licenses", "-output-version", "1.6", modPath)
}

// runTool execs an external generator and returns its stdout. A missing binary
// or a non-zero exit fails loudly, carrying the tool's stderr for diagnosis.
func runTool(bin string, args ...string) ([]byte, error) {
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("%s not found on PATH: %w", bin, err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v failed: %w\n%s", bin, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
