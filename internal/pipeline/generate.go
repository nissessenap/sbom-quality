package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// toolTimeout caps every external-tool invocation (runTool + validateReport).
// A hung tool (bad input, network stall, deadlocked child) would otherwise hang
// the run — and CI — indefinitely. Central default; a var (not const) so tests
// can shorten it. Bump per-tool only if one legitimately needs longer.
var toolTimeout = 5 * time.Minute

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

	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("%s timed out after %s", bin, toolTimeout)
		}
		return nil, fmt.Errorf("%s %v failed: %w\n%s", bin, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// writeTempSBOM writes an SBOM to a temp file and returns its path; the caller
// removes it. Files-as-truth is how exec stages hand documents to external tools.
func writeTempSBOM(sbom []byte) (string, error) {
	f, err := os.CreateTemp("", "sbom-quality-*.cdx.json")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(sbom); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return f.Name(), nil
}
