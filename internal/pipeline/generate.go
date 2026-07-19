package pipeline

import (
	"bytes"
	"fmt"
	"os/exec"
)

// generate runs trivy against a remote image ref and returns its CycloneDX JSON.
// --format cyclonedx puts trivy in SBOM-generation mode: image-pull only, no
// vulnerability DB. Modern trivy emits 1.7; the caller down-converts.
func generate(imageRef string) ([]byte, error) {
	if _, err := exec.LookPath("trivy"); err != nil {
		return nil, fmt.Errorf("trivy not found on PATH: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command("trivy", "image", imageRef, "--format", "cyclonedx")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy image %s failed: %w\n%s", imageRef, err, stderr.String())
	}
	return stdout.Bytes(), nil
}
