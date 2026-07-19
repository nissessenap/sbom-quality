package pipeline

import "os"

// merge combines the gomod SBOM into the trivy image SBOM with sbomasm's augment
// merge. trivy is --primary, so its OS-package inventory is retained; the gomod
// SBOM back-fills trivy's thin Go entries (licenses/supplier/hashes) under
// --merge-mode if-missing-or-empty. Dedupe (PURL → CPE → name-version) is native
// to sbomasm. Augment merge adds no new root, so output is flat. Both inputs must
// already be 1.6 (trivy is down-converted upstream, gomod is native); -e 1.6 pins
// the exported spec version.
func merge(primary, secondary []byte) ([]byte, error) {
	pf, err := writeTempSBOM(primary)
	if err != nil {
		return nil, err
	}
	defer os.Remove(pf)

	sf, err := writeTempSBOM(secondary)
	if err != nil {
		return nil, err
	}
	defer os.Remove(sf)

	return runTool("sbomasm", "assemble", "--augmentMerge",
		"--primary", pf, "--merge-mode", "if-missing-or-empty",
		"-e", "1.6", sf)
}
