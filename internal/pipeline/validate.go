package pipeline

import "os"

// validate writes the SBOM to a temp file and runs sbom-utility against it.
// A failed validation (or a missing sbom-utility) fails the run loudly via runTool.
func validate(sbom []byte) error {
	path, err := writeTempSBOM(sbom)
	if err != nil {
		return err
	}
	defer os.Remove(path)

	_, err = runTool("sbom-utility", "validate", "--input-file", path)
	return err
}
