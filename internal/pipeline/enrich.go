package pipeline

import "os"

// enrich runs parlay (ecosyste.ms backend) over the whole SBOM, filling
// supplier(proxy)/license/vcs from the upstream registry — it dispatches by
// purl and enriches pkg:golang and pkg:maven alike, no-oping on entries it
// can't resolve (so an image-only run is harmless).
// Checksums are not enrich's job (no registry
// exposes hashes via ecosyste.ms) — those come from the generate stage. A
// missing or errored parlay fails the run loudly; --skip-enrichment (handled
// in Run) is the sole opt-out.
func enrich(sbom []byte) ([]byte, error) {
	path, err := writeTempSBOM(sbom)
	if err != nil {
		return nil, err
	}
	defer os.Remove(path)

	return runTool("parlay", "ecosystems", "enrich", path)
}
