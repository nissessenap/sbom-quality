package pipeline

// Run executes the pipeline for cfg and returns the final CycloneDX 1.6 JSON.
// Stages present in this slice: generate (trivy) → 1.6 down-convert → validate.
// Later slices add merge, enrich, augment and quality-patch between them.
func Run(cfg Config) ([]byte, error) {
	raw, err := generate(cfg.Image)
	if err != nil {
		return nil, err
	}

	sbom, err := downConvertTo16(raw)
	if err != nil {
		return nil, err
	}

	if err := validate(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}
