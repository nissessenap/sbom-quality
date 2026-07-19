package pipeline

import "errors"

// Run executes the pipeline for cfg and returns the final CycloneDX 1.6 JSON.
// Sources: --image (trivy, needs 1.6 down-convert) and/or --go-mod (cyclonedx-gomod,
// emits 1.6 natively). At least one is required. A solo run passes the generator's
// output straight through to validate — no merge tool is invoked. Merging both
// sources is a later slice.
func Run(cfg Config) ([]byte, error) {
	switch {
	case cfg.Image == "" && cfg.GoMod == "":
		return nil, errors.New("at least one of --image or --go-mod is required")
	case cfg.Image != "" && cfg.GoMod != "":
		return nil, errors.New("merging --image and --go-mod is not yet implemented; pass exactly one source")
	}

	var sbom []byte
	var err error
	if cfg.GoMod != "" {
		// Solo gomod: already 1.6, pass through unchanged.
		sbom, err = generateGoMod(cfg.GoMod)
	} else {
		// Solo image: trivy emits 1.7, down-convert to 1.6.
		var raw []byte
		if raw, err = generateImage(cfg.Image); err == nil {
			sbom, err = downConvertTo16(raw)
		}
	}
	if err != nil {
		return nil, err
	}

	if err := validate(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}
