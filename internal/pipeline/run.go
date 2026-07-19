package pipeline

import "errors"

// Run executes the pipeline for cfg and returns the final CycloneDX 1.6 JSON.
// Sources: --image (trivy, needs 1.6 down-convert) and/or --go-mod (cyclonedx-gomod,
// emits 1.6 natively). At least one is required. With both sources the two SBOMs
// are merged (trivy primary) via sbomasm; a solo run passes the generator's output
// straight through to validate — no merge tool is invoked.
func Run(cfg Config) ([]byte, error) {
	if cfg.Image == "" && cfg.GoMod == "" {
		return nil, errors.New("at least one of --image or --go-mod is required")
	}

	var image, gomod []byte
	var err error
	if cfg.Image != "" {
		// trivy emits 1.7; down-convert to 1.6 before merge/validate.
		var raw []byte
		if raw, err = generateImage(cfg.Image); err != nil {
			return nil, err
		}
		if image, err = downConvertTo16(raw); err != nil {
			return nil, err
		}
	}
	if cfg.GoMod != "" {
		// gomod emits 1.6 natively.
		if gomod, err = generateGoMod(cfg.GoMod); err != nil {
			return nil, err
		}
	}

	var sbom []byte
	switch {
	case cfg.Image != "" && cfg.GoMod != "":
		// Both sources: merge trivy (primary, keeps OS packages) with gomod.
		if sbom, err = merge(image, gomod); err != nil {
			return nil, err
		}
	case cfg.Image != "":
		sbom = image // solo image, pass through
	default:
		sbom = gomod // solo gomod, pass through
	}

	if err := validate(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}
