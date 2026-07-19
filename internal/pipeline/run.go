package pipeline

import "errors"

// Run executes the pipeline for cfg and returns the final CycloneDX 1.6 JSON.
// Sources: --image (trivy, needs 1.6 down-convert) and/or --go-mod (cyclonedx-gomod,
// emits 1.6 natively). At least one is required. With both sources the two SBOMs
// are merged (trivy primary) via sbomasm; a solo run passes the generator's output
// straight through. The merged-or-solo SBOM is then enriched by parlay (unless
// --skip-enrichment) before validate — no merge tool is invoked for a solo run.
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

	// enrich: parlay fills supplier/license/VCS for Go components from the
	// registry. --skip-enrichment is the sole opt-out; otherwise fail-loud.
	if !cfg.SkipEnrichment {
		if sbom, err = enrich(sbom); err != nil {
			return nil, err
		}
	}

	// augment: fill document-identity metadata. VCS autodetect runs here (not via
	// kong env: tags) so flag > autodetect > generator precedence holds.
	var vcs vcsInfo
	if !cfg.NoCIAutodetect {
		vcs = detectGitHubVCS()
	}
	if sbom, err = augment(sbom, cfg, vcs); err != nil {
		return nil, err
	}

	if err := validate(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}
