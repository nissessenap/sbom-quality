package pipeline

import (
	"errors"
	"os"
)

// Run executes the pipeline for cfg and returns the final CycloneDX 1.6 JSON.
// Sources: --image (trivy, needs 1.6 down-convert) plus at most one build source —
// --go-mod (cyclonedx-gomod, native 1.6) XOR --sbom (a bring-your-own CycloneDX
// dependency SBOM, e.g. from cyclonedx-maven/gradle, normalized to 1.6). At least
// one source is required. With an image + a build source the two SBOMs are merged
// (image primary, so OS packages are retained) via sbomasm; a solo run passes the
// source straight through. The merged-or-solo SBOM is then enriched by parlay
// (unless --skip-enrichment) before validate — no merge tool is invoked for a solo run.
func Run(cfg Config) ([]byte, error) {
	if cfg.GoMod != "" && cfg.SBOM != "" {
		return nil, errors.New("--go-mod and --sbom are mutually exclusive")
	}
	if cfg.Image == "" && cfg.GoMod == "" && cfg.SBOM == "" {
		return nil, errors.New("at least one of --image, --go-mod, or --sbom is required")
	}

	var image, buildSBOM []byte
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
	switch {
	case cfg.GoMod != "":
		// gomod emits 1.6 natively.
		if buildSBOM, err = generateGoMod(cfg.GoMod); err != nil {
			return nil, err
		}
	case cfg.SBOM != "":
		// BYO CycloneDX dependency SBOM: validate at the trust boundary + normalize to 1.6.
		if buildSBOM, err = acquireSBOM(cfg.SBOM, os.Stderr); err != nil {
			return nil, err
		}
	}

	var sbom []byte
	switch {
	case cfg.Image != "" && buildSBOM != nil:
		// Both sources: merge image (primary, keeps OS packages) with the build SBOM.
		if sbom, err = merge(image, buildSBOM); err != nil {
			return nil, err
		}
	case cfg.Image != "":
		sbom = image // solo image, pass through
	default:
		sbom = buildSBOM // solo build source, pass through
	}

	// enrich: parlay fills supplier/license/VCS for Go and Maven components from
	// the registry. --skip-enrichment is the sole opt-out; otherwise fail-loud.
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

	// quality-patch: native score-tuning (license shape, compositions, wrapper
	// supplier/license back-fill). Runs after augment so the doc supplier and
	// primary-component license it back-fills are already set.
	if sbom, err = qualityPatch(sbom); err != nil {
		return nil, err
	}

	if sbom, err = validate(sbom); err != nil {
		return nil, err
	}
	return sbom, nil
}
