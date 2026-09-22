# Thin wrappers over the local loops. All logic lives in the scripts, not here.
.PHONY: test gate dogfood compare

# Unit tests (no external tools needed).
test:
	go test ./...

# CI quality gate: gomod + merged + dogfood sbomqs floors.
gate:
	./scripts/sbomqs-gate.sh

# Build sbom-quality's own image and scan it with itself.
dogfood:
	./scripts/dogfood.sh

# Throwaway: score ours vs sbomify-action vs sbom-generation-example (sbomqs).
compare:
	./scripts/compare.sh
