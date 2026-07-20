#!/usr/bin/env bash
# Build the binary and score its SBOMs with sbomqs, failing if any score
# regresses below its floor. Ratchet the floors up as score-lifting stages
# (enrich/augment/quality-patch) land.
#
# Gates:
#   gomod-solo  --go-mod only (pass-through)                       FLOOR
#   merged      ko-built Go image + --go-mod (real sbomasm merge)  MERGED_FLOOR
#   dogfood     sbom-quality scans its own image (scripts/dogfood.sh)
#
# The merged gate ko-builds the fixture into a Go image (ko's default base) so the
# merge does its real job — back-filling trivy's thin Go entries from gomod
# (alpine has no Go, so its components never overlap). It asserts a merged Go
# component carries a gomod-sourced SHA-256 hash — which trivy's image scan never
# emits — proving the back-fill actually happened, not just that a merge ran.
#
# Requires cyclonedx-gomod, sbomasm, trivy, sbom-utility, sbomqs, ko, jq and a
# docker daemon (ko --local loads the fixture image; the dogfood gate builds the
# tool image).
set -euo pipefail

FLOOR="${FLOOR:-7.9}"
MERGED_FLOOR="${MERGED_FLOOR:-6.4}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

stage_fixture "$REPO_ROOT/testdata/fixture-module" "$WORK"
go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"

"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --go-mod "$WORK" -o "$WORK/gomod.cdx.json"
gate gomod-solo "$FLOOR" "$WORK/gomod.cdx.json"

IMG="$(ko_build_fixture "$WORK")"
echo "ko-built fixture image: $IMG"
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --image "$IMG" --go-mod "$WORK" -o "$WORK/merged.cdx.json"
# The merge's core job: back-fill trivy's thin Go entries from gomod. trivy's
# image scan lists Go modules with a version but no hashes; gomod supplies the
# SHA-256. A SHA-256 on any Go component is proof the back-fill ran — kept
# component-agnostic so bumping the fixture's deps doesn't break the gate.
if ! jq -e '.components[] | select(.purl // "" | startswith("pkg:golang/")) | .hashes[]? | select(.alg == "SHA-256")' "$WORK/merged.cdx.json" >/dev/null; then
	echo "::error::merged SBOM has no gomod-sourced SHA-256 hash on any Go component — merge back-fill regressed"
	exit 1
fi
echo "OK: merge back-filled a gomod SHA-256 hash onto a trivy Go component"
gate merged "$MERGED_FLOOR" "$WORK/merged.cdx.json"

# The tool describing the artifact it ships — highest-signal e2e.
"$REPO_ROOT/scripts/dogfood.sh"
