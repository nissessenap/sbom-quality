#!/usr/bin/env bash
# npm golden gate: build a dependency SBOM from the npm fixture via the recommended
# generator (@cyclonedx/cyclonedx-npm), run it through the full --sbom pipeline, and
# fail if the sbomqs score regresses below its floor or sbom-utility rejects CycloneDX
# 1.6 conformance. Independent of the Go/Java gates: needs only Node, never
# cyclonedx-gomod/ko or a JDK — so those gates never grow a Node dependency.
#
# Gates:
#   npm-solo   --sbom (cyclonedx-npm, native 1.6)   FLOOR
#
# Measured post-pipeline (Node 24, @cyclonedx/cyclonedx-npm latest, sbomqs 2.0.8):
# solo ~8.2. cyclonedx-npm defaults to 1.6 (no flag) and stamps acknowledgement:declared;
# it parks each dep's npm `integrity` on a "distribution" externalReference, which the
# quality-patch stage lifts into component.hashes (where sbomqs credits it) — that lift
# is what carries the score from ~6.8 to ~8.2. No --sbom + --image gate: npm has no
# canonical fixture image builder (unlike Java's Jib); the solo run is the signal.
# Floor sits below the measured number with headroom; ratchet up as stages land.
#
# Requires: Node + npm (fixture package-lock.json is checked in for `npm ci`), network
# to the npm registry, parlay, sbom-utility, sbomqs, jq and git.
set -euo pipefail

FLOOR="${FLOOR:-7.9}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"

# cyclonedx-npm reads the installed node_modules tree, so `npm ci` from the checked-in
# lockfile first (reproducible), then generate a native 1.6 BOM.
( cd "$REPO_ROOT/testdata/fixture-npm" && npm ci --no-audit --no-fund )
( cd "$REPO_ROOT/testdata/fixture-npm" && \
	npx --yes @cyclonedx/cyclonedx-npm@latest --output-format JSON --output-file "$WORK/npm.bom.json" )

"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$WORK/npm.bom.json" -o "$WORK/npm.cdx.json"

# The lift's job: cyclonedx-npm puts the integrity hash on a distribution
# externalReference, not the component. Assert the pipeline surfaced it as a
# component-level checksum — the delta that lifts the score. Component-agnostic, so
# bumping the fixture's deps doesn't break the gate.
if ! jq -e '[.components[] | select(.hashes and (.hashes | length > 0))] | length > 0' "$WORK/npm.cdx.json" >/dev/null; then
	echo "::error::npm SBOM has no component-level checksums — the distribution-hash lift regressed"
	exit 1
fi
echo "OK: quality-patch lifted npm integrity hashes onto components"
gate npm-solo "$FLOOR" "$WORK/npm.cdx.json"
