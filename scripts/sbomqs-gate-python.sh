#!/usr/bin/env bash
# Python golden gate: generate a dependency SBOM from the poetry fixture via the
# recommended generator (cyclonedx-python, native 1.6), run it through the full
# --sbom pipeline, and fail if the sbomqs score regresses below its floor or
# sbom-utility rejects CycloneDX 1.6 conformance. Independent of the Go/Java gates:
# needs only cyclonedx-py (run via uvx), never cyclonedx-gomod/ko/a JDK.
#
# Gates:
#   python-solo   --sbom (cyclonedx-py poetry, native 1.6)    FLOOR
#   python-uv     --sbom (uv export cyclonedx1.5, up-converted) UV_FLOOR
#
# cyclonedx-py reads the committed poetry.lock directly (no poetry binary needed).
# The lock is frozen, so component set + hashes are deterministic; only parlay's
# ecosyste.ms enrichment is live, hence the floor sits below the measured number.
#
# poetry.lock is platform-independent: cyclonedx-py records one SHA-256 per platform
# wheel under externalReferences[distribution]. quality-patch lifts the one canonical
# platform-independent artifact's hash (the universal py3-none-any wheel, else the
# sdist) onto the component — faithful, since it verifies on every platform — and never
# an arbitrary platform wheel. That recovers the heavily-weighted Integrity category, so
# the floor is ratcheted up accordingly.
#
# Requires: uv (for uvx), network to PyPI + ecosyste.ms, parlay, sbom-utility,
# sbomqs, jq, git. No image => no trivy/sbomasm merge (the Go/Java gates cover that).
set -euo pipefail

FLOOR="${FLOOR:-8.0}"
UV_FLOOR="${UV_FLOOR:-6.3}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The user's shell may default UV_INDEX_URL to a private mirror; the fixture must
# resolve against public PyPI only.
unset UV_INDEX_URL

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"

# cyclonedx-python emits a native 1.6 dependency SBOM with a primary component and
# the dependency graph straight from poetry.lock — no flags, no code in our pipeline.
uvx --from cyclonedx-bom cyclonedx-py poetry "$REPO_ROOT/testdata/fixture-python" -o "$WORK/py.bom.json"
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$WORK/py.bom.json" -o "$WORK/py.cdx.json"

# Assert quality-patch lifted the CANONICAL artifact's hash for multi-wheel pypi deps:
# at least one pypi component must now carry a component hash, and for every pypi
# component that took the canonical-fallback path (i.e. had MORE THAN ONE distribution
# ref — the fast path only fires on a single-artifact ref set) every lifted hash must
# match a distribution ref whose URL is the universal wheel (…py3-none-any.whl) or sdist
# (….tar.gz) — never an arbitrary platform wheel. That invariant is component-agnostic
# for multi-ref pypi deps, so bumping the fixture's deps doesn't break the gate. (see
# quality_patch.go liftDistributionHashes.)
if ! jq -e '[.components[] | select(.purl // "" | startswith("pkg:pypi/")) | select(.hashes // [] | length > 0)] | length > 0' "$WORK/py.cdx.json" >/dev/null; then
	echo "::error::no pypi component carries a lifted component hash — the canonical-artifact lift regressed"
	exit 1
fi
if jq -e '.components[] | select(.purl // "" | startswith("pkg:pypi/")) | select(.hashes // [] | length > 0)
  | select([.externalReferences[]? | select(.type == "distribution")] | length > 1)
  | . as $c
  | [$c.externalReferences[]? | select(.type == "distribution" and ((.url // "" | endswith("py3-none-any.whl")) or (.url // "" | endswith(".tar.gz")))) | .hashes[]?.content] as $canon
  | select(any($c.hashes[].content; . as $h | ($canon | index($h)) | not))' "$WORK/py.cdx.json" >/dev/null; then
	echo "::error::a pypi component hash does not match its universal-wheel/sdist ref — an arbitrary platform wheel was lifted"
	exit 1
fi
echo "OK: pypi components carry the universal-wheel/sdist SHA-256, not an arbitrary platform wheel"
gate python-solo "$FLOOR" "$WORK/py.cdx.json"

# uv path: uv exports CycloneDX 1.5 natively (no cyclonedx-py) from the committed,
# frozen uv.lock; the pipeline accepts >=1.5 and up-converts to 1.6. The differentiator
# vs the requirements hop is that uv keeps a primary component — assert it survives.
uv export --project "$REPO_ROOT/testdata/fixture-python-uv" --format cyclonedx1.5 -o "$WORK/uv.bom.json"
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$WORK/uv.bom.json" -o "$WORK/uv.cdx.json"
if ! jq -e '.metadata.component.name' "$WORK/uv.cdx.json" >/dev/null; then
	echo "::error::uv SBOM lost its primary component through the pipeline"
	exit 1
fi
echo "OK: uv native 1.5 up-converted to 1.6 with its primary component intact"
gate python-uv "$UV_FLOOR" "$WORK/uv.cdx.json"
