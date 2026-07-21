#!/usr/bin/env bash
# Python golden gate: generate a dependency SBOM from the poetry fixture via the
# recommended generator (cyclonedx-python, native 1.6), run it through the full
# --sbom pipeline, and fail if the sbomqs score regresses below its floor or
# sbom-utility rejects CycloneDX 1.6 conformance. Independent of the Go/Java gates:
# needs only cyclonedx-py (run via uvx), never cyclonedx-gomod/ko/a JDK.
#
# Gates:
#   python-solo   --sbom (cyclonedx-py poetry, native 1.6)   FLOOR
#
# cyclonedx-py reads the committed poetry.lock directly (no poetry binary needed).
# The lock is frozen, so component set + hashes are deterministic; only parlay's
# ecosyste.ms enrichment is live, hence the floor sits below the measured number.
#
# Measured post-pipeline (cyclonedx-py 7.3.0, sbomqs 2.0.8): solo ~8.3. The score
# depends on quality-patch #6 lifting each dep's poetry.lock-pinned SHA-256 out of
# externalReferences[distribution] into a component-level hash — cyclonedx-py parks
# it there, where sbomqs' integrity check otherwise can't see it.
#
# Requires: uv (for uvx), network to PyPI + ecosyste.ms, parlay, sbom-utility,
# sbomqs, jq, git. No image => no trivy/sbomasm merge (the Go/Java gates cover that).
set -euo pipefail

FLOOR="${FLOOR:-7.9}"
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

# Assert quality-patch #6 actually lifted a poetry.lock SHA-256 onto a pypi
# component (the integrity signal sbomqs credits) — kept component-agnostic so
# bumping the fixture's deps doesn't break the gate.
if ! jq -e '.components[] | select(.purl // "" | startswith("pkg:pypi/")) | .hashes[]? | select(.alg == "SHA-256")' "$WORK/py.cdx.json" >/dev/null; then
	echo "::error::python SBOM has no SHA-256 on any pypi component — quality-patch checksum lift regressed"
	exit 1
fi
echo "OK: quality-patch lifted a poetry.lock SHA-256 onto a pypi component"
gate python-solo "$FLOOR" "$WORK/py.cdx.json"
