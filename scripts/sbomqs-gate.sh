#!/usr/bin/env bash
# Generate an SBOM from testdata/fixture-module with the built binary, score it
# with sbomqs, and fail if the score regresses below FLOOR. Ratchet FLOOR up as
# score-lifting stages (enrich/augment/quality-patch) land. Requires cyclonedx-gomod,
# sbom-utility and sbomqs on PATH.
set -euo pipefail

FLOOR="${FLOOR:-6.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# cyclonedx-gomod reads the module version from git, so stage the fixture in a
# throwaway repo (the checked-in fixture can't carry its own .git).
cp "$REPO_ROOT"/testdata/fixture-module/{go.mod,go.sum,main.go} "$WORK/"
git -C "$WORK" init -q
git -C "$WORK" add -A
git -C "$WORK" -c user.email=ci@example.com -c user.name=ci commit -qm fixture
git -C "$WORK" tag v0.1.0

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
"$WORK/sbom-quality" --go-mod "$WORK" --supplier-name "sbom-quality CI" -o "$WORK/out.cdx.json"

echo "=== sbomqs score ==="
sbomqs score "$WORK/out.cdx.json"

SCORE="$(sbomqs score "$WORK/out.cdx.json" --basic | cut -f1)"
echo "score=$SCORE floor=$FLOOR"
if awk -v s="$SCORE" -v f="$FLOOR" 'BEGIN { exit !(s + 0 < f + 0) }'; then
	echo "::error::sbomqs score $SCORE is below floor $FLOOR — SBOM quality regressed"
	exit 1
fi
echo "OK: sbomqs score $SCORE meets floor $FLOOR"
