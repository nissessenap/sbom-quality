#!/usr/bin/env bash
# Build the binary and score its SBOMs with sbomqs, failing if any score
# regresses below its floor. Ratchet the floors up as score-lifting stages
# (enrich/augment/quality-patch) land.
#
# Three gates (one per representative pipeline input):
#   gomod-solo  --go-mod only (pass-through)          FLOOR
#   image-solo  --image only (pass-through)           IMAGE_FLOOR
#   merged      --image + --go-mod (sbomasm merge)    MERGED_FLOOR
#
# Each gate also asserts sbom-utility validates the output — a regression in
# either score or validity fails the build.
#
# Requires cyclonedx-gomod, sbomasm, trivy, sbom-utility and sbomqs on PATH.
# The image/merged gates pull IMAGE (a small public image); trivy runs image-pull only.
set -euo pipefail

FLOOR="${FLOOR:-7.7}"
IMAGE_FLOOR="${IMAGE_FLOOR:-6.6}"
MERGED_FLOOR="${MERGED_FLOOR:-6.8}"
IMAGE="${IMAGE:-alpine:3.20}"
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

# gate NAME FLOOR FILE — validate the SBOM, print its score report, and fail if
# it is invalid or the score drops below FLOOR.
gate() {
	local name="$1" floor="$2" file="$3" score
	echo "=== $name sbom-utility validate ==="
	if ! sbom-utility validate --input-file "$file"; then
		echo "::error::$name failed sbom-utility validation"
		exit 1
	fi
	echo "=== $name sbomqs score ==="
	sbomqs score "$file"
	score="$(sbomqs score "$file" --basic | cut -f1)"
	echo "$name score=$score floor=$floor"
	if awk -v s="$score" -v f="$floor" 'BEGIN { exit !(s + 0 < f + 0) }'; then
		echo "::error::$name sbomqs score $score is below floor $floor — SBOM quality regressed"
		exit 1
	fi
	echo "OK: $name score $score meets floor $floor"
}

"$WORK/sbom-quality" --go-mod "$WORK" --supplier-name "sbom-quality CI" --author "sbom-quality CI" -o "$WORK/gomod.cdx.json"
gate gomod-solo "$FLOOR" "$WORK/gomod.cdx.json"

"$WORK/sbom-quality" --image "$IMAGE" --supplier-name "sbom-quality CI" --author "sbom-quality CI" -o "$WORK/image.cdx.json"
gate image-solo "$IMAGE_FLOOR" "$WORK/image.cdx.json"

"$WORK/sbom-quality" --image "$IMAGE" --go-mod "$WORK" --supplier-name "sbom-quality CI" --author "sbom-quality CI" -o "$WORK/merged.cdx.json"
gate merged "$MERGED_FLOOR" "$WORK/merged.cdx.json"
