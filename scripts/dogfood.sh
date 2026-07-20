#!/usr/bin/env bash
# Dogfood: build sbom-quality's own shipped image from source, then scan it with
# sbom-quality itself — the highest-signal e2e, the tool describing the artifact
# it ships. Building from source (not pulling a released tag) means the scan
# reflects THIS commit's tool and packaging, so a PR can't silently ship a
# lower-quality image. Fails if the output is invalid or its sbomqs score drops
# below DOGFOOD_FLOOR.
#
# Requires docker, trivy, sbom-utility, sbomqs. The host binary does the scan and
# trivy reads the freshly-built image straight from the docker daemon — no socket
# mount, that's only needed when trivy runs inside a container.
set -euo pipefail

DOGFOOD_FLOOR="${DOGFOOD_FLOOR:-6.7}"
IMAGE_TAG="${IMAGE_TAG:-sbom-quality:dogfood}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "=== docker build $IMAGE_TAG ==="
docker build -t "$IMAGE_TAG" "$REPO_ROOT"

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
"$WORK/sbom-quality" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" \
	--image "$IMAGE_TAG" -o "$WORK/dogfood.cdx.json"
gate dogfood "$DOGFOOD_FLOOR" "$WORK/dogfood.cdx.json"
