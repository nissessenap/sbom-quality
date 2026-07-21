#!/usr/bin/env bash
# cdxgen fallback compat check (light, non-scored). cdxgen is the documented
# fallback generator for polyglot builds or ecosystems the native build plugins
# don't cover. This asserts only that a cdxgen `-t java` SBOM parses, flows
# through the full --sbom pipeline, and validates as CycloneDX 1.6 — NOT that it
# scores well (it carries 0% hashes and scores lower than the build plugins; see
# #42). No score floor here; the scored gate is scripts/sbomqs-gate-java.sh.
#
# cdxgen defaults to CycloneDX 1.7, so we pin --spec-version 1.6. Requires cdxgen
# (Node) plus a JDK + Maven wrapper (cdxgen runs `mvn dependency:tree`), trivy,
# parlay, sbom-utility. FETCH_LICENSE=false keeps it offline-ish and fast.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality

echo "=== cdxgen -t java (pinned 1.6) on fixture-maven ==="
FETCH_LICENSE=false cdxgen -t java --spec-version 1.6 \
	-o "$WORK/cdxgen.bom.json" "$REPO_ROOT/testdata/fixture-maven"

echo "=== flow through --sbom (pipeline validates 1.6 or fails loud) ==="
"$WORK/sbom-quality" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" \
	--sbom "$WORK/cdxgen.bom.json" -o "$WORK/cdxgen.cdx.json"

# Belt-and-suspenders: the pipeline already validates, but assert it independently
# so this check fails loudly if that ever stops being true.
if ! sbom-utility validate --input-file "$WORK/cdxgen.cdx.json"; then
	echo "::error::cdxgen -t java SBOM failed CycloneDX 1.6 validation after --sbom"
	exit 1
fi
echo "OK: cdxgen -t java flows through --sbom and validates 1.6"
