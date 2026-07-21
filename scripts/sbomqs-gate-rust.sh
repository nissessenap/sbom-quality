#!/usr/bin/env bash
# Rust golden gate: build a dependency SBOM from the cargo fixture via BOTH supported
# generators, run each through the full --sbom pipeline, and fail if the sbomqs score
# regresses below its floor or sbom-utility rejects CycloneDX 1.6 conformance. Independent
# of the Go/Java/npm gates — those gates never grow a Rust dependency.
#
# Two sub-gates, one per generator (the tool supports both; see docs/rust.md):
#   rust-cargo    cargo-cyclonedx --spec-version 1.5  (native tool; 1.5 up-converted to 1.6)
#   rust-cdxgen   cdxgen -t rust --spec-version 1.6   (polyglot; native 1.6)
#
# Measured post-pipeline (rustc 1.86, cargo-cyclonedx 0.5.9, cdxgen 11.1.5, sbomqs 2.0.8):
# cargo ~8.2, cdxgen ~8.3, both grade B. Both carry SHA-256 hashes, SPDX license
# expressions and pkg:cargo purls, so the language-blind back half lifts them with zero
# code delta beyond the acquire guard now accepting 1.5 (up-converts to 1.6 — cargo-cyclonedx
# maxes at 1.5, its 1.6 support is upstream CycloneDX/cyclonedx-rust-cargo#769). No
# --sbom + --image gate: cargo has no canonical fixture-image builder (unlike Java's Jib);
# the solo runs are the signal. Floor sits below both measured numbers with headroom.
#
# Requires: cargo + cargo-cyclonedx, cdxgen, parlay, sbom-utility, sbomqs, jq, git — and
# network: `cargo fetch` and cdxgen's FETCH_LICENSE both pull from crates.io, and parlay
# hits ecosyste.ms. The checked-in Cargo.lock only makes the dependency graph deterministic.
set -euo pipefail

FLOOR="${FLOOR:-8.0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"

# Copy the fixture into a scratch dir so cargo-cyclonedx can drop its BOM next to the
# crate without polluting the tracked testdata tree.
CARGO_SRC="$WORK/cargo-src"
mkdir -p "$CARGO_SRC"
cp -r "$REPO_ROOT/testdata/fixture-cargo"/{Cargo.toml,Cargo.lock,src} "$CARGO_SRC/"

# rust_subgate NAME BOM — run the BYO SBOM through the pipeline, assert an SPDX
# expression survived the quality-patch unwrap, then score-gate it. Rust crates license
# as expressions (`MIT OR Apache-2.0`); the unwrap must preserve them as a declared
# license.name (credited, NOT dropped — the #67/#63 concern). Component-agnostic: any
# surviving compound expression counts, so a fixture dep bump can't silently break it.
rust_subgate() {
	local name="$1" bom="$2"
	local out="$WORK/$name.cdx.json"
	"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$bom" -o "$out"
	if ! jq -e '[.components[] | select(.licenses) | .licenses[] | select(.license.name and (.license.name | contains(" OR ")))] | length > 0' "$out" >/dev/null; then
		echo "::error::$name: no SPDX-expression license survived as a declared license.name — the expression unwrap regressed"
		exit 1
	fi
	echo "OK: $name SPDX license expressions preserved as declared licenses"
	gate "$name" "$FLOOR" "$out"
}

# cargo-cyclonedx: native tool. Reads licenses from each crate's Cargo.toml, so `cargo
# fetch` must populate the registry cache first. --spec-version 1.5 is its ceiling; the
# acquire guard up-converts to 1.6. It writes <crate>.cdx.json into the crate dir.
( cd "$CARGO_SRC" && cargo fetch --locked && cargo cyclonedx --spec-version 1.5 --format json -a )
rust_subgate rust-cargo "$CARGO_SRC/fixture-cargo.cdx.json"

# cdxgen: polyglot generator, emits 1.6 directly. FETCH_LICENSE pulls SPDX licenses from
# crates.io (they aren't in Cargo.lock); --spec-version 1.6 pins the output.
( cd "$CARGO_SRC" && FETCH_LICENSE=true cdxgen -t rust --spec-version 1.6 -o "$WORK/cdxgen.bom.json" . )
rust_subgate rust-cdxgen "$WORK/cdxgen.bom.json"
