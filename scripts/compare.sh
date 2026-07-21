#!/usr/bin/env bash
# ponytail: throwaway cross-language head-to-head — NOT a CI gate. For each fixture,
# generate an SBOM two ways and score both with sbomqs (same metric the gates use):
#   ours      sbom-quality: recommended generator -> --sbom (Go uses native --go-mod)
#   sbomify   sbomify-action lockfile-mode on the SAME lockfile
# Fail-soft: a broken toolchain for one language just shows "n/a", the rest still run.
# Generation logic is lifted from scripts/sbomqs-gate*.sh. Delete this + compare-out/
# when done. Env: LANGS="go npm" to subset; SBOMIFY_IMAGE=... to pin a different tag.
set -uo pipefail   # deliberately no -e: per-language failures must not abort the run.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"

OUT="${OUT:-$REPO_ROOT/compare-out}"
SBOMIFY_IMAGE="${SBOMIFY_IMAGE:-sbomifyhub/sbomify-action:26.2.0}"
LANGS="${LANGS:-go npm python python-uv rust maven gradle}"
TD="$REPO_ROOT/testdata"
mkdir -p "$OUT"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"
sq() { "$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" "$@"; }   # our tool, run "properly"
score() { [ -s "$1" ] && sbomqs score "$1" --basic | cut -f1 || echo "n/a"; }
comps() { [ -s "$1" ] && jq '.components | length' "$1" 2>/dev/null || echo 0; }

# gen_ours LANG -> writes $OUT/ours-LANG.cdx.json. Mirrors the matching gate script.
gen_ours() {
	local lang="$1" out="$OUT/ours-$1.cdx.json" bom="$WORK/$1.bom.json" d
	rm -f "$out"
	case "$lang" in
	go)
		d="$WORK/go-src"; mkdir -p "$d"; stage_fixture "$TD/fixture-module" "$d"
		sq --go-mod "$d" -o "$out" ;;
	npm)
		d="$WORK/npm-src"; cp -r "$TD/fixture-npm" "$d"
		( cd "$d" && npm ci --no-audit --no-fund \
			&& npx --yes @cyclonedx/cyclonedx-npm@latest --output-format JSON --output-file "$bom" ) \
		&& sq --sbom "$bom" -o "$out" ;;
	python)
		uvx --from cyclonedx-bom cyclonedx-py poetry "$TD/fixture-python" -o "$bom" \
		&& sq --sbom "$bom" -o "$out" ;;
	python-uv)
		uv export --project "$TD/fixture-python-uv" --format cyclonedx1.5 -o "$bom" \
		&& sq --sbom "$bom" -o "$out" ;;
	rust)
		d="$WORK/rust-src"; mkdir -p "$d"; cp -r "$TD/fixture-cargo"/{Cargo.toml,Cargo.lock,src} "$d/"
		( cd "$d" && cargo fetch --locked && cargo cyclonedx --spec-version 1.5 --format json -a ) \
		&& sq --sbom "$d/fixture-cargo.cdx.json" -o "$out" ;;
	maven)
		( cd "$TD/fixture-maven" && ./mvnw -q -B \
			"org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeBom" \
			-DoutputFormat=json -DoutputName=bom -DoutputDirectory="$WORK/mvn" ) \
		&& sq --sbom "$WORK/mvn/bom.json" -o "$out" ;;
	gradle)
		local gst; gst="$(stage_gradle "$TD/fixture-gradle" "$WORK")"
		cat > "$WORK/cdx.init.gradle" <<-EOF
			initscript {
			    repositories { gradlePluginPortal() }
			    dependencies { classpath("org.cyclonedx:cyclonedx-gradle-plugin:2.3.1") }
			}
			allprojects {
			    group = "com.example"; version = "1.0.0"
			    apply plugin: org.cyclonedx.gradle.CycloneDxPlugin
			    tasks.named("cyclonedxBom") { setSchemaVersion("1.6"); setOutputFormat("json"); setIncludeConfigs(["runtimeClasspath"]) }
			}
		EOF
		( cd "$gst" && ./gradlew --no-daemon --init-script "$WORK/cdx.init.gradle" cyclonedxBom ) \
		&& sq --sbom "$gst/build/reports/bom.json" -o "$out" ;;
	esac
}

# gen_sbomify LANG FIXTURE LOCKREL PURL NAME VERSION -> $OUT/sbomify-LANG.cdx.json.
# Copies the fixture into a throwaway workspace so sbomify's scratch files + root-owned
# output don't touch testdata/. Mirrors sbom-generation-example's sbomify-* targets.
gen_sbomify() {
	local lang="$1" fixture="$2" lockrel="$3" purl="$4" name="$5" ver="$6"
	local ws="$WORK/sf-$lang" out="$OUT/sbomify-$lang.cdx.json"
	rm -f "$out"; rm -rf "$ws"; cp -r "$fixture" "$ws"
	docker run --rm \
		-v "$ws":/github/workspace -w /github/workspace -e HOME=/tmp \
		-e LOCK_FILE="/github/workspace/$lockrel" \
		-e OUTPUT_FILE=/github/workspace/sbomify.cdx.json \
		-e SBOM_FORMAT=cyclonedx \
		-e COMPONENT_NAME="$name" -e COMPONENT_VERSION="$ver" -e COMPONENT_PURL="$purl" \
		-e AUGMENT=true -e ENRICH=true -e UPLOAD=false \
		"$SBOMIFY_IMAGE" && cp "$ws/sbomify.cdx.json" "$out" 2>/dev/null
}

# sbomify_args LANG -> "fixture lockrel purl name version" for gen_sbomify.
sbomify_args() {
	case "$1" in
	go)        echo "$TD/fixture-module go.mod pkg:golang/example.com/hello@v0.1.0 hello v0.1.0" ;;
	npm)       echo "$TD/fixture-npm package-lock.json pkg:npm/fixture-npm@1.0.0 fixture-npm 1.0.0" ;;
	python)    echo "$TD/fixture-python poetry.lock pkg:pypi/fixture-python@0.1.0 fixture-python 0.1.0" ;;
	python-uv) echo "$TD/fixture-python-uv uv.lock pkg:pypi/fixture-python-uv@0.1.0 fixture-python-uv 0.1.0" ;;
	rust)      echo "$TD/fixture-cargo Cargo.lock pkg:cargo/fixture-cargo@0.1.0 fixture-cargo 0.1.0" ;;
	maven)     echo "$TD/fixture-maven pom.xml pkg:maven/com.example/fixture-maven@1.0.0 fixture-maven 1.0.0" ;;
	gradle)    echo "$TD/fixture-gradle build.gradle.kts pkg:maven/com.example/fixture-gradle@1.0.0 fixture-gradle 1.0.0" ;;
	esac
}

for lang in $LANGS; do
	echo "########## $lang: ours ##########"
	gen_ours "$lang"
	echo "########## $lang: sbomify ##########"
	# shellcheck disable=SC2046
	gen_sbomify "$lang" $(sbomify_args "$lang")
done

echo
echo "===== head-to-head: sbom-quality vs sbomify-action (sbomqs, higher = better) ====="
printf '%-12s %8s %6s   %8s %6s\n' "language" "ours" "comps" "sbomify" "comps"
printf '%-12s %8s %6s   %8s %6s\n' "--------" "----" "-----" "-------" "-----"
for lang in $LANGS; do
	o="$OUT/ours-$lang.cdx.json"; s="$OUT/sbomify-$lang.cdx.json"
	printf '%-12s %8s %6s   %8s %6s\n' "$lang" "$(score "$o")" "$(comps "$o")" "$(score "$s")" "$(comps "$s")"
done
echo "================================================================================="
echo "files in $OUT/ (sbomify-*.cdx.json are root-owned; sudo rm -rf compare-out when done)"
