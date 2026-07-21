#!/usr/bin/env bash
# Java golden gate: build dependency SBOMs from the Maven + Gradle fixtures via the
# recommended build plugins (cyclonedx-maven / cyclonedx-gradle), run each through
# the full --sbom pipeline, and fail if the sbomqs score regresses below its floor
# or sbom-utility rejects CycloneDX 1.6 conformance. Independent of the Go gate:
# needs a JDK + the build plugins, never cyclonedx-gomod/ko — so the Go gate never
# grows a JVM dependency.
#
# Gates:
#   maven-solo     --sbom (cyclonedx-maven build plugin, native 1.6)      FLOOR
#   gradle-solo    --sbom (cyclonedx-gradle build plugin, native 1.6)     FLOOR
#   gradle-merged  Jib image + --sbom (real sbomasm merge)                MERGED_FLOOR
#
# Measured post-pipeline (JDK 25, cyclonedx-maven 2.9.1, cyclonedx-gradle 2.3.1,
# sbomqs 2.0.8): solo ~8.3, merged ~6.6. Merged scores LOWER, not higher: Jib's
# default base is a full-OS eclipse-temurin, so trivy's image scan adds ~140 OS deb
# components that dilute field coverage. The image is additive — app identity comes
# from the build-source SBOM (see #38) — which is exactly why the merge keeps the
# app jars' hashes. Floors sit below the measured numbers with headroom; ratchet up
# as score-lifting stages land.
#
# Requires: a JDK >=17, the Maven wrapper (fixture ./mvnw) and Gradle wrapper
# (fixture ./gradlew) with network to Maven Central + the Gradle Plugin Portal,
# trivy, sbomasm, parlay, sbom-utility, sbomqs, jq, git and a docker daemon (Jib's
# jibDockerBuild loads the fixture image locally).
set -euo pipefail

FLOOR="${FLOOR:-7.9}"
MERGED_FLOOR="${MERGED_FLOOR:-6.2}"
CDX_MAVEN_VERSION="${CDX_MAVEN_VERSION:-2.9.1}"
CDX_GRADLE_VERSION="${CDX_GRADLE_VERSION:-2.3.1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$REPO_ROOT/scripts/lib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

go build -C "$REPO_ROOT" -o "$WORK/sbom-quality" ./cmd/sbom-quality
SQ="$WORK/sbom-quality"

# --- Maven: the build plugin emits a native 1.6 dependency SBOM. Invoked fully
# qualified from the CLI so the fixture pom stays plugin-free. ---
( cd "$REPO_ROOT/testdata/fixture-maven" && ./mvnw -q -B \
	"org.cyclonedx:cyclonedx-maven-plugin:${CDX_MAVEN_VERSION}:makeBom" \
	-DoutputFormat=json -DoutputName=bom -DoutputDirectory="$WORK/maven" )
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$WORK/maven/bom.json" -o "$WORK/maven.cdx.json"
gate maven-solo "$FLOOR" "$WORK/maven.cdx.json"

# --- Gradle: stage into a remote-less checkout (see stage_gradle) and apply the
# cyclonedx-gradle plugin via an init script so the fixture build.gradle.kts stays
# a pure Jib fixture. group/version are set so the primary component isn't
# "unspecified". ---
GST="$(stage_gradle "$REPO_ROOT/testdata/fixture-gradle" "$WORK")"
cat > "$WORK/cyclonedx.init.gradle" <<EOF
initscript {
    repositories { gradlePluginPortal() }
    dependencies { classpath("org.cyclonedx:cyclonedx-gradle-plugin:${CDX_GRADLE_VERSION}") }
}
allprojects {
    group = "com.example"
    version = "1.0.0"
    apply plugin: org.cyclonedx.gradle.CycloneDxPlugin
    tasks.named("cyclonedxBom") {
        setSchemaVersion("1.6")
        setOutputFormat("json")
        setIncludeConfigs(["runtimeClasspath"])
    }
}
EOF
( cd "$GST" && ./gradlew --no-daemon --init-script "$WORK/cyclonedx.init.gradle" cyclonedxBom )
GRADLE_BOM="$GST/build/reports/bom.json"
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" --sbom "$GRADLE_BOM" -o "$WORK/gradle.cdx.json"
gate gradle-solo "$FLOOR" "$WORK/gradle.cdx.json"

# --- Gradle + Jib image merge: build the Jib image into the local docker daemon
# (no registry) and merge it with the build-source SBOM. The full-OS base exercises
# validate's stale-SPDX-id repair (trivy emits Artistic-dist, an SPDX id newer than
# the validator's list — demoted to a free-form name so the doc stays 1.6-valid). ---
( cd "$GST" && ./gradlew --no-daemon jibDockerBuild )
"$SQ" "${SQ_IDENTITY[@]}" --license "$SQ_LICENSE" \
	--image fixture-gradle:latest --sbom "$GRADLE_BOM" -o "$WORK/gradle-merged.cdx.json"
# The merge's job: unite the image scan (OS packages, image-only) with the
# build-source SBOM (the app jars). Assert both views survived — a pkg:deb OS
# component (only trivy sees it) and a pkg:maven app component (the build source).
# Component-agnostic, so bumping the fixture's deps doesn't break the gate.
if ! jq -e '[.components[] | (.purl // "")] | any(startswith("pkg:deb/"))' "$WORK/gradle-merged.cdx.json" >/dev/null \
	|| ! jq -e '[.components[] | (.purl // "")] | any(startswith("pkg:maven/"))' "$WORK/gradle-merged.cdx.json" >/dev/null; then
	echo "::error::merged SBOM missing an OS (pkg:deb) or app (pkg:maven) component — Jib image+build-source merge regressed"
	exit 1
fi
echo "OK: merge united the image (pkg:deb) and build-source (pkg:maven) views"
gate gradle-merged "$MERGED_FLOOR" "$WORK/gradle-merged.cdx.json"
