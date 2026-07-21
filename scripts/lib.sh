#!/usr/bin/env bash
# Shared helpers for the gate and dogfood scripts. Source it; don't run it.
# Keeps the fixture-staging, ko-build, and score-gate logic in one place so the
# three scripts can't drift apart.

# Document-identity flags for every SBOM these scripts generate. They describe
# sbom-quality-the-producer, so they're identical across gate and dogfood —
# and setting them fully is the point: we gate the tool used properly, not a
# deliberately-degraded run.
SQ_IDENTITY=(
	--supplier-name "sbom-quality"
	--supplier-url "https://github.com/NissesSenap/sbom-quality"
	--supplier-contact "sbom-quality maintainers"
	--author "sbom-quality CI"
	--manufacturer "sbom-quality"
)

# Primary-component license. Every subject we generate for is our own repo code
# (the fixture module and sbom-quality itself), all Apache-2.0 — a faithful
# declared fact. Kept off SQ_IDENTITY because it describes the *subject*, not the
# producer: a gate over a third-party image must not blanket-claim it.
SQ_LICENSE="Apache-2.0"

# stage_fixture SRC DST — copy the fixture module into DST and make it a git repo.
# cyclonedx-gomod and ko both read the module version from git, and the checked-in
# fixture can't carry its own .git.
stage_fixture() {
	local src="$1" dst="$2"
	cp "$src"/{go.mod,go.sum,main.go} "$dst/"
	git -C "$dst" init -q
	git -C "$dst" add -A
	git -C "$dst" -c user.email=ci@example.com -c user.name=ci commit -qm fixture
	git -C "$dst" tag v0.1.0
}

# stage_gradle SRC DST — copy the Gradle fixture's build inputs into a fresh dir
# under DST with a clean, remote-less git repo, and echo that dir. The
# cyclonedx-gradle plugin derives a VCS external reference from git origin; a
# scp-style origin (git@host:org/repo) normalizes to a non-IRI URL that fails CDX
# 1.6 validation. Building from a remote-less checkout makes the gate deterministic
# regardless of the host's git remote (in GitHub CI the origin is https, valid).
stage_gradle() {
	local src="$1" dst="$2/gradle-src"
	mkdir -p "$dst"
	cp -r "$src"/{build.gradle.kts,settings.gradle.kts,gradlew,gradle,src} "$dst/"
	git -C "$dst" init -q
	git -C "$dst" add -A
	git -C "$dst" -c user.email=ci@example.com -c user.name=ci commit -qm fixture
	echo "$dst"
}

# ko_build_fixture DIR — ko-build the staged module in DIR into the local docker
# daemon and echo the resulting image ref (build logs go to stderr). Uses ko's
# default base (chainguard static) unpinned — deliberately realistic to how ko is
# used by default; the score floors are the tripwire if that base ever degrades.
ko_build_fixture() {
	( cd "$1" && KO_DOCKER_REPO=ko.local ko build --local --bare . )
}

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
