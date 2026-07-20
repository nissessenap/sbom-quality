# fixture-gradle

A small-but-real Gradle (Kotlin DSL) Java app used by the sbom-quality
**generator bench** (map #35, ticket #41). Same deps as `../fixture-maven`
(`guava`, `commons-lang3`, `jackson-databind` + transitives) so merge/dedup/
enrich are exercised, and it builds its container image via **Jib**.

## Build

```sh
./gradlew build         # -> build/libs/fixture-gradle.jar
./gradlew jibBuildTar   # -> build/jib-image.tar  (a docker-archive image)
```

`jibBuildTar` needs **no Docker daemon and no registry** — it writes an image
tarball the bench can hand straight to scanners:

```sh
syft scan   docker-archive:build/jib-image.tar
trivy image --input          build/jib-image.tar
```

## Build-env prereqs (discovered)

- **JDK >= 17** on `PATH` (built & verified on JDK 25; `sourceCompatibility`/
  `targetCompatibility` = 17, which Jib also reads to match the base image).
- **Gradle**: pinned by the wrapper (`./gradlew` → Gradle 9.5.1; `gradle-
  wrapper.jar` is committed, standard practice). Needs network for the
  distribution + plugins on first run.
- **Jib** `com.google.cloud.tools.jib` 3.5.4 — pulls the base image
  `eclipse-temurin:17-jre` from Docker Hub.
- **Network** to Maven Central, `plugins.gradle.org`, and Docker Hub on first
  build.

## Notes for the bench (R3 / #38)

Jib's default base is a **full-OS `eclipse-temurin`**, not distroless — the
resulting image scans to ~160 components: OS `deb` packages **plus** the real
`.jar` deps and their transitives. App identity should come from the
build-source SBOM, not the image scan.
