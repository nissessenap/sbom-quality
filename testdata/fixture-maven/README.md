# fixture-maven

A small-but-real Maven Java app used by the sbom-quality **generator bench**
(map #35, ticket #41). It has a handful of real third-party deps — `guava`,
`commons-lang3`, `jackson-databind` (which pulls its own transitives) — so the
merge/dedup/enrich stages have something to chew on.

## Build

```sh
./mvnw package        # -> target/fixture-maven-1.0.0.jar
```

## Build-env prereqs (discovered)

- **JDK >= 17** on `PATH` (built & verified on JDK 25; bytecode targets 17 via
  `maven.compiler.release`, so it runs on any JDK >= 17).
- **Maven**: pinned by the wrapper (`./mvnw` downloads Apache Maven 3.9.9 on
  first run — needs network to `repo.maven.apache.org` + Maven Central). No
  `maven-wrapper.jar` is committed; modern wrapper bootstraps itself.
- **Network** to Maven Central for deps on first build.

This fixture produces a **jar artifact** (no container). Jib lives on the
Gradle fixture; see `../fixture-gradle`.
