# sbom-quality

Generates quality SBOM which includes enrichment with focus on container images + applications.

It's hopefully a leaner implementation compared to [sbomify-action](https://github.com/sbomify/sbomify-action) which only focuses on generating SBOMs.

Intially [trivy](https://github.com/aquasecurity/trivy) will be the main scanner for container images, this due support of [Dependcy Track](https://dependencytrack.org/).

In the future it will support more tools like [syft](https://github.com/anchore/syft).

It will intially support cyclondx but SPDX is also on the todo.

## Container

The primary artifact is a multi-arch (linux/amd64, linux/arm64) image on GHCR
bundling the runtime tools (trivy, cyclonedx-gomod, sbomasm, parlay,
sbom-utility). Published on each `vX.Y.Z` tag as both the version tag and
`latest`.

```sh
# image + Go module → one merged 1.6 SBOM on stdout
docker run --rm -v "$PWD":/work ghcr.io/nissessenap/sbom-quality:latest \
  --image alpine:3.20 --go-mod /work --supplier-name "ACME" > sbom.cdx.json
```

`--go-mod` assumes `main` sits at the module root. For the usual `./cmd/<app>`
layout, point `--go-main` at it (relative to `--go-mod`):

```sh
docker run --rm -v "$PWD":/work ghcr.io/nissessenap/sbom-quality:latest \
  --go-mod /work --go-main ./cmd/myapp --supplier-name "ACME" > sbom.cdx.json
```

`--trivy-arg` forwards a flag verbatim to trivy (repeatable, requires `--image`)
— use it to scope the scan (`--skip-dirs`) or pin a platform on a multi-arch
index (`--platform linux/amd64`):

```sh
docker run --rm ghcr.io/nissessenap/sbom-quality:latest \
  --image repo:tag --trivy-arg=--platform --trivy-arg=linux/amd64 \
  --supplier-name "ACME" > sbom.cdx.json
```

For Java (or any build env), bring your own CycloneDX dependency SBOM — e.g. one
produced by `cyclonedx-maven` / `cyclonedx-gradle` in your CI — via `--sbom`
(mutually exclusive with `--go-mod`, `--image` optional). No Java toolchain is
bundled; the `--sbom` path is pure Go, accepts CycloneDX 1.6/1.7, and rejects
anything older.

```sh
# BYO Java dependency SBOM + Jib image → one merged 1.6 SBOM
docker run --rm -v "$PWD":/work ghcr.io/nissessenap/sbom-quality:latest \
  --sbom /work/deps.cdx.json --image repo:tag --supplier-name "ACME" > sbom.cdx.json
```

See [docs/java.md](docs/java.md) for pinned, runnable Maven and Gradle build-plugin
examples (and the cdxgen fallback and its trade-offs).

The from-source binary (`go build ./cmd/sbom-quality`) runs the identical code
path, expecting the same tools on `$PATH`.

## Verifying what we ship

Each released image carries two keyless (Sigstore/Fulcio) attestations bound to
its digest: SLSA build provenance (how it was built) and a CycloneDX SBOM (what's
in it). Verify them before trusting the image:

```sh
img=ghcr.io/nissessenap/sbom-quality:latest
gh attestation verify "oci://$img" --repo nissessenap/sbom-quality
gh attestation verify "oci://$img" --repo nissessenap/sbom-quality \
  --predicate-type https://cyclonedx.org/bom
```

## Validation

Using a number of different tools to determine SBOM quality.

- [sbomqs](https://github.com/interlynk-io/sbomqs)
