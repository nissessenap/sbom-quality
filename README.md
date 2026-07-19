# sbom-quality

Generates quality SBOM which includes enrichment with focus on container images + applications.

It's hopefully a leaner implementation compared to [sbomify-action](https://github.com/sbomify/sbomify-action) which only focuses on generating SBOMs.

Intially [trivy](https://github.com/aquasecurity/trivy) will be the main scanner for container images, this due support of [Dependcy Track](https://dependencytrack.org/).

In the future it will support more tools like [syft](https://github.com/anchore/syft).

It will intially support cyclondx but SPDX is also on the todo.

## Container

The primary artifact is a linux/amd64 image on GHCR bundling the runtime tools
(trivy, cyclonedx-gomod, sbomasm, parlay, sbom-utility). Published on each
`vX.Y.Z` tag as both the version tag and `latest`.

```sh
# image + Go module → one merged 1.6 SBOM on stdout
docker run --rm -v "$PWD":/work ghcr.io/nissessenap/sbom-quality:latest \
  --image alpine:3.20 --go-mod /work --supplier-name "ACME" > sbom.cdx.json
```

The from-source binary (`go build ./cmd/sbom-quality`) runs the identical code
path, expecting the same tools on `$PATH`.

## Validation

Using a number of different tools to determine SBOM quality.

- [sbomqs](https://github.com/interlynk-io/sbomqs)
