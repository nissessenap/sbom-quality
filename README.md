# sbom-quality

Generates quality SBOM which includes enrichment with focus on container images + applications.

It's hopefully a leaner implementation compared to [sbomify-action](https://github.com/sbomify/sbomify-action) which only focuses on generating SBOMs.

Intially [trivy](https://github.com/aquasecurity/trivy) will be the main scanner for container images, this due support of [Dependcy Track](https://dependencytrack.org/).

In the future it will support more tools like [syft](https://github.com/anchore/syft).

It will intially support cyclondx but SPDX is also on the todo.

## Validation

Using a number of different tools to determine SBOM quality.

- [sbomqs](https://github.com/interlynk-io/sbomqs)
