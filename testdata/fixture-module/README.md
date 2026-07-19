# fixture-module

A minimal Go module (one real dependency) used by `scripts/sbomqs-gate.sh` to
generate an SBOM and score it with sbomqs. It is a nested module, so the parent
`go build ./...` ignores it.

`cyclonedx-gomod` derives the primary component's version from git, so the gate
script copies these files into a throwaway git repo before generating.
