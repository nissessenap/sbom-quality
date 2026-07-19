# CLAUDE.md

`sbom-quality` is a Go CLI that orchestrates external binaries (trivy, cyclonedx-gomod,
sbomasm, parlay, sbom-utility) into a single high-quality **CycloneDX 1.6** SBOM. It does
not reimplement SBOM generation — it wires good tools through a fixed linear pipeline:
`generate → merge → enrich → augment → quality-patch → validate`.

The locked MVP spec lives in **GitHub issue #15** — read it before non-trivial work.

## Layout

- `cmd/sbom-quality` — flat kong CLI, no subcommands.
- `internal/pipeline` — one file per stage, **functions not interfaces**. Exec stages
  hand documents to tools as temp files; native stages (down-convert, augment,
  quality-patch) operate on an in-memory `cyclonedx-go.BOM`.
- Fail-loud everywhere: a missing tool or any stage error aborts the run.

## Commands

- `go build ./... && go test ./...` — unit tests cover the native transforms; no external tools needed.
- `./scripts/sbomqs-gate.sh` — the CI quality gate: builds the binary, generates the gomod-solo
  and merged SBOMs, and fails if either sbomqs score drops below its floor. Ratchet the floors up
  as score-lifting stages land. sbomqs is a dev/CI gate only, never a runtime stage.

## Agent skills

### Issue tracker

Issues live in this repo's GitHub Issues, via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Default five canonical labels (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
