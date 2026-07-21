# fixture-python

A small-but-real Poetry project used by the sbom-quality Python golden gate
(`scripts/sbomqs-gate-python.sh`, map #60 / ticket #65). A handful of real deps —
`requests`, `click`, `jinja2`, `rich`, `pyyaml` — pull enough transitives (14
components) that the enrich / quality-patch stages have something to chew on, and
their licenses span the shapes parlay back-fills.

## Generate the dependency SBOM

`cyclonedx-py` reads the committed `poetry.lock` directly — **no `poetry` binary
needed** (only the lock, which is frozen so the component set + hashes are
deterministic):

```sh
uvx --from cyclonedx-bom cyclonedx-py poetry . -o bom.json   # native CycloneDX 1.6
```

Then feed it to the pipeline: `sbom-quality --sbom bom.json`. See `docs/python.md`.

## Re-locking (only when bumping deps)

```sh
uvx poetry lock        # needs network to PyPI; regenerates poetry.lock
```

`package-mode = false` in `pyproject.toml` — this is a dependency fixture, not a
distributable package, so there's nothing to build or install.
