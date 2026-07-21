# fixture-python-uv

A small-but-real **uv** project used by the uv path of the Python golden gate
(`scripts/sbomqs-gate-python.sh`, `python-uv` sub-gate). Same dep set as the sibling
poetry fixture — `requests`, `click`, `jinja2`, `rich`, `pyyaml` — so the enrich /
quality-patch stages get the same 14-component workout.

## Generate the dependency SBOM

uv exports CycloneDX **natively** — no `cyclonedx-py`, no intermediate file. It reads
the committed, frozen `uv.lock` (deterministic component set):

```sh
uv export --format cyclonedx1.5 -o bom.json    # native CycloneDX 1.5 + primary component + graph
```

`uv` emits **1.5**; the pipeline accepts CycloneDX >= 1.5 and up-converts to 1.6
losslessly. Then feed it to the pipeline: `sbom-quality --sbom bom.json`. See
`docs/python.md`.

## Re-locking (only when bumping deps)

```sh
uv lock        # needs network to PyPI; regenerates uv.lock
```

`package = false` under `[tool.uv]` — this is a dependency fixture, not a distributable
package, so there's nothing to build or install.
