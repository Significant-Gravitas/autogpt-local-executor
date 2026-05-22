# Packaging stubs

These are starting-point manifests for the two third-party package managers
we plan to support post-PyPI-publish:

- `homebrew/autogpt-local-executor.rb` — Homebrew formula
- `scoop/autogpt-local-executor.json` — Scoop manifest

They are NOT wired up to a live tap / bucket yet — that is a repo-org-level
decision (which GitHub org, which tap name, who has push access). When the
project is ready:

1. Publish `autogpt-local-executor` to PyPI.
2. Fork these files into the chosen tap / bucket repo.
3. Fill in the `PLACEHOLDER-*` `url` / `sha256` / `hash` values from the
   live PyPI release.
4. Tag a release in this repo; CI in the tap/bucket repo should be wired
   to bump these manifests automatically on every new tag.

Until then, the primary install path stays:

```bash
pipx install autogpt-local-executor
```

per `docs/CROSS_PLATFORM.md` "Packaging & install" row.
