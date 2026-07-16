# Releasing

Releases are tagged from `main`. The `release` workflow verifies the tag matches the version in
`pyproject.toml`, builds the sdist and wheel, and creates the GitHub Release with notes extracted
from `CHANGELOG.md`. The `test` workflow should already be green on `main`.

1. Bump `version` in `pyproject.toml`.
2. Move the `[Unreleased]` entries in `CHANGELOG.md` under a `## [X.Y.Z] - YYYY-MM-DD` heading,
   and update the link definitions at the bottom of the file.
3. Commit, then tag and push:

```bash
git tag vX.Y.Z
git push origin main
git push origin vX.Y.Z
```

A tag that does not match `pyproject.toml` fails before anything is published. The release workflow
expects a matching `## [X.Y.Z] - YYYY-MM-DD` section in `CHANGELOG.md`.
