# Releasing

1. Update the version in **both** `pyproject.toml` and `src/piileak/__init__.py` (a test checks they match).
2. Add a section for the new version to `CHANGELOG.md`.
3. Commit and push to `main`, and wait for CI to pass.
4. Tag and push:
   ```
   git tag v0.2.0
   git push origin v0.2.0
   ```
5. The **Release** workflow then runs the checks, builds the package, creates a GitHub Release with the files,
   and pushes `ghcr.io/<owner>/<repo>:<version>` and `:latest`.

## Publishing to PyPI (optional)

1. Check the name is free at https://pypi.org/project/piileak/ (rename `name` in `pyproject.toml` if it is taken).
2. On PyPI, add a *trusted publisher* for this repository: workflow `release.yml`, environment `pypi`.
3. In the GitHub repository settings, create an environment called `pypi`, and a repository variable
   `PUBLISH_TO_PYPI` set to `true`.
