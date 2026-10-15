# Changelog

Notable changes to vulnerable-python. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each version is a git tag.

## [Unreleased]

### Added

- A container image, `ghcr.io/eyalsec/vulnerable-python`, built from `main`
  for `linux/amd64` and `linux/arm64` with a signed build provenance
  attestation (`Dockerfile`, `.github/workflows/container.yml`).
- A development container, so the repository opens in GitHub Codespaces or
  Ona (formerly Gitpod) with the app running.
- `requirements-adapters.txt`, the pinned libraries behind `/adapter/*`.
- A Docker Hub mirror workflow, inactive until the `DOCKERHUB_TOKEN` secret
  exists.

## [1.0.0] - 2026-10-15

The first tagged version. It contains:

- The Flask app (`app.py`): one route per pair of untrusted-data source and
  risky operation, covering SQL injection, OS command injection, code
  injection, insecure deserialization, path traversal, SSRF, XXE, ReDoS, CSV
  injection, format-string disclosure, dynamic import and more. The landing
  page at `/` lists every route with an example request.
- The foreign-code routes under `/foreign/*`, with `setup-foreign.sh` for the
  cases that need a second user on the machine.
- Optional routes under `/adapter/*` for third-party libraries (Jinja2,
  MarkupSafe, YAML, JWT, SQLAlchemy, MongoDB, Redis); without the library
  installed, each says which one it needs.
- The command-line demos in `demos/`, run in pairs by `run-demos.sh`.
- The privilege-escalation lab in `priv/`.
- Smoke tests in `tests/`, run in CI on Python 3.9, 3.12 and 3.13 with a lint
  pass.
- Flask 3.1.3 or later is required (`requirements.txt`), the Flask security
  fix release.

[1.0.0]: https://github.com/EyalSec/vulnerable-python/tree/v1.0.0
