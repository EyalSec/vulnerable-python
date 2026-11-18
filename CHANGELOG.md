# Changelog

Notable changes to vulnerable-python. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Each version is a git tag.

## [Unreleased]

### Added

- A full page for every attack es-python stops, shown in the browser: the
  severity and what the attacker was after, a clear "Blocked" verdict, the
  request with the attacker's input marked, the endpoint's own code with the
  exact line where it was stopped, the values that were about to reach the
  operation (taken from the stopped call, not reconstructed), a step-by-step
  timeline with the measured time to stop, and a link to the safe version.
  Command-line clients still get the short plain-text answer.
- A secure counterpart for every injectable endpoint, under `/safe/...`
  (parameterised SQL, an argument list with no shell, a contained file path,
  an arithmetic evaluator, JSON instead of pickle/marshal, an allow-listed
  import and library load, escaped regex and CSV, a sandboxed template). Each
  one is linked beneath the vulnerable example on the landing page and works
  with ordinary input while es-python stays quiet.
- A **Run this attack** button on the landing page for the POST endpoints
  (`/pickle`, `/marshal`, `/xxe`), which sends a canned payload from the
  browser and shows the response, so they are clickable like the GET examples.
- A favicon and a clear page title on every page (the EyalSec icon).

- A live copy at [vp.eyalsec.com](https://vp.eyalsec.com), running this code
  unchanged under es-python.
- An open-source banner on every page a browser opens, linking to this
  repository, the ZIP download and the exact lines of code behind that page.
  Each endpoint on the landing page links to its code. curl and other
  non-browser clients get the same responses as before.
- When es-python stops a request in Protect mode, the page says so (HTTP 403)
  instead of showing a generic error.
- `VP_SOURCE_REF` pins the code links to a commit; `VP_LIVE_DEMO=1` adds the
  es-python line to the banner.

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
