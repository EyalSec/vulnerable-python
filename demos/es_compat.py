"""Plain-python3 fallbacks for the es-python taint builtins.

The demos in this directory are meant to run **unchanged** under both
runtimes, which is the entire point of this repository. Under es-python,
`make_vuln` / `check_vuln` / `get_taint` are real builtins provided by the
runtime. Under plain python3 they do not exist, so importing this module
installs inert stand-ins: `make_vuln` returns the object untouched, nothing is
ever tainted, and every demo still runs to completion - silently vulnerable,
exactly like the production app it stands in for.

    from es_compat import make_vuln, check_vuln, get_taint, ES_PYTHON

`ES_PYTHON` is True only when the real builtins were found.
"""

try:
    make_vuln = make_vuln          # noqa: F821, PLW0127  (es-python builtin)
    check_vuln = check_vuln        # noqa: F821, PLW0127
    get_taint = get_taint          # noqa: F821, PLW0127
    ES_PYTHON = True
except NameError:                  # plain python3
    ES_PYTHON = False

    def make_vuln(obj, taint=None):
        """No-op stand-in: plain python3 has no taint tracking."""
        return obj

    def check_vuln(obj):
        return False

    def get_taint(obj):
        return None


def banner(title):
    """Print a heading that states which runtime is actually running."""
    runtime = "es-python (taint tracking ACTIVE)" if ES_PYTHON else \
              "plain python3 (no taint tracking - silently vulnerable)"
    print("=" * 78)
    print(f" {title}")
    print(f" runtime: {runtime}")
    print("=" * 78)
