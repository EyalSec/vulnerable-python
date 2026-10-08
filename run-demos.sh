#!/usr/bin/env bash
#
# Run the three "what only runtime taint can do" demos twice each: once as the
# machine is configured, and once asking for a raise, so the difference is
# visible in one command.
#
# READ THIS BEFORE JUDGING THE OUTPUT
# -----------------------------------
# Whether a sink actually raises is decided by the machine config your EyalSec
# dashboard pushes, NOT by this script. ES2_RAISE=1 is only a fallback, and
# es-python honours it only when the machine has no raise rules of its own.
# So the second run of each pair aborts the flow only if:
#
#   * the machine has a matching raise rule (the supported path), or
#   * you are on a local dev build that honours the ES2_RAISE fallback.
#
# If both runs of a pair print the same RESULT, raising is not armed on this
# machine. That is a configuration state, not a failure of the demo - and the
# first run of each pair is still the real thing: the flow is detected and
# reported to the dashboard.
#
# Do not read the headers below as promises. Each demo prints its own RESULT
# line describing what actually happened.
#
# Usage:
#   ./run-demos.sh                       # uses ~/opt/eyalsec/bin/python3.13
#   ./run-demos.sh /path/to/python3.13   # explicit interpreter
#   ./run-demos.sh python3               # plain python3, to see the contrast
#
set -uo pipefail
cd "$(dirname "$0")"

PY="${1:-$HOME/opt/eyalsec/bin/python3.13}"
if ! command -v "$PY" >/dev/null 2>&1 && [ ! -x "$PY" ]; then
  echo "interpreter not found: $PY" >&2
  echo "Pass one explicitly, e.g.:" >&2
  echo "  ./run-demos.sh /home/you/opt/eyalsec/bin/python3.13" >&2
  exit 1
fi

run() {
  local title="$1"; shift
  echo
  echo "###############################################################################"
  echo "# $title"
  echo "###############################################################################"
  "$@"
}

# Demos 1 and 3 use make_vuln(), which needs at least one taint source armed for
# taint tracking to be active. The socket source is the lightest one.
#
# Demo 2 arms ONLY the foreign source on purpose. Adding ES2_MAKE_FILE_VULN
# would taint every file the interpreter reads, including its own cached .pyc
# files - and combined with the blunt ES2_RAISE=1 below that aborts startup at
# the marshal sink before any demo code runs. The foreign source taints only
# files another user can write, which is exactly the demo's subject.

run "1. the secret that cannot be sent  [as configured]" \
  env ES2_MAKE_SOCKET_VULN=1 "$PY" demos/secret_exfil_server.py --selftest

run "1. the secret that cannot be sent  [asking for a raise]" \
  env ES2_MAKE_SOCKET_VULN=1 ES2_RAISE=1 "$PY" demos/secret_exfil_server.py --selftest

run "2. the code load nothing else can see  [as configured]" \
  env ES2_MAKE_FOREIGN_VULN=1 "$PY" demos/uncatchable_plugin.py

run "2. the code load nothing else can see  [asking for a raise]" \
  env ES2_MAKE_FOREIGN_VULN=1 ES2_RAISE=1 "$PY" demos/uncatchable_plugin.py

run "2b. the world-writable main script  [as configured]" \
  env ES2_MAKE_FOREIGN_VULN=1 "$PY" demos/foreign_main_script.py

run "2b. the world-writable main script  [asking for a raise]" \
  env ES2_MAKE_FOREIGN_VULN=1 ES2_RAISE=1 "$PY" demos/foreign_main_script.py

# Piped through a shell so stdin genuinely carries code - that is one of the
# four sources this demo covers.
#
# The raise run drops ES2_MAKE_ENV_VULN on purpose, for the same reason demo 2
# drops ES2_MAKE_FILE_VULN: env taint marks $HOME, site.py stats the user-site
# directory during startup, and the blunt raise aborts there with "Failed to
# import the site module" before any demo code runs. A dashboard rule scoped to
# one source and one sink has no such problem; the blunt env var does.
UNTRUSTED_ENV='ES2_MAKE_FOREIGN_VULN=1 ES2_MAKE_STDIN_VULN=1 ES2_MAKE_ENV_VULN=1 DEMO_CODE="z = 3"'

run "2c. untrusted code from stdin / argv / env  [as configured]" \
  bash -c "echo 'x = 6 * 7' | env $UNTRUSTED_ENV '$PY' demos/untrusted_code_demo.py 'y = 1 + 1'"

run "2c. untrusted code from stdin / make_vuln  [asking for a raise]" \
  bash -c "echo 'x = 6 * 7' | env ES2_MAKE_FOREIGN_VULN=1 ES2_MAKE_STDIN_VULN=1 ES2_RAISE=1 '$PY' demos/untrusted_code_demo.py 'y = 1 + 1'"

run "3. taint through 15 transformations  [as configured]" \
  env ES2_MAKE_SOCKET_VULN=1 "$PY" demos/taint_gauntlet.py

run "3. taint through 15 transformations  [asking for a raise]" \
  env ES2_MAKE_SOCKET_VULN=1 ES2_RAISE=1 "$PY" demos/taint_gauntlet.py

cat <<'EOF'

###############################################################################
# Reading the results
###############################################################################
Compare the two RESULT lines in each pair.

  different  -> the flow was detected, and then blocked when a raise was asked
                for. That is Observe and Protect, side by side.

  both leak  -> raising is not armed on this machine. The flows were still
                detected and reported; add a rule in the dashboard to block
                them:
                  demo 1:  Source 1        Event sendall  Mode Raise
                  demo 2:  Source foreign  Event exec     Mode Raise
                  demo 2b: Source foreign  Event run script  Mode Raise
                  demo 2c: Source stdin    Event exec     Mode Raise
                  demo 3:  Source 7        Event sendall  Mode Raise

  both block -> this machine already carries the matching raise rules.

Under plain python3 every run above succeeds silently, with nothing detected
and nothing recorded. That is the point.
EOF
