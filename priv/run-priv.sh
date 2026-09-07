#!/usr/bin/env bash
#
# Run all four privilege-escalation demos twice each: once as configured
# (the load is DETECTED and reported), then with --raise (the load is REFUSED).
#
# READ THIS BEFORE JUDGING THE OUTPUT
# -----------------------------------
# Whether a load is actually refused is decided by the raise rules your EyalSec
# dashboard pushes to the machine, NOT by this script. --raise is a local
# fallback the interpreter honours only when the machine has no raise rules of
# its own. So the second run of each pair refuses the load only if:
#
#   * the machine has a matching raise rule (the supported path), or
#   * you are on a build that honours the --raise fallback AND does not abort at
#     startup first (see the next paragraph).
#
# THE LOCAL FULL DEV BUILD IS A SPECIAL CASE. That build taints every file it
# reads, including its own cached .pyc files, so an armed raise stops it at the
# first standard-library marshal load - during startup, before the demo's own
# load. Each demo detects this and prints a RESULT saying so; it is a property
# of that build, not a failure of the demo. The first run of each pair (no
# --raise) is the real detection either way: the load is judged and reported.
#
# Do not read the headers below as promises. Each demo prints its own RESULT
# line describing what actually happened.
#
# Usage:
#   ./run-priv.sh                       # uses ~/opt/eyalsec/bin/python3.13
#   ./run-priv.sh /path/to/python3.13   # explicit interpreter
#   ./run-priv.sh python3               # stock CPython, to see the contrast
#
set -uo pipefail
cd "$(dirname "$0")"

PY="${1:-$HOME/opt/eyalsec/bin/python3.13}"
if ! command -v "$PY" >/dev/null 2>&1 && [ ! -x "$PY" ]; then
  echo "interpreter not found: $PY" >&2
  echo "Pass one explicitly, e.g.:" >&2
  echo "  ./run-priv.sh /home/you/opt/eyalsec/bin/python3.13" >&2
  exit 1
fi

pair() {
  local title="$1" script="$2"
  echo
  echo "###############################################################################"
  echo "# $title"
  echo "###############################################################################"
  echo "----- as configured (detect) -------------------------------------------------"
  "$PY" "$script"
  echo
  echo "----- asking for a raise (protect) -------------------------------------------"
  "$PY" "$script" --raise
}

pair "1. helper module on a writable sys.path directory" escalate_syspath.py
pair "2. the privileged main script is itself writable"  escalate_main_script.py
pair "3. private source, writable bytecode cache"        escalate_pyc_cache.py
pair "4. sitecustomize on a writable startup path"       escalate_startup_hooks.py

echo
echo "Done. Every path above is the same move - load code from somewhere another"
echo "account can write - and every one is judged at the load, before the planted"
echo "code's first line. Point run-priv.sh at stock python3 to see the difference:"
echo "the same escalations run, and nothing records that they happened."
