#!/usr/bin/env bash
#
# Launch vulnerable-python under a LOCAL DEV es-python build with every taint
# source armed. Hitting the endpoints then produces source->sink events on the
# EyalSec dashboard (Observe), or aborts at the sink if ES2_RAISE=1 (Protect).
#
# On the obfuscated PRODUCTION build the taint sources are armed from the
# dashboard machine config instead of these environment variables - this
# script's flag path targets a dev build such as ~/opt/eyalsec.
#
# Usage:
#   ./run-eyalsec.sh                       # uses ~/opt/eyalsec/bin/python3.13
#   ES2_RAISE=1 ./run-eyalsec.sh           # Protect mode: sinks raise
#   ./run-eyalsec.sh /path/to/python3.13   # explicit interpreter
#
set -euo pipefail
cd "$(dirname "$0")"

PY="${1:-$HOME/opt/eyalsec/bin/python3.13}"
if [ ! -x "$PY" ]; then
  echo "es-python not found at: $PY" >&2
  echo "Pass the path to your es-python as the first argument, e.g.:" >&2
  echo "  ./run-eyalsec.sh /home/you/opt/eyalsec/bin/python3.13" >&2
  exit 1
fi

# Arm every taint source this app exercises.
export ES2_MAKE_SOCKET_VULN=1     # HTTP request data (recv)
export ES2_MAKE_FILE_VULN=1       # file reads          -> /source/file
export ES2_MAKE_STDIN_VULN=1      # stdin / input()     -> demos/
export ES2_MAKE_ENV_VULN=1        # env vars + sys.argv -> /source/env, demos/argv_demo.py
export ES2_MAKE_FOREIGN_VULN=1    # other-user-writable code -> /source/foreign

# The env-source demo reads this tainted value straight into a shell.
export DEMO_INPUT="127.0.0.1; id"

echo "launching vulnerable-python under: $PY"
echo "taint sources armed: socket, file, stdin, env, argv, foreign-code"
[ "${ES2_RAISE:-}" = "1" ] && echo "mode: PROTECT (ES2_RAISE=1, sinks abort)" || echo "mode: OBSERVE (events only)"
echo

exec "$PY" app.py
