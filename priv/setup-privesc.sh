#!/usr/bin/env bash
#
# setup-privesc.sh - create the access that lets one account load code as
# another. This is the "arrange the vulnerability" half of the privilege-
# escalation lab; the priv/escalate_*.py demos are the "watch it get caught"
# half.
#
#   ##########################################################################
#   #  Isolated lab machines ONLY. This script deliberately makes files and  #
#   #  directories writable by accounts other than yours - which is exactly  #
#   #  the misconfiguration that turns an import into a privilege escalation.#
#   #  Undo everything with:  ./setup-privesc.sh --remove                    #
#   ##########################################################################
#
# Two ways to use it:
#
#   ./setup-privesc.sh                 build the standard fixture set under
#                                      /var/tmp/eyalsec-privesc (see below)
#   ./setup-privesc.sh --grant PATH    grant "somebody else can write this" to
#                                      a file or directory YOU choose - the
#                                      access that makes loading PATH an
#                                      escalation. This is the direct answer to
#                                      "create the access to the file I am
#                                      executing code from": point it at that
#                                      file.
#   ./setup-privesc.sh --remove        undo everything this script created
#
# Most cases need no root: any unprivileged process can `chmod o+w` its own
# files, and world-writable is already enough to be foreign. The OWNER and
# SHARED-GROUP cases need a second account, so they are added only when you run
# with sudo. A root-owned negative control is added too - es-python trusts root,
# and it must stay silent.
#
set -uo pipefail

DIR=/var/tmp/eyalsec-privesc
GROUP=eyalsecdemo
OTHER=nobody                          # the "somebody else"; exists everywhere
ME=${SUDO_USER:-$(id -un)}
HAVE_SUDO=0
if [ "$(id -u)" = "0" ] || sudo -n true 2>/dev/null; then HAVE_SUDO=1; fi

say() { printf '%s\n' "$*"; }
run_priv() { if [ "$(id -u)" = "0" ]; then "$@"; else sudo "$@"; fi; }

# --------------------------------------------------------------------------- #
# --grant PATH : make PATH loadable-as-me by somebody else.
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--grant" ]; then
    TARGET="${2:-}"
    [ -n "$TARGET" ] || { say "usage: $0 --grant <path>" >&2; exit 2; }
    [ -e "$TARGET" ] || { say "no such path: $TARGET" >&2; exit 1; }
    if [ -d "$TARGET" ]; then
        chmod o+w "$TARGET"
        say "granted world-write on directory $TARGET"
        say "  -> anyone can now drop or replace a .py/.pyc that a process here imports."
    else
        chmod o+w "$TARGET"
        say "granted world-write on file $TARGET"
        say "  -> anyone can now rewrite the code this file loads before it runs."
    fi
    say ""
    say "es-python now treats $TARGET as foreign. Confirm with the demos' predicate:"
    DEMOS_DIR="$(cd "$(dirname "$0")/../demos" && pwd)"
    say "  es-python -c \"import sys; sys.path.insert(0, '$DEMOS_DIR'); \\"
    say "     from foreign_lab import verdict; print(verdict('$TARGET')['why'])\""
    say ""
    say "Undo just this one:  chmod o-w '$TARGET'   (or ./setup-privesc.sh --remove"
    say "                     for everything this script created)."
    exit 0
fi

# --------------------------------------------------------------------------- #
# --remove : undo everything.
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--remove" ]; then
    run_priv rm -rf "$DIR"
    if getent group "$GROUP" >/dev/null 2>&1; then
        run_priv gpasswd -d "$OTHER" "$GROUP" >/dev/null 2>&1 || true
        run_priv gpasswd -d "$ME" "$GROUP" >/dev/null 2>&1 || true
        run_priv groupdel "$GROUP" 2>/dev/null || true
    fi
    say "removed $DIR and group $GROUP"
    exit 0
fi

# --------------------------------------------------------------------------- #
# Default: build the standard fixture set.
# --------------------------------------------------------------------------- #
say "building privilege-escalation fixtures in $DIR"
mkdir -p "$DIR"
chmod 755 "$DIR"

# 1. A writable sys.path directory with a planted helper module (world-writable,
#    no root needed). This is the escalate_syspath.py case, as a durable fixture.
mkdir -p "$DIR/writable_lib"
cat > "$DIR/writable_lib/app_config.py" <<'PY'
# Planted into a world-writable sys.path directory. Whoever imports app_config
# from here runs this with their own authority.
DB_URL = "postgres://prod/main"
PY
chmod 777 "$DIR/writable_lib"
chmod 666 "$DIR/writable_lib/app_config.py"
say "  [ok] writable sys.path dir : $DIR/writable_lib (import app_config)"

# 2. A private source with a writable bytecode cache (world-writable cache dir,
#    no root needed). This is the escalate_pyc_cache.py case.
mkdir -p "$DIR/writable_cache"
cat > "$DIR/writable_cache/vic.py" <<'PY'
VALUE = "original, from trusted source"
PY
chmod 644 "$DIR/writable_cache/vic.py"
# compile with whatever python is around, so the .pyc exists to be replaced
if command -v python3 >/dev/null 2>&1; then
    python3 -c "import py_compile; py_compile.compile('$DIR/writable_cache/vic.py')" 2>/dev/null || true
fi
[ -d "$DIR/writable_cache/__pycache__" ] && chmod 777 "$DIR/writable_cache/__pycache__" && \
    chmod 666 "$DIR/writable_cache/__pycache__/"*.pyc 2>/dev/null || true
say "  [ok] writable .pyc cache   : $DIR/writable_cache/__pycache__ (source is private)"

# 3. A writable startup-hook directory with a planted sitecustomize.py.
mkdir -p "$DIR/writable_startup"
cat > "$DIR/writable_startup/sitecustomize.py" <<'PY'
import sys
print("  [!] planted sitecustomize ran at startup", file=sys.stderr)
PY
chmod 777 "$DIR/writable_startup"
chmod 666 "$DIR/writable_startup/sitecustomize.py"
say "  [ok] writable startup dir  : $DIR/writable_startup (PYTHONPATH -> sitecustomize)"

# 4/5/6. Owner, shared-group, and root-control cases: need a second account.
if [ "$HAVE_SUDO" = "1" ] && getent passwd "$OTHER" >/dev/null 2>&1; then
    # 4. Module OWNED BY ANOTHER USER (mode 0644 - foreign by owner, not by mode).
    run_priv tee "$DIR/other_user_module.py" >/dev/null <<'PY'
# Owned by another user. They decide what a process that imports this runs.
MESSAGE = "loaded from a module owned by another user"
PY
    run_priv chown "$OTHER" "$DIR/other_user_module.py"
    run_priv chmod 644 "$DIR/other_user_module.py"
    say "  [ok] owned by $OTHER        : $DIR/other_user_module.py (mode 0644, still foreign)"

    # 5. Shared group + a group-writable module.
    getent group "$GROUP" >/dev/null 2>&1 || run_priv groupadd "$GROUP"
    run_priv usermod -aG "$GROUP" "$ME"    >/dev/null 2>&1 || true
    run_priv usermod -aG "$GROUP" "$OTHER" >/dev/null 2>&1 || true
    run_priv tee "$DIR/group_writable_module.py" >/dev/null <<'PY'
# Mine, mode 0664, group eyalsecdemo - and somebody else is in that group.
MESSAGE = "loaded from a module a shared group can write"
PY
    run_priv chown "$ME:$GROUP" "$DIR/group_writable_module.py"
    run_priv chmod 664 "$DIR/group_writable_module.py"
    say "  [ok] shared-group writable : $DIR/group_writable_module.py (group $GROUP)"

    # 6. NEGATIVE CONTROL: root-owned. es-python trusts root; must stay silent.
    run_priv tee "$DIR/root_owned_module.py" >/dev/null <<'PY'
# Owned by root. Loading this must produce NO event - root is trusted.
MESSAGE = "root-owned - deliberately silent"
PY
    run_priv chown root:root "$DIR/root_owned_module.py"
    run_priv chmod 644 "$DIR/root_owned_module.py"
    say "  [ok] root-owned control    : $DIR/root_owned_module.py (must stay SILENT)"
else
    say "  [--] owner / shared-group / root-control cases skipped (need sudo + a"
    say "       second account). Re-run with sudo to add them; the world-writable"
    say "       cases above are already enough to see the detector fire."
fi

say ""
say "done. The escalate_*.py demos build their own throwaway fixtures, so you do"
say "not need this script to run them - it is here to create durable fixtures and"
say "to grant access to a path of your own with --grant."
