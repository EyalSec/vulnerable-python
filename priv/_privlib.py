#!/usr/bin/env python3.13
"""Shared helpers for the privilege-escalation lab (`priv/*`).

  ############################################################################
  #  WARNING: these demos deliberately create code the interpreter loads from #
  #  a location another account can write. Isolated lab machines only - see   #
  #  the warning at the top of app.py.                                        #
  ############################################################################

Every demo in this directory is one shape of the same move: get a privileged
process to load code from somewhere an unprivileged account can write. The
helpers here are the parts they all share:

  * `resolve()` locates the es-python interpreter and the repo's `es_compat`
    and `foreign_lab` modules, so a demo can run from anywhere.
  * `run_victim()` runs a victim script in a child process, inheriting the
    caller's environment, and classifies what happened from a first-line
    sentinel plus the child's exit status - so a load that was REFUSED under
    an armed raise is told apart from an interpreter that aborted at startup
    (the dev-build file-taint hazard; see run-priv.sh).
  * `show_predicate()` prints es-python's own foreign predicate, computed in
    pure Python by `foreign_lab.verdict()`, against the file we planted - the
    same three rules the interpreter applies in C, shown so you can see which
    one matched.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEMOS = os.path.join(REPO, "demos")

# es_compat (make_vuln/check_vuln/get_taint + banner) and foreign_lab.verdict
# both live one level up; make them importable no matter where we were started.
for _p in (DEMOS, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from es_compat import ES_PYTHON, banner  # noqa: E402

try:
    from foreign_lab import verdict       # noqa: E402
except Exception:                         # foreign_lab pulls in grp/pwd; never fatal
    verdict = None


# The sentinel the victim children print as their very FIRST line, before the
# risky load. Its presence proves the interpreter started; its absence under a
# non-zero exit means startup itself was aborted, not the planted load.
CHILD_START = "PRIV-CHILD-START"
CHILD_OK = "PRIV-CHILD-OK"

# Demos take `--raise` rather than asking you to export ES2_RAISE. The reason is
# specific to the local full dev build: that build taints every file read,
# including the interpreter's own cached .pyc files, so ES2_RAISE=1 on the
# PARENT aborts it at the first stdlib marshal load before the demo runs. The
# raise belongs on the CHILD that performs the planted load, so each demo builds
# the child's environment here and leaves the parent untouched.
RAISE_FLAG = "--raise"


def wants_raise(argv):
    return RAISE_FLAG in argv


def child_env(raise_):
    """Environment for a victim child: the foreign gate always on (so the demo
    works even if you forgot to export it), the raise only when asked."""
    env = os.environ.copy()
    env["ES2_MAKE_FOREIGN_VULN"] = "1"
    if raise_:
        env["ES2_RAISE"] = "1"
    return env


def show_predicate(path):
    """Print es-python's foreign verdict for `path`, rule by rule."""
    if verdict is None:
        print(f" (foreign_lab unavailable - cannot show the predicate for {path})")
        return
    v = verdict(path)
    if not v.get("exists"):
        print(f" predicate: {path} does not exist ({v.get('error')})")
        return
    print(f" es-python's foreign predicate for the planted file:")
    print(f"   path   {v['path']}")
    print(f"   owner  {v['owner']}   mode {v['mode']}   (me: uid {os.geteuid()})")
    for rule, hit in v["rules"].items():
        print(f"   [{'x' if hit else ' '}] {rule}")
    print(f"   => foreign for a code load: {v['foreign_for_code_load']}")
    for why in v["why"]:
        print(f"      - {why}")


def run_victim(victim_path, *args, env=None):
    """Run `victim_path` as a main script in a child; return a classification.

    The result is one of:
      'ran'      the load succeeded and the victim finished (observe mode, or
                 stock CPython) - the child printed CHILD_OK.
      'blocked'  the interpreter started (printed CHILD_START) but the planted
                 load was refused before the victim finished - an armed raise.
      'startup'  the child exited non-zero WITHOUT printing CHILD_START - the
                 interpreter aborted during startup, not on our load. On a full
                 local dev build this is the file-taint-plus-raise hazard, not
                 a real result for this demo (run-priv.sh explains it).
    Also returns the child's stdout lines and the tail of its stderr.
    """
    child = subprocess.run(
        [sys.executable, victim_path, *args],
        capture_output=True, text=True,
        env=env if env is not None else os.environ.copy(),
    )
    out = child.stdout.splitlines()
    started = any(line.strip() == CHILD_START for line in out)
    finished = any(line.strip().startswith(CHILD_OK) for line in out)
    if finished:
        kind = "ran"
    elif child.returncode != 0 and started:
        kind = "blocked"
    elif child.returncode != 0 and not started:
        kind = "startup"
    else:
        kind = "ran"
    err_tail = child.stderr.strip().splitlines()[-6:]
    return kind, out, err_tail, child.returncode


def print_child(out, err_tail):
    for line in out:
        print("   |", line)
    for line in err_tail:
        print("   !", line)


STARTUP_CAVEAT = "\n".join([
    " RESULT: the child interpreter aborted during STARTUP, not on our load -",
    "         the local full dev build taints its own cached .pyc files, so an",
    "         armed raise stops it at the first stdlib marshal load. This is a",
    "         property of this build, not a result for the demo. Re-run without",
    "         --raise to see the load reported; arm the raise on a real machine",
    "         (its config, or a fast/stock build) to see it refused cleanly.",
])


def print_startup_caveat():
    print(STARTUP_CAVEAT)
