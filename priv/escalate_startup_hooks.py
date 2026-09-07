#!/usr/bin/env python3.13
"""PRIVESC 4 - code that runs at interpreter startup, before your main script.

  ############################################################################
  #  WARNING: intentionally vulnerable demo. Isolated lab machines only.     #
  ############################################################################

Python runs several things before your `main()` - before your first line, in
fact. Two of them are files on disk that a less-privileged account may be able
to write:

  * `sitecustomize.py` / `usercustomize.py` - imported automatically at startup
    if found anywhere on `sys.path`. A writable directory early on the path (a
    stray `PYTHONPATH` entry, a world-writable install dir) means attacker code
    runs in every interpreter that starts there.
  * a `.pth` file in site-packages whose line begins with `import ` - executed
    by `site.py` at startup. If site-packages is group- or world-writable,
    anyone who can drop a `.pth` runs code in every process on the box.

Either way the attacker's code runs before the privileged program exists to
defend itself.

What es-python does
-------------------
`sitecustomize` is imported like any module, so loading it from a foreign
directory is a CODE LOAD from a foreign-writable file: origin
`foreign-code:<path>`, reported before its body runs, refused under an armed
raise. This demo shows the `sitecustomize` case end to end. (The `.pth` line is
described in README; site-packages here is not writable, so we do not tamper
with it.)

Run it
------
    es-python priv/escalate_startup_hooks.py            # observe: reported
    es-python priv/escalate_startup_hooks.py --raise    # protect: refused

Under stock CPython the startup hook runs and nothing records that the directory
it was loaded from was writable by another account.
"""
import os
import stat
import sys
import tempfile

from _privlib import (CHILD_OK, CHILD_START, ES_PYTHON, banner, child_env,
                      print_child, print_startup_caveat, run_victim,
                      show_predicate, wants_raise)


# The victim is a trivial program. The point is what runs BEFORE it: the
# planted sitecustomize on the writable PYTHONPATH directory.
VICTIM = f'''\
# By the time this prints, sitecustomize has already been imported at startup.
print("{CHILD_START}")
print("main program body runs now - but the startup hook already ran above")
print("{CHILD_OK} done")
'''

SITECUSTOMIZE = '''\
# Planted sitecustomize.py on a writable directory. Imported automatically at
# interpreter startup, before the main program - this line proves it ran.
import sys
print("  [!] planted sitecustomize executed at startup, uid",
      __import__("os").geteuid(), file=sys.stderr)
'''


def main():
    banner("privesc 4: sitecustomize on a writable startup path")
    workdir = tempfile.mkdtemp(prefix="eyalsec_privesc_startup_")
    try:
        hookdir = os.path.join(workdir, "startup")
        os.makedirs(hookdir)
        planted = os.path.join(hookdir, "sitecustomize.py")
        with open(planted, "w") as fh:
            fh.write(SITECUSTOMIZE)
        os.chmod(planted, 0o666)                        # anyone can rewrite it

        victim = os.path.join(workdir, "victim.py")
        with open(victim, "w") as fh:
            fh.write(VICTIM)
        os.chmod(victim, 0o644)

        st = os.stat(planted)
        print(f" victim program : {victim}  (mine, mode 0644 - trusted)")
        print(f" startup hook   : {planted}")
        print(f" hook mode      : {stat.filemode(st.st_mode)}  "
              f"world-writable={bool(st.st_mode & stat.S_IWOTH)}")
        print()
        show_predicate(planted)
        print()
        print(" running the victim with the writable dir on PYTHONPATH...")
        print(" (sitecustomize is imported at startup, before the victim's body)")
        print()

        # sitecustomize is found via PYTHONPATH; put the writable dir there for
        # the child on top of the gate/raise the demo controls.
        env = child_env(wants_raise(sys.argv))
        env["PYTHONPATH"] = hookdir + os.pathsep + env.get("PYTHONPATH", "")
        kind, out, err_tail, rc = run_victim(victim, env=env)
        print_child(out, err_tail)
        print()
        hook_ran = any("planted sitecustomize executed" in l for l in err_tail)
        # A refusal of the hook implicates sitecustomize (or our planted dir) in
        # the error; an abort that names the interpreter's own stdlib cache is
        # the dev-build startup hazard, not a refusal of this hook.
        refused_hook = (not hook_ran and rc != 0
                        and any(("sitecustomize" in l) or (hookdir in l)
                                for l in err_tail))
        if kind == "blocked" or refused_hook:
            print(" RESULT: the startup hook did not run.")
            print("         es-python judged sitecustomize.py foreign-writable and")
            print("         refused to import it before the victim started.")
        elif kind == "startup":
            print_startup_caveat()
        elif ES_PYTHON:
            print(" RESULT: the startup hook ran (observe mode). es-python reported it:")
            print(f"         foreign-code:{planted}")
            print("         To refuse such a hook, arm the rule on the machine:")
            print("           Source: foreign   Event: import (foreign code)   Mode: Raise")
            print("         (nothing reported? enable 'foreign' in the machine config,")
            print("          or run locally with ES2_MAKE_FOREIGN_VULN=1)")
        else:
            print(" RESULT: the startup hook ran. Stock CPython.")
            print("         No event, and no way for the program to learn that code ran")
            print("         at startup from a directory another account could write.")
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
