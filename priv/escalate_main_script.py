#!/usr/bin/env python3.13
"""PRIVESC 2 - the privileged script IS the writable file.

  ############################################################################
  #  WARNING: intentionally vulnerable demo. Isolated lab machines only.     #
  ############################################################################

A cron entry, a systemd timer or a sudoers line runs a specific script:

    */5 * * * * root  /opt/jobs/deploy_job.py

If `/opt/jobs/deploy_job.py` is writable by a less-privileged account - it
landed that way from a tarball, a CI artifact, an rsync, a shared volume, or a
too-generous `chmod` - that account rewrites it between two runs and owns the
next invocation with the privileged process's authority.

This is the hardest case for everything-but-the-runtime to catch. There is no
import to hook, no `sys.modules` entry to inspect, and no application code
running yet that could check anything: by the time the script's first line
executes, the attacker's line has already executed too.

What es-python does
-------------------
es-python performs the foreign check on the MAIN SCRIPT, before its first
statement runs, and reports origin `foreign-code:<path>`, event `run script`.
Under an armed raise the script is refused rather than run. It is one of the
very few checks that deliberately fires during interpreter startup: waiting for
"user code to start" is meaningless when blocking untrusted code is the whole
point.

How this demo arranges it
-------------------------
A script cannot make itself world-writable before it is loaded - the check has
already run. So the parent (an ordinary file you own, which produces no event)
copies a small victim into a temp directory, makes the COPY mode 0666, and runs
that copy as a main script in a child. The copy is what the interpreter judges.

Run it
------
    es-python priv/escalate_main_script.py            # observe: reported
    es-python priv/escalate_main_script.py --raise    # protect: refused

Under stock CPython the copy runs and nothing records that the file the
interpreter just executed was writable by every account on the box.
"""
import os
import stat
import sys
import tempfile

from _privlib import (CHILD_OK, CHILD_START, ES_PYTHON, banner, child_env,
                      print_child, print_startup_caveat, run_victim,
                      show_predicate, wants_raise)


VICTIM = f'''\
# A deploy job that runs as root every five minutes. Made world-writable in the
# copy the parent runs, so it stands in for a script an attacker can rewrite.
print("{CHILD_START}")                 # startup survived
print("deploy_job: running as uid", __import__("os").geteuid())
print("{CHILD_OK} deploy complete")    # only reached if the load was allowed
'''


def main():
    banner("privesc 2: the privileged main script is itself writable")
    workdir = tempfile.mkdtemp(prefix="eyalsec_privesc_main_")
    try:
        planted = os.path.join(workdir, "deploy_job.py")
        with open(planted, "w") as fh:
            fh.write(VICTIM)
        os.chmod(planted, 0o666)                        # anyone can rewrite it

        st = os.stat(planted)
        print(f" cron/sudo runs : {planted}")
        print(f" planted mode   : {stat.filemode(st.st_mode)}  "
              f"world-writable={bool(st.st_mode & stat.S_IWOTH)}")
        print(f" interpreter    : {sys.executable}")
        print()
        show_predicate(planted)
        print()
        print(" running the writable script as a main script in a child...")
        print()

        kind, out, err_tail, rc = run_victim(planted,
                                             env=child_env(wants_raise(sys.argv)))
        print_child(out, err_tail)
        print()
        if kind == "blocked":
            print(" RESULT: the script never ran.")
            print("         es-python judged the main script foreign-writable and")
            print("         aborted the load before its first statement executed.")
        elif kind == "startup":
            print_startup_caveat()
        elif ES_PYTHON:
            print(" RESULT: the script ran (observe mode). es-python reported it:")
            print(f"         foreign-code:{planted}")
            print("         To refuse to run such a script, arm the rule on the machine:")
            print("           Source: foreign   Event: run script   Mode: Raise")
            print("         (nothing reported? enable 'foreign' in the machine config,")
            print("          or run locally with ES2_MAKE_FOREIGN_VULN=1)")
        else:
            print(" RESULT: the script ran. Stock CPython.")
            print("         No event, and no way for the application to find out that the")
            print("         file the interpreter just executed was writable by anyone.")
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
