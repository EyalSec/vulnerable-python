#!/usr/bin/env python3.13
"""SOURCE foreign-code -> running a world-writable SCRIPT  =>  the load before your code.

  ############################################################################
  #  WARNING: part of an intentionally vulnerable demo app. Isolated lab      #
  #  machines only.                                                           #
  ############################################################################

Everything else in this repository is about code your application *loads*. This
demo is about the script the interpreter loads before your application exists:
the main script itself.

    $ chmod o+w deploy_job.py       # or: it landed that way out of a tarball,
    $ es-python deploy_job.py       # a CI artifact, an rsync, a shared volume

Any user on that box can rewrite `deploy_job.py` between two runs of the cron
entry that invokes it. There is no import to hook, no `sys.modules` entry to
inspect, and no application code running yet that could check anything - by the
time your first line executes, the attacker's line has already executed too.

es-python performs the foreign check inside `run_mod`, the interpreter function
that runs the main script, so the event happens before any user code at all:

    origin  foreign-code:/path/to/deploy_job.py
    event   run script

Under an armed raise rule the script is aborted rather than run. Note this is
one of the very few checks that deliberately fires DURING interpreter startup:
the ordinary "wait until user code has started" guard is skipped, because
"block untrusted code" is meaningless if it waits for the untrusted code to
start.

How this demo arranges it
-------------------------
A script cannot make itself world-writable before it is loaded - the check has
already run by then. So this file has two modes:

  * plain run (what you type)  - copies itself to a private temp directory,
    makes the COPY mode 0666, and runs that copy as a main script in a child
    process. The copy is what the interpreter judges.
  * `--planted` (the child)    - reports that it is running, and from where.

The parent is an ordinary file you own, so the parent process produces no
event. Everything reported comes from the child.

Run it
------
    ES2_MAKE_FOREIGN_VULN=1 es-python demos/foreign_main_script.py
    ES2_MAKE_FOREIGN_VULN=1 ES2_RAISE=1 es-python demos/foreign_main_script.py

Under stock CPython the child runs and nothing anywhere records that the script
that just ran was writable by every account on the machine.
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile

from es_compat import ES_PYTHON, banner


def planted_child():
    """The world-writable copy, running as the main script."""
    st = os.stat(__file__)
    print(f" child running     : {__file__}")
    print(f" child mode        : {stat.filemode(st.st_mode)}")
    print(f" world-writable    : {bool(st.st_mode & stat.S_IWOTH)}")
    if ES_PYTHON:
        print(" under es-python this file was judged in run_mod, before the first")
        print(" statement of the script executed - the parent reports the outcome.")
    else:
        print(" stock CPython judged nothing: the interpreter ran this file without")
        print(" recording, or being able to tell you, who was able to write it.")
    return 0


def main():
    banner("world-writable main script (the load before your code)")

    workdir = tempfile.mkdtemp(prefix="eyalsec_mainscript_")
    try:
        planted = os.path.join(workdir, "deploy_job.py")
        shutil.copyfile(__file__, planted)
        # es_compat lives next to this file; the copy needs it on its path too.
        shutil.copyfile(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "es_compat.py"),
                        os.path.join(workdir, "es_compat.py"))
        os.chmod(planted, 0o666)

        st = os.stat(planted)
        print(f" planted script    : {planted}")
        print(f" mode              : {stat.filemode(st.st_mode)}")
        print(f" owner             : uid {st.st_uid} (me: uid {os.geteuid()})")
        print(f" interpreter       : {sys.executable}")
        print()
        print(" running it as a main script in a child process...")
        print()

        child = subprocess.run([sys.executable, planted, "--planted"],
                               capture_output=True, text=True)
        for line in child.stdout.splitlines():
            print("   |", line)
        if child.stderr.strip():
            for line in child.stderr.strip().splitlines()[-6:]:
                print("   !", line)

        blocked = child.returncode != 0
        print()
        if blocked:
            print(" RESULT: the script never ran.")
            print("         es-python judged the main script foreign-writable in run_mod")
            print("         and aborted the load before the first statement executed.")
        elif ES_PYTHON:
            print(" RESULT: the script ran, and es-python reported where it came from:")
            print(f"         foreign-code:{planted}")
            print("         Observe mode. To refuse to run such a script, add the rule:")
            print("           Source: foreign   Event: run script   Mode: Raise")
            print("         (nothing reported at all? the foreign source is off on this")
            print("          machine - enable 'foreign' in the machine config, or run")
            print("          locally with ES2_MAKE_FOREIGN_VULN=1)")
        else:
            print(" RESULT: the script ran. Stock CPython.")
            print("         No event, and no way for the application to find out that the")
            print("         file the interpreter just executed was writable by anyone.")
    finally:
        # Never leave a world-writable .py behind, on any exit path.
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    if "--planted" in sys.argv:
        raise SystemExit(planted_child())
    raise SystemExit(main())
