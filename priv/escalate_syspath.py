#!/usr/bin/env python3.13
"""PRIVESC 1 - a helper module on a writable `sys.path` directory.

  ############################################################################
  #  WARNING: intentionally vulnerable demo. Isolated lab machines only.     #
  ############################################################################

The classic one, and the one people actually hit. A privileged process - a
cron job, a `sudo`-invoked deploy script, a root-run service - imports a helper
module by name:

    import app_config

`app_config` resolves against `sys.path`. If ANY directory earlier on that path
is writable by a less-privileged account, that account plants `app_config.py`
there and their code runs with the privileged process's authority. No exploit,
no memory corruption: they wrote a file the privileged process was always going
to import.

    victim.py        (mine, private, trusted)     imports ->
    lib/app_config.py (mode 0666, anyone can write) => attacker's code, my uid

What es-python does
-------------------
The import is a CODE LOAD from a foreign-writable file, so es-python reports it
at load time - origin `foreign-code:<path>`, event `import (foreign code)` -
before a single statement of `app_config` runs. Under an armed raise rule the
import is refused and the privileged process never executes the planted code.

Nothing an audit hook, an EDR file rule or a SAST pass keys on: the import
looks exactly like every other import. The only thing that distinguishes it is
who could write the file, which is precisely what the foreign gate checks.

Run it
------
    es-python priv/escalate_syspath.py            # observe: the load is reported
    es-python priv/escalate_syspath.py --raise    # protect: the load is refused

`--raise` arms the raise on the child that performs the load, not on the parent
(see _privlib.child_env for why). Under stock CPython the planted module is
imported and nothing records that the directory it came from was writable by
another account.
"""
import os
import stat
import sys
import tempfile

from _privlib import (CHILD_OK, CHILD_START, ES_PYTHON, banner, child_env,
                      print_child, print_startup_caveat, run_victim,
                      show_predicate, wants_raise)


VICTIM = f'''\
import sys
print("{CHILD_START}")                 # startup survived
sys.path.insert(0, sys.argv[1])        # the writable directory, first on the path
print("importing app_config from a directory another account can write...")
import app_config                       # <- the planted code loads HERE
print("{CHILD_OK}", app_config.DB_URL) # only reached if the load was allowed
'''

PLANTED = '''\
# Planted by a less-privileged account into a writable sys.path directory.
# Under stock CPython this runs with the importing process's full authority.
import os
DB_URL = "postgres://prod/main"
# a real attacker would do their work here; we only prove we ran:
open(os.path.join(os.path.dirname(__file__), "attacker-was-here"), "w").close()
'''


def main():
    banner("privesc 1: helper module on a writable sys.path directory")
    workdir = tempfile.mkdtemp(prefix="eyalsec_privesc_syspath_")
    try:
        libdir = os.path.join(workdir, "lib")
        os.makedirs(libdir)
        planted = os.path.join(libdir, "app_config.py")
        with open(planted, "w") as fh:
            fh.write(PLANTED)
        os.chmod(planted, 0o666)                       # anyone can rewrite it

        victim = os.path.join(workdir, "victim.py")
        with open(victim, "w") as fh:
            fh.write(VICTIM)
        os.chmod(victim, 0o644)                         # the victim itself is fine

        st = os.stat(planted)
        print(f" victim script  : {victim}  (mine, mode 0644 - trusted)")
        print(f" planted module : {planted}")
        print(f" planted mode   : {stat.filemode(st.st_mode)}  "
              f"world-writable={bool(st.st_mode & stat.S_IWOTH)}")
        print()
        show_predicate(planted)
        print()
        print(" running the privileged victim as a child, with lib/ on its path...")
        print()

        kind, out, err_tail, rc = run_victim(victim, libdir,
                                             env=child_env(wants_raise(sys.argv)))
        print_child(out, err_tail)
        print()
        if kind == "blocked":
            print(" RESULT: the planted module never loaded.")
            print(f"         es-python judged {os.path.basename(planted)} foreign-writable")
            print("         and refused the import before app_config's code ran.")
        elif kind == "startup":
            print_startup_caveat()
        elif ES_PYTHON:
            marker = os.path.join(os.path.dirname(planted), "attacker-was-here")
            print(" RESULT: the planted module ran (observe mode). es-python reported it:")
            print(f"         foreign-code:{planted}")
            print(f"         proof the attacker's code executed: {os.path.exists(marker)}")
            print("         To refuse such an import, arm the rule on the machine:")
            print("           Source: foreign   Event: import (foreign code)   Mode: Raise")
            print("         (nothing reported? enable 'foreign' in the machine config,")
            print("          or run locally with ES2_MAKE_FOREIGN_VULN=1)")
        else:
            print(" RESULT: the planted module ran. Stock CPython.")
            print("         No event, and no way for the process to learn that the module")
            print("         it imported came from a directory anyone could write.")
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
