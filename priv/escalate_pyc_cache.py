#!/usr/bin/env python3.13
"""PRIVESC 3 - a private source file with a WRITABLE bytecode cache.

  ############################################################################
  #  WARNING: intentionally vulnerable demo. Isolated lab machines only.     #
  ############################################################################

You locked down the source. `app_config.py` is mode 0644, owned by you, in a
directory only you can write. But Python does not run the source on the second
import - it runs the compiled `__pycache__/app_config.*.pyc`, and if
THAT file (or the `__pycache__` directory that holds it) is writable by another
account, they replace the bytecode and your hardened source is never read.

    app_config.py                       0644, mine        (looks safe)
    __pycache__/app_config...pyc        writable by other (runs instead)

This is the vector that fools "just check the .py permissions". The bytecode is
what executes, and the interpreter loads it through a different path than the
source.

What es-python does - and why this one is different
---------------------------------------------------
The other three demos are CODE-LOAD findings: the load itself is reported as
`foreign-code:<path>`. This one is caught on the DATA path instead. The source
loader reads the `.pyc` bytes and hands them to `marshal.loads`; es-python
labels bytes read from a foreign-writable file `foreign`, and `marshal.loads`
of foreign bytes is the sink. So the report is a tainted-data-reached-sink
finding on `marshal loads`, not a `foreign-code:` line - naming it correctly
matters, because that is where you will actually find it.

This demo shows the concrete evidence directly: it reads the planted `.pyc` and
prints `get_taint()` on the bytes. Under es-python that is `'foreign'`; under
plain python3 it is `None`.

Run it
------
    es-python priv/escalate_pyc_cache.py            # observe: bytes are foreign
    es-python priv/escalate_pyc_cache.py --raise    # protect: marshal refuses

Under plain python3 the replaced bytecode runs and nothing records that the
cache it came from was writable by another account.
"""
import glob
import os
import stat
import sys
import tempfile

from _privlib import (CHILD_OK, CHILD_START, ES_PYTHON, banner, child_env,
                      print_child, print_startup_caveat, run_victim,
                      show_predicate, wants_raise)

try:
    get_taint = get_taint                    # noqa: F821 (es-python builtin)
except NameError:
    def get_taint(_obj):
        return None


VICTIM = f'''\
import sys
print("{CHILD_START}")
sys.dont_write_bytecode = True               # do not regenerate the cache we planted
sys.path.insert(0, sys.argv[1])
import app_config                             # loads the WRITABLE .pyc, not the source
print("{CHILD_OK}", app_config.VALUE)
'''

SOURCE = '''\
# Mode 0644, owned by me, in a directory only I can write. Looks safe.
VALUE = "original, from trusted source"
'''


def main():
    banner("privesc 3: private source, writable bytecode cache")
    workdir = tempfile.mkdtemp(prefix="eyalsec_privesc_pyc_")
    try:
        pkgdir = os.path.join(workdir, "pkg")
        os.makedirs(pkgdir)
        src = os.path.join(pkgdir, "app_config.py")
        with open(src, "w") as fh:
            fh.write(SOURCE)
        os.chmod(src, 0o644)

        # Compile once so the .pyc exists, then make the cache writable - the
        # part an attacker controls. (chmod o+w on a dir you own needs no root.)
        import py_compile
        py_compile.compile(src, doraise=True)
        cache = glob.glob(os.path.join(pkgdir, "__pycache__", "app_config.*.pyc"))[0]
        os.chmod(os.path.dirname(cache), 0o777)
        os.chmod(cache, 0o666)

        st_src = os.stat(src)
        st_pyc = os.stat(cache)
        print(f" source  : {src}")
        print(f"           {stat.filemode(st_src.st_mode)}  "
              f"world-writable={bool(st_src.st_mode & stat.S_IWOTH)}  (looks safe)")
        print(f" cache   : {cache}")
        print(f"           {stat.filemode(st_pyc.st_mode)}  "
              f"world-writable={bool(st_pyc.st_mode & stat.S_IWOTH)}  (runs instead)")
        print()
        show_predicate(cache)
        print()

        # Concrete, local evidence: the bytes read from the cache are foreign.
        with open(cache, "rb") as fh:
            pyc_bytes = fh.read()
        with open(src, "rb") as fh:
            src_bytes = fh.read()
        print(" reading the two files back through the interpreter:")
        print(f"   get_taint(cache bytes)  = {get_taint(pyc_bytes)!r}"
              "   <- marshal.loads of these is the sink")
        print(f"   get_taint(source bytes) = {get_taint(src_bytes)!r}"
              "   <- the source itself is not foreign")
        print()
        print(" importing the module in a child (it runs the cache, not the source)...")
        print()

        kind, out, err_tail, rc = run_victim(VICTIM_PATH(workdir, VICTIM), pkgdir,
                                             env=child_env(wants_raise(sys.argv)))
        print_child(out, err_tail)
        print()
        if kind == "blocked":
            print(" RESULT: the bytecode never loaded.")
            print("         es-python labelled the cache bytes foreign and refused")
            print("         marshal.loads before the replaced bytecode ran.")
        elif kind == "startup":
            print_startup_caveat()
        elif ES_PYTHON:
            print(" RESULT: the cache loaded (observe mode). es-python reported it as")
            print(f"         foreign data reaching the marshal sink:")
            print(f"           origin foreign-code:{cache}")
            print("           sink   marshal loads")
            print("         To refuse it, arm the rule on the machine:")
            print("           Source: foreign   Sink: marshal.loads   Mode: Raise")
            print("         (nothing reported? enable 'foreign' in the machine config,")
            print("          or run locally with ES2_MAKE_FOREIGN_VULN=1)")
        else:
            print(" RESULT: the cache loaded. Plain python3.")
            print("         get_taint returned None: no way to tell that the bytecode")
            print("         the interpreter ran came from a cache anyone could write.")
    finally:
        import shutil
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


def VICTIM_PATH(workdir, text):
    """Write the victim script (owned by me, private) and return its path."""
    path = os.path.join(workdir, "victim.py")
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o644)
    return path


if __name__ == "__main__":
    raise SystemExit(main())
