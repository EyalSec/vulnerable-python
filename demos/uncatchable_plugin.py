#!/usr/bin/env python3.13
"""SOURCE foreign-writable file (read as DATA) -> SINK exec  =>  the load nothing else sees.

  ############################################################################
  #  WARNING: part of an intentionally vulnerable demo app. Isolated lab      #
  #  machines only.                                                           #
  ############################################################################

The flow is four lines of the most ordinary Python imaginable - a plugin
loader, the kind that ships in a thousand real applications:

    with open(plugin_path) as fh:
        source = fh.read()          # the file is read as DATA, not imported
    exec(source, namespace)         # ...and then run

The plugin file is writable by another user. Anyone who can write it owns this
process. That is the entire supply-chain attack, and it happens without a
single import statement.

Why every other class of tool misses this
-----------------------------------------
The code that runs is a **bare string**. `exec` compiles it under the filename
`<string>`. There is no module, no `__file__`, no import hook, no entry in
`sys.modules`, nothing on disk that identifies what just ran. Follow each
detection strategy to its dead end:

* **SAST / dependency scanners** analyse the repository. The dangerous content
  is not in the repository - it arrives on disk at runtime, written by someone
  else, after the scan. There is nothing to scan. At most a linter flags
  "exec() is dangerous", which is a style warning about a line that is present
  in perfectly safe plugin loaders too.

* **Python audit hooks** (`sys.addaudithook`, the officially supported hook for
  exactly this, PEP 578) fire on `compile` and `exec`, and receive the source
  plus a filename - but for `exec` of a string that filename is the constant
  `<string>`. The same hook does see a separate `open` event carrying the real
  path, and nothing links the two together. So an audit hook still cannot
  distinguish `exec(config_text)` read from a file the admin owns from
  `exec(attacker_text)` read from a file the attacker owns.

* **RASP / APM agents** monkey-patch at the Python level and inherit the exact
  same blindness, for the exact same reason: a `str` carries no history.

* **EDR / syscall monitors** see the file opened and read, and nothing that
  distinguishes reading it from running it. No `execve`, no new process, no
  library load, no network. Reading a text file and doing arithmetic on it
  looks identical to reading a text file and running it.

* **File-integrity monitoring** could flag the write - if you knew in advance
  to watch that path, and if the attacker did not simply use a path you had not
  enumerated. It also tells you a file changed, not that your process ran it.

es-python sees it because the taint chain remembers where the bytes came from.
The `open().read()` stamped the resolved path onto the string. When that string
reaches `exec`, the interpreter walks the chain back to the origin, stats it,
finds it writable by another user, and reports:

    foreign-code:/tmp/eyalsec_demo_plugin.py

Under an armed raise rule the load is aborted **before the source is compiled**
- this raise is synchronous, so the code never runs at all:

    RuntimeError: EyalSec: untrusted data from /tmp/eyalsec_demo_plugin.py
                  reached sink exec

Note this is the *same* `foreign-code:<path>` event a direct `import` of that
file produces. Whether the attacker's code arrives by import or by
`exec(open(p).read())`, one rule covers both.

Arming it
---------
Enable the **foreign** taint source for the machine in your dashboard's machine
config. To block rather than observe, add:

    Source: foreign   Event: exec   Mode: Raise

Run it
------
    python3 demos/uncatchable_plugin.py

Under stock CPython the plugin runs and nothing anywhere records that a
world-writable file just executed inside your process.
"""
import os
import shutil
import stat
import tempfile

from es_compat import ES_PYTHON, banner, check_vuln, get_taint

# What "another user" writes into the plugin. Deliberately benign - it proves
# execution without doing damage. A real attacker writes a reverse shell here.
PLUGIN_SOURCE = """\
# Written by whoever can write this file. It is not part of the application,
# it is not in the repository, and nothing imported it.
PLUGIN_RESULT = "attacker-controlled code executed inside the application"
import os
PLUGIN_UID = os.getuid()
"""


def plant_plugin(directory):
    """Create the plugin file and make it writable by every user (mode 0666).

    The file goes in a private 0700 directory created fresh for this run rather
    than at a fixed, predictable /tmp path. A demo that is *about* other users
    writing your files should not itself be hijackable by one: a guessable path
    lets another user pre-create it as a symlink and have us truncate whatever
    it points at. The foreign-writable check that this demo exercises looks at
    the file's own mode, so a private parent does not weaken the demonstration.
    """
    path = os.path.join(directory, "eyalsec_demo_plugin.py")
    with open(path, "w") as fh:
        fh.write(PLUGIN_SOURCE)
    os.chmod(path, 0o666)
    return path, os.stat(path)


def load_plugin(path):
    """The vulnerability, in the form real applications actually write it.

    Note what is NOT here: no import, no importlib, no __file__, no sys.modules
    entry. Just a file read and an exec of the resulting string.
    """
    with open(path) as fh:
        source = fh.read()      # <-- SOURCE: bytes stamped with this path

    namespace = {}
    exec(source, namespace)     # <-- SINK: compiled as "<string>"
    return namespace, source


def main():
    banner("world-writable plugin, exec'd as a bare string")

    workdir = tempfile.mkdtemp(prefix="eyalsec_demo_")
    try:
        plugin_path, st = plant_plugin(workdir)
        print(f" plugin file      : {plugin_path}")
        print(f" mode             : {stat.filemode(st.st_mode)}")
        print(f" writable by others: {bool(st.st_mode & stat.S_IWOTH)}")
        print()

        blocked = False
        namespace = {}
        source = ""
        try:
            namespace, source = load_plugin(plugin_path)
        except RuntimeError as exc:
            blocked = True
            print(f" BLOCKED: {exc}")

        tracked = check_vuln(source)
        if not blocked:
            print(f" source string tainted : {tracked}")
            print(f" taint source          : {get_taint(source)}")
            print(" filename exec saw     : <string>   (no path, no __file__)")
            print(f" plugin ran            : {'PLUGIN_RESULT' in namespace}")

        print()
        if blocked:
            print(" RESULT: the plugin never ran.")
            print("         The raise is synchronous - the source was not even compiled.")
            print("         es-python recovered the file path from the taint chain and")
            print("         matched it against the foreign-writable check.")
        elif ES_PYTHON and tracked:
            print(" RESULT: the plugin ran, and es-python tracked where its code came")
            print(f"         from:  foreign-code:{plugin_path}")
            print("         Observe mode. To stop the load instead, add the rule:")
            print("           Source: foreign   Event: exec   Mode: Raise")
        elif ES_PYTHON:
            print(" RESULT: the plugin ran, and taint was NOT tracked, so nothing was")
            print("         reported. The foreign taint source is off on this machine:")
            print("         enable 'foreign' in the machine config, or run locally with")
            print("         ES2_MAKE_FOREIGN_VULN=1.")
        else:
            print(" RESULT: the plugin ran. Stock CPython.")
            print("         No event. No log line. No process spawned, no library loaded,")
            print("         no import recorded - nothing for any monitor to notice.")
            print("         The application cannot even tell you which file it just ran.")
    finally:
        # Never leave a world-writable .py behind, on any exit path.
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
