# priv/ — privilege escalation, and why it does not work here

Almost every privilege escalation *through Python* is one move: get a
privileged process to load code from somewhere a less-privileged account can
write. A cron job that imports a helper, a `sudo`-invoked deploy script, a
service that runs at boot — each of them loads code, and if any of that code
lives on a file or in a directory somebody else controls, that somebody runs
with the privileged process's authority. No memory corruption, no exploit: they
wrote a file the privileged process was always going to load.

This directory shows the four ways to arrange that move, and shows es-python
catching each one **at the load — before the planted code's first line runs**,
and refusing it when a raise rule is armed.

Every file here is owned by you, private, and trusted. The *only* thing that
makes each demo an escalation is that one file or directory is writable by
another account. That is exactly the question es-python's foreign gate answers:
*could a user other than me have written this?*

## The four vectors

| Demo | The writable thing | Caught as |
|---|---|---|
| `escalate_syspath.py` | a helper module on a `sys.path` directory anyone can write | code load — `foreign-code:<path>`, event `import (foreign code)` |
| `escalate_main_script.py` | the privileged script the cron/sudo entry runs is itself writable | code load — `foreign-code:<path>`, event `run script`, before the first statement |
| `escalate_pyc_cache.py` | the source is private, but its `__pycache__/*.pyc` (or the cache dir) is writable | **data path** — foreign bytes reach the `marshal loads` sink |
| `escalate_startup_hooks.py` | a `sitecustomize.py` on a writable startup directory, run before your program | code load — `foreign-code:<path>`, event `import (foreign code)` |

Three of the four are **code-load** findings: the load itself is the event,
reported with the file's real path even when the code arrives as a string
(`exec`/`compile`) whose filename is `<string>`. Nothing an audit hook, an EDR
file rule, a SAST pass or a RASP keys on — the import looks like every other
import; the only thing that distinguishes it is who could write the file.

The `.pyc` cache demo is deliberately the odd one out, and it is labelled that
way on purpose. The source loader reads the cached bytecode and hands it to
`marshal.loads`. es-python labels bytes read from a foreign-writable file
`foreign`, so this is caught as **tainted data reaching a sink** — origin
`foreign-code:<path>`, sink `marshal loads` — not as a `foreign-code:` code
load. That is where you will actually find it, so that is what the demo tells
you. `escalate_pyc_cache.py` prints `get_taint()` on the cache bytes directly:
under es-python it is `'foreign'`, under plain python3 it is `None`.

## What counts as foreign

Three rules on the file itself, any one of which is enough:

- **owned by another, non-root user** — whoever owns it can rewrite it; its
  permission bits are irrelevant.
- **world-writable (`o+w`)** — any local account, container, CI runner or
  compromised service owns your next load.
- **group-writable, and the group has another real member** — membership is
  resolved for real, including users whose *primary* group it is; a private
  one-member group correctly produces nothing.

Reads (not code loads) additionally look at the immediate parent directory: if
another user can rename or replace the file, the file is foreign even when its
own bits are private. The sticky bit is honoured, so an ordinary file you own in
`/tmp` is **not** foreign.

**Root-owned files are trusted deliberately.** Root can replace anything on the
box, so calling root-owned code untrusted would report the whole standard
library on every import and the signal would be worth nothing. The setup script
plants a root-owned module as a negative control; it must stay silent.

## Run it

Each demo builds its own throwaway fixtures in a temp directory and cleans up
after itself — you do not need to set anything up first:

```bash
# one vector, detected then (attempted) refused
es-python priv/escalate_syspath.py
es-python priv/escalate_syspath.py --raise

# all four, each twice
./priv/run-priv.sh

# the contrast: the same escalations under plain python3, silently
./priv/run-priv.sh python3
```

`--raise` arms the raise on the child process that performs the load, not on the
parent. On the local full dev build an armed raise stops the interpreter at the
first standard-library marshal load during startup — a property of that build,
not a result for the demo; each demo detects this and says so. On a real
monitored machine the machine's own raise rules decide, and the refusal is
clean. Read each demo's own RESULT line; do not read the headers as promises.

## Creating the access yourself: `setup-privesc.sh`

The demos arrange the *world-writable* cases themselves, because any
unprivileged process can `chmod o+w` its own files. Two cases need a second
account — **owned by another user** and **group-writable with another member** —
and those, plus the root-owned negative control, are what `setup-privesc.sh`
builds when you run it with `sudo`. It mirrors `../setup-foreign.sh`.

```bash
# durable fixtures under /var/tmp/eyalsec-privesc (owner/group cases need sudo)
./priv/setup-privesc.sh
sudo ./priv/setup-privesc.sh

# grant "somebody else can write this" to a path of your own — the access that
# turns loading that file into an escalation:
./priv/setup-privesc.sh --grant /path/to/the/file/you/load

# undo everything
./priv/setup-privesc.sh --remove
```

> **Isolated lab machines only.** `setup-privesc.sh` deliberately creates the
> misconfiguration — files and directories writable by other accounts. That is
> the point, and it is not something to leave on a machine that matters.

## The one-line version

You cannot escalate by planting code where a privileged process will load it,
because es-python decides *who could have written this* at the load, before the
code runs — and refuses it when told to. Provenance is checked at the operation
the program actually performs, so there is nothing in between to encode around.
