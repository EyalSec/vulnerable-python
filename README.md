# vulnerable-python

An intentionally vulnerable Python web app, built as a live demonstration target
for **[EyalSec](https://eyalsec.com)**. Each endpoint contains exactly one real
vulnerability, wired from a distinct **taint source** into a distinct **sink**.
Together the endpoints cover every source and every sink class EyalSec tracks.

Think DVWA or OWASP WebGoat, but purpose-built to show what runtime taint
tracking sees: run the *same unchanged code* under stock CPython and it is a
normal, silently exploitable app; run it under **es-python** and every attack
that reaches a sink is reported to your dashboard, or aborted at the sink.

> ### Warning: this app is deliberately, dangerously insecure
> Every route runs attacker-controlled input into a dangerous operation on
> purpose. Run it **only on an isolated lab machine you control**. Never expose
> it to the internet and never deploy it to production.

---

## The point in one picture

The app is plain standard-library Python. It does not import, detect, or know
about EyalSec. It is byte-for-byte identical between the two runs below. Only
the interpreter changes.

| Run it with | What happens |
|---|---|
| **stock CPython** (`python3 app.py`) | The app works and quietly does whatever the attacker asked. No signal, no record. This is what an unprotected Python service does today. |
| **es-python** (EyalSec) | Tainted data reaching a sink is reported to the dashboard (**Observe** mode), or raises a `RuntimeError` at the sink (**Protect** mode, `ES2_RAISE=1`). Zero source changes. |

That difference, with no code changes, is the entire product.

---

## Quickstart

```bash
# one dependency
es-pip install -r requirements.txt        # or: pip install -r requirements.txt

# A) stock Python - silently vulnerable, no telemetry
python3 app.py                            # http://127.0.0.1:5000/

# B) es-python, local dev build - arms every taint source, then launches
./run-eyalsec.sh
#    Observe -> Protect:  ES2_RAISE=1 ./run-eyalsec.sh

# C) the three demos that no other tool class can reproduce, run twice each:
#    as configured, then asking for a raise (works under stock Python too)
./run-demos.sh                            # or: ./run-demos.sh python3
```

Open http://127.0.0.1:5000/ for the endpoint catalog. Under es-python, click the
example links and watch each one land on your EyalSec dashboard.

If you only have time for one thing, run `./run-demos.sh` and read
[What only runtime taint can do](#what-only-runtime-taint-can-do). The endpoints
show breadth; those three show what the runtime engine does that scanners,
hooks, agents and filters cannot.

### On a real monitored machine

For a client-representative demo, do not use the dev flags. Instead:

1. Install es-python on an isolated demo box from your EyalSec dashboard's
   `/install.sh`.
2. In the dashboard **machine config**, arm the taint sources you want (socket,
   file, stdin, env, foreign-code) and pick Observe or Protect per sink.
3. Run the app with the installed interpreter: `python3.13 app.py`.
4. Exercise the endpoints and watch the events appear, attributed to that machine.

The obfuscated production build arms taint from the **server-pushed machine
config**, not from environment variables. The `run-eyalsec.sh` flag path is only
for a local *dev* es-python build.

---

## Coverage: every source, every sink

**Taint sources** (where untrusted data enters), each armed independently:

| Source | Armed by (dev) | Demonstrated by |
|---|---|---|
| Network socket | `ES2_MAKE_SOCKET_VULN` | every HTTP endpoint (request data) |
| File read | `ES2_MAKE_FILE_VULN` | `GET /source/file` |
| stdin / `input()` | `ES2_MAKE_STDIN_VULN` | `demos/stdin_demo.py`, `demos/input_demo.py` |
| Environment variable | `ES2_MAKE_ENV_VULN` | `GET /source/env` |
| Command-line `argv` | `ES2_MAKE_ENV_VULN` | `demos/argv_demo.py` |
| Foreign code (other-user-writable) | `ES2_MAKE_FOREIGN_VULN` | `GET /source/foreign`, `demos/uncatchable_plugin.py` |
| `make_vuln(obj, n)` (an application-declared secret) | dev build: whenever the taint engine is active. Installed build: only when the machine config enables the `make_vuln` source | `demos/secret_exfil_server.py`, `demos/taint_gauntlet.py` |

**Sink classes** (where tainted data becomes an exploit): SQL execution, OS
command / shell, `eval` / `exec`, dynamic import, deserialization
(`pickle` / `marshal`), file-path open, outbound connect (SSRF), XML parse,
regex, CSV, `str.format`, `os.mkfifo`, and native/FFI load. Every one has a
dedicated endpoint below.

---

## Endpoint reference

Socket source (HTTP request data is tainted the moment it is received):

| Endpoint | Vulnerability | Sink | Example |
|---|---|---|---|
| `GET /sqli` | SQL injection | `sqlite3.execute` | `/sqli?name=x' OR '1'='1` |
| `GET /cmd` | OS command injection | `os.system` | `/cmd?host=127.0.0.1; id` |
| `GET /cmd-subprocess` | Command injection | `subprocess(shell=True)` | `/cmd-subprocess?host=127.0.0.1; whoami` |
| `GET /eval` | Code injection | `eval` | `/eval?expr=6*7` |
| `GET /exec` | Code injection | `exec` | `/exec?code=x=1` |
| `POST /pickle` | Insecure deserialization | `pickle.loads` | `curl --data-binary @payload.pkl :5000/pickle` |
| `POST /marshal` | Deserialization | `marshal.loads` | `curl --data-binary @payload.marshal :5000/marshal` |
| `GET /path` | Path traversal | `open()` | `/path?file=../../../../etc/passwd` |
| `GET /ssrf` | SSRF | `urllib` / connect | `/ssrf?url=http://169.254.169.254/` |
| `POST /xxe` | XXE / XML injection | `ElementTree.fromstring` | `curl --data-binary @doc.xml :5000/xxe` |
| `GET /redos` | ReDoS / regex injection | `re.search` | `/redos?pattern=(a+)+$&text=aaaaaaaaaaX` |
| `GET /csv` | CSV / formula injection | `csv.writer` | `/csv?row=name,=cmd\|'/C calc'!A0` |
| `GET /format` | Format-string leak | `str.format` | `/format?template={secrets[api_key]}` |
| `GET /import` | Dynamic import injection | `importlib.import_module` | `/import?module=os` |
| `GET /mkfifo` | Path injection | `os.mkfifo` | `/mkfifo?name=../escape.fifo` |
| `GET /ctypes` | Native/FFI load | `ctypes.CDLL` | `/ctypes?lib=libc.so.6` |

Other sources:

| Endpoint | Vulnerability | Flow |
|---|---|---|
| `GET /source/file` | File-borne SQL injection | `sample/tainted_input.txt` -> `sqlite3.execute` |
| `GET /source/env` | Env-borne command injection | `$DEMO_INPUT` -> `os.system` |
| `GET /source/foreign` | Supply-chain / tampered code | load a world-writable `.py` -> `foreign-code:<path>` |

Process-launch sources (CLI demos, not HTTP):

```bash
echo '6*7' | ES2_MAKE_STDIN_VULN=1 ~/opt/eyalsec/bin/python3.13 demos/stdin_demo.py
ES2_MAKE_STDIN_VULN=1 ~/opt/eyalsec/bin/python3.13 demos/input_demo.py
ES2_MAKE_ENV_VULN=1  ~/opt/eyalsec/bin/python3.13 demos/argv_demo.py '127.0.0.1; id'
```

---

## What only runtime taint can do

The endpoints above are the familiar vulnerability classes, and plenty of tools
claim some coverage of them. These three demos are the ones that separate a
runtime taint engine from everything else: a secret that **cannot** leave the
process, a code load that **nothing else can see**, and a value that stays
tracked through transformations that erase every trace of what it was.

```bash
python3 demos/secret_exfil_server.py --selftest   # 1. the secret that cannot be sent
python3 demos/uncatchable_plugin.py               # 2. the load nothing else sees
python3 demos/taint_gauntlet.py                   # 3. taint through 15 transformations
```

Each one runs under **both** interpreters and prints which it is running under,
so the contrast is visible in a single command. Under stock CPython they all
succeed silently, which is the point.

### 1. A secret that cannot leave the process

`demos/secret_exfil_server.py` is a plain TCP echo server holding one secret:

```python
SECRET = make_vuln(b"data sent", 1)
```

`make_vuln(obj, 1)` marks the object tainted and stamps it with **user taint
number 1**. That number is the handle you write policy against: it names *this
value*, not a category of traffic. Send the server the word `data` and it tries
to hand the secret back. With the rule armed, `sendall` aborts before a byte
reaches the wire:

```
[server] received 4 bytes
[server] BLOCKED: EyalSec: untrusted data from make_vuln reached sink socket sendall

[client] sent 'hello' -> echoed back correctly : True
[client] sent 'data'  -> secret in the reply   : False
```

Two properties make this a control rather than a warning:

- **The block is synchronous.** The raise happens *before* the send loop, not
  after it. A sink that reported after sending would leave the secret already
  gone, and the application's own `except RuntimeError` would hide it. Here the
  receiver gets nothing.
- **The rule is scoped to the secret, not to the socket.** It matches taint
  number 1, so ordinary echo traffic keeps flowing and only the secret is
  stopped. A server that blocked every tainted `sendall` would just be a broken
  server.

Arm it in your dashboard's rules for that machine:

| Field | Value |
|---|---|
| Source | `1` (the custom taint number) |
| Event | `sendall` |
| Mode | Raise |

### 2. The code load nothing else can see

`demos/uncatchable_plugin.py` is a plugin loader written the way real
applications write one:

```python
with open(plugin_path) as fh:
    source = fh.read()      # read as DATA, not imported
exec(source, namespace)     # ...and then run
```

The plugin file is writable by another user, so whoever can write it owns the
process. There is no import statement, no `__file__`, no `sys.modules` entry.
`exec` compiles the string under the filename `<string>`. Walk each detection
strategy to its dead end:

| Tool class | Why it misses this |
|---|---|
| SAST, dependency and secret scanners | The dangerous content is not in the repository. It is written to disk at runtime, by someone else, after the scan. At most a linter warns that `exec()` exists, which is equally true of safe plugin loaders. |
| Python audit hooks (`sys.addaudithook`, PEP 578) | The officially supported hook for exactly this. It fires on `compile` and `exec` and is handed the source plus a filename, but for `exec` of a string that filename is the constant `<string>`. The same hook does see a separate `open` event carrying the real path, and nothing connects the two. So it still cannot tell `exec(config_text)` read from an admin-owned file apart from `exec(attacker_text)` read from an attacker-owned one. |
| RASP and APM agents | Monkey-patch at the Python level and inherit the same blindness, for the same reason: a `str` carries no history. |
| EDR and syscall monitors | See the file opened and read, and nothing that distinguishes reading it from running it. No `execve`, no new process, no library load, no network. |
| File integrity monitoring | Can flag the write, if you knew in advance to watch that path. It tells you a file changed, not that your process ran it. |

es-python sees it because the taint chain remembers where the bytes came from.
The `open().read()` stamped the resolved path onto the string; when that string
reaches `exec`, the interpreter walks back to the origin, stats it, finds it
writable by another user, and reports `foreign-code:/tmp/eyalsec_demo_plugin.py`.
Under an armed rule the raise is synchronous, so the source is never compiled:

```
BLOCKED: EyalSec: untrusted data from /tmp/eyalsec_demo_plugin.py reached sink exec

RESULT: the plugin never ran.
```

This is the *same* event a direct `import` of that file produces, so one rule
covers both arrival paths. Enable the **foreign** taint source in the machine
config; to block rather than observe, add `Source: foreign`, `Event: exec`,
`Mode: Raise`.

### 3. Taint through fifteen transformations

`demos/taint_gauntlet.py` takes a secret and runs it through fifteen
consecutive transformations, chosen the way an exfiltration tool chooses them,
to leave nothing a matcher can match: hex, base64, rot13, reversal, a
digit-substitution cipher, a dict-key round trip, UTF-16, a memoryview slice,
hexlify, a bytearray round trip and string formatting. Then it sends the result
to a socket.

```
  #  transformation               type     len  tainted  taint  fingerprint
  0  the secret itself            bytes     36     True      7  d5ca40c1d5
  1  bytes.hex()                  str       72     True      7  0f1e02bdff
  ...
 15  str.encode()  (final)        bytes    390     True      7  7e5f6a006c

 a content matcher searching the final payload finds:
   the secret, plain        not present
   the secret, hex          not present
   the secret, base64       not present
   the 'EYALSEC{' marker    not present
```

36 bytes in, 390 bytes out, a different alphabet, a different encoding, a
different byte width, and no shared substring. Taint number **7** still arrives
at the sink, so a rule scoped to the original secret still matches, and a raise
rule still stops the send.

- **Content matching** (DLP, egress filters, WAFs, secret scanners) compares
  bytes against known bad bytes. Two encodings in, the bytes stop resembling the
  secret. You can teach a matcher base64; you cannot teach it every composition
  of every encoding, and the attacker picks the composition after seeing your
  rules. The demo prints that search and its four misses.
- **Static taint analysis** must model each of these operations across module
  boundaries and then decide which path a real run takes. Chains built from
  `codecs`, `memoryview`, `binascii` and container round-trips are where static
  models get over-approximated into uselessness or quietly give up.
- **Python-level RASP** hooks the functions it knows. `str.translate`,
  `memoryview.tobytes`, `bytes.hex` and a dict-key round trip are C-level
  built-in operations: an agent written in Python cannot patch them and has
  nowhere to attach per-object state, so taint is lost at the first one and the
  rest of the chain is invisible.

es-python propagates taint at the level the transformation happens, in the C
implementation of the operation itself. Every step in the chain is there because
it is verified to carry taint through. Arm the block with `Source: 7`,
`Event: sendall`, `Mode: Raise`.

### What actually turns raising on

Blocking is driven by the **machine config your dashboard pushes**, not by an
environment variable. This matters for reading the demo output:

- A **scoped rule** (a source plus an event, as in the tables above) raises on
  that one flow. This is the supported path and the only one that produces
  demo 1's real result: the echo keeps working and the secret still cannot
  leave.
- `ES2_RAISE=1` is a **fallback**, honoured only when the machine has no raise
  rules of its own, and only on builds that enable the fallback. On a machine
  that already has rules, or an installed build without it, setting the variable
  changes nothing. If both runs of a `run-demos.sh` pair print the same result,
  this is why.
- When `ES2_RAISE=1` does apply it raises at **every** sink, including `print()`
  of tainted data, since stdout is a sink too. That is useful for a quick local
  check and wrong for anything else. (The demos never print tainted values, so
  they behave sensibly either way.)

In all three cases the *detection* is the same. Observe mode is not a degraded
mode: the flow is found and reported either way, and the rule only decides
whether it is also stopped.

---

## SQL injection across every shipped driver

The live `/sqli` route uses stdlib `sqlite3`, so it runs anywhere with no
database server. es-python also ships the dominant third-party drivers, each
carrying the identical statement-string sink (fires on the query text only, so
correct parameterization is never a false positive). Point any of these at a
real database and the same event fires:

| Database | Driver | Sink site |
|---|---|---|
| SQLite | `sqlite3` (stdlib, live here) | cursor execute |
| PostgreSQL | `psycopg2` | `_psyco_curs_execute` (C) |
| PostgreSQL | `psycopg` v3 | `PGconn` query wrappers (C) |
| MySQL | `mysqlclient` | `_mysql` query (C) |
| MariaDB | `mariadb` | `MrdbCursor_parse` (C) |
| Oracle | `oracledb` | `BaseCursorImpl._prepare` (Cython) |

---

## Observe vs Protect

- **Observe** (default): the sink runs, and the tainted source-to-sink event is
  recorded to the dashboard. Behavior is unchanged. Use this first.
- **Protect** (`ES2_RAISE=1`): the sink raises a `RuntimeError`, aborting the
  operation at the injection boundary. For SQL, path, import, and
  deserialization sinks the raise fires *before* the dangerous call; for shell
  sinks it fires immediately at the boundary. In this app that surfaces as an
  HTTP 500 on the attacked endpoint, which is exactly the point: the exploit did
  not complete.

---

## Files

```
app.py                        all HTTP endpoints, each commented SOURCE -> SINK -> report
landing.py                    the landing-page catalog served at /, rendered in pure Python
run-eyalsec.sh                launch the web app under a dev es-python, every source armed
run-demos.sh                  run the three CLI demos twice each, with and without a raise
demos/
  stdin_demo.py               stdin source -> eval
  input_demo.py               input() source -> eval
  argv_demo.py                argv source -> os.system
  secret_exfil_server.py      a secret that cannot leave the process
  uncatchable_plugin.py       the code load nothing else can see
  taint_gauntlet.py           taint through 15 transformations
  es_compat.py                inert stand-ins so every demo also runs on stock CPython
sample/                       fixture files for the file-read and path-traversal demos
requirements.txt              Flask (the only dependency)
```

The `demos/` scripts import `es_compat`, which supplies no-op versions of
`make_vuln` / `check_vuln` / `get_taint` when the interpreter has no taint
engine. That is what lets one unchanged file run on both runtimes and report
which one it is on. Those three builtins are the only es-python API any code
here touches: the web app itself calls nothing, and the endpoints are protected
without a single application-level change.

The landing page is rendered without Jinja2 on purpose: Jinja pulls in the
compiled `markupsafe._speedups` extension, whose stock ABI is incompatible with
es-python's instrumented string layout. Pure-Python rendering keeps the demo
crash-proof under every es-python build.

---

## License

MIT. See [LICENSE](LICENSE). This software is intentionally insecure and exists
solely to demonstrate EyalSec runtime taint tracking. Isolated lab use only.
