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
```

Open http://127.0.0.1:5000/ for the endpoint catalog. Under es-python, click the
example links and watch each one land on your EyalSec dashboard.

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
| Foreign code (other-user-writable) | `ES2_MAKE_FOREIGN_VULN` | `GET /source/foreign` |

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
app.py            all HTTP endpoints, each commented SOURCE -> SINK -> report
landing.py        the landing-page catalog served at /, rendered in pure Python
run-eyalsec.sh    launch under a dev es-python with every source armed
demos/            stdin / input() / argv CLI demonstrations
sample/           fixture files for the file-read and path-traversal demos
requirements.txt  Flask (the only dependency)
```

The landing page is rendered without Jinja2 on purpose: Jinja pulls in the
compiled `markupsafe._speedups` extension, whose stock ABI is incompatible with
es-python's instrumented string layout. Pure-Python rendering keeps the demo
crash-proof under every es-python build.

---

## License

MIT. See [LICENSE](LICENSE). This software is intentionally insecure and exists
solely to demonstrate EyalSec runtime taint tracking. Isolated lab use only.
