#!/usr/bin/env python3.13
"""
vulnerable-python - an intentionally vulnerable demo app for EyalSec.

  ############################################################################
  #  WARNING: THIS APPLICATION IS DELIBERATELY, DANGEROUSLY INSECURE.        #
  #  Every endpoint contains a real, exploitable vulnerability by design.    #
  #  Run it ONLY on an isolated lab machine you control. Never expose it to  #
  #  the internet and never deploy it to production.                         #
  ############################################################################

Why this exists
---------------
EyalSec ships `es-python`, a drop-in CPython that performs dynamic taint
tracking from untrusted *sources* to dangerous *sinks* inside the C-level
interpreter. This app is a live target for it.

Run this exact file two ways:

  * Under stock CPython  -> it is a normal, silently exploitable web app.
                            Nothing is logged. The vulnerability just works.
  * Under es-python      -> every attack that reaches a sink is reported to
                            the EyalSec dashboard (Observe mode), or aborted
                            with a RuntimeError at the sink (Protect mode,
                            ES2_RAISE=1). The code did not change - the
                            interpreter did.

The code below is plain standard-library Python. It is byte-for-byte identical
regardless of which interpreter runs it - that is the whole point. EyalSec adds
zero source changes to the app it protects.

Each route demonstrates exactly one (taint source -> sink) pair. See the
ENDPOINTS catalog at the bottom, which also drives the landing page at "/".
"""

import csv
import ctypes
import io
import marshal
import os
import pickle
import re
import sqlite3
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

from flask import Flask, Response, request

import landing

app = Flask(__name__)

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(HERE, "vulnerable_demo.db")
SAMPLE_DIR = os.path.join(HERE, "sample")

# A fake secret the format-string sink can leak, so the demo shows real impact.
APP_SECRETS = {"api_key": "sk-demo-DO-NOT-USE-3f9a2c7b41e0", "flag": "EYALSEC{format_string_leak}"}


# --------------------------------------------------------------------------- #
# One-time fixtures: a seeded SQLite DB, a file the "file" source reads, and a
# world-writable module the "foreign-code" source flags.
# --------------------------------------------------------------------------- #
def setup_fixtures():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, bio TEXT, secret TEXT);
        INSERT INTO users (name, bio, secret) VALUES
            ('alice', 'demo user',  'alice-password-hunter2'),
            ('bob',   'demo user',  'bob-api-token-abc123'),
            ('admin', 'superuser',  'admin-root-key-topsecret');
        """
    )
    db.commit()
    db.close()

    os.makedirs(SAMPLE_DIR, exist_ok=True)

    # The "file" taint source: an on-disk file whose contents an attacker who
    # can write the file controls. Its bytes flow into a SQL query below.
    with open(os.path.join(SAMPLE_DIR, "tainted_input.txt"), "w") as fh:
        fh.write("alice' OR '1'='1")

    # A benign readable file for the path-traversal demo's default case.
    with open(os.path.join(SAMPLE_DIR, "notes.txt"), "w") as fh:
        fh.write("public demo note - nothing secret here\n")

    # A secret that lives OUTSIDE the sample/ sandbox the /path route is meant
    # to serve. Reading it via ../ proves the traversal escaped the sandbox,
    # reliably and regardless of how deep the app is installed. (/etc/passwd is
    # the classic target too, once enough ../ hops reach the filesystem root.)
    with open(os.path.join(HERE, "flag.txt"), "w") as fh:
        fh.write("EYALSEC{path_traversal_escaped_the_sandbox}\n")

    # The "foreign-code" taint source: a Python module made writable by ANY
    # user (mode 0666). Loading code from a file another user can write is the
    # supply-chain primitive es-python flags as `foreign-code:<path>`.
    foreign = os.path.join(tempfile.gettempdir(), "eyalsec_demo_foreign.py")
    with open(foreign, "w") as fh:
        fh.write("MESSAGE = 'code loaded from a world-writable file'\n")
    try:
        os.chmod(foreign, 0o666)
    except OSError:
        pass
    return foreign


FOREIGN_MODULE = setup_fixtures()


def db_connect():
    return sqlite3.connect(DB_PATH)


# ===========================================================================
# SOCKET SOURCE
# Flask reads every HTTP request off a socket. Under es-python with the socket
# source armed, request query/body data is tainted the moment it is recv()'d,
# so each route below just steers that tainted data into a different sink.
# ===========================================================================

@app.get("/sqli")
def sqli():
    """SOURCE socket -> SINK sqlite3.execute  =>  SQL injection (OWASP A03).

    Try:  /sqli?name=alice
          /sqli?name=x' OR '1'='1   (dumps every row, secrets included)
    EyalSec reports: tainted SQL statement string at the sqlite3 sink.
    """
    name = request.args.get("name", "alice")
    query = "SELECT id, name, bio, secret FROM users WHERE name = '" + name + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return {"query": query, "rows": rows}


@app.get("/cmd")
def cmd():
    """SOURCE socket -> SINK os.system  =>  OS command injection.

    Try:  /cmd?host=127.0.0.1
          /cmd?host=127.0.0.1; id      (runs `id` after the ping)
    EyalSec reports: tainted command string at the os.system sink.
    """
    host = request.args.get("host", "127.0.0.1")
    cmd_str = "ping -c 1 " + host
    code = os.system(cmd_str)  # <-- SINK
    return {"ran": cmd_str, "exit_code": code}


@app.get("/cmd-subprocess")
def cmd_subprocess():
    """SOURCE socket -> SINK subprocess(shell=True)  =>  command injection.

    Try:  /cmd-subprocess?host=127.0.0.1; whoami
    EyalSec reports: tainted argument at the subprocess sink.
    """
    host = request.args.get("host", "127.0.0.1")
    cmd_str = "ping -c 1 " + host
    out = subprocess.run(cmd_str, shell=True, capture_output=True, text=True)  # <-- SINK
    return {"ran": cmd_str, "stdout": out.stdout, "stderr": out.stderr}


@app.get("/eval")
def eval_():
    """SOURCE socket -> SINK eval  =>  arbitrary code / expression injection.

    Try:  /eval?expr=6*7
          /eval?expr=__import__('os').getuid()
    EyalSec reports: tainted source passed to eval.
    """
    expr = request.args.get("expr", "6*7")
    return {"expr": expr, "result": repr(eval(expr))}  # <-- SINK


@app.get("/exec")
def exec_():
    """SOURCE socket -> SINK exec  =>  arbitrary statement injection.

    Try:  /exec?code=open('/tmp/pwned','w').write('x')
    EyalSec reports: tainted source passed to exec.
    """
    code = request.args.get("code", "x = 1")
    ns = {}
    exec(code, ns)  # <-- SINK
    return {"code": code, "namespace_keys": [k for k in ns if not k.startswith("__")]}


@app.post("/pickle")
def unpickle():
    """SOURCE socket -> SINK pickle.loads  =>  insecure deserialization (RCE).

    Try:  POST raw pickle bytes as the request body.
    EyalSec reports: tainted bytes reaching pickle.loads (deserialization gadget path).
    """
    obj = pickle.loads(request.get_data())  # <-- SINK
    return {"unpickled": repr(obj)}


@app.post("/marshal")
def unmarshal():
    """SOURCE socket -> SINK marshal.loads  =>  deserialization of untrusted data.

    Try:  POST raw marshal bytes as the request body.
    EyalSec reports: tainted bytes reaching marshal.loads.
    """
    obj = marshal.loads(request.get_data())  # <-- SINK
    return {"unmarshalled": repr(obj)}


@app.get("/path")
def path_traversal():
    """SOURCE socket -> SINK open()  =>  path traversal / arbitrary file read.

    Try:  /path?file=notes.txt
          /path?file=../flag.txt              (escapes the sample/ sandbox)
          /path?file=../../../../etc/passwd   (classic, on a shallow install)
    EyalSec reports: tainted path at the file-open sink.
    """
    fname = request.args.get("file", "notes.txt")
    full = SAMPLE_DIR + "/" + fname            # naive join, escapable with ../
    with open(full) as fh:                     # <-- SINK
        return Response(fh.read(), mimetype="text/plain")


@app.get("/ssrf")
def ssrf():
    """SOURCE socket -> SINK urllib/socket connect  =>  server-side request forgery.

    Try:  /ssrf?url=http://example.com
          /ssrf?url=http://169.254.169.254/latest/meta-data/   (cloud metadata)
    EyalSec reports: tainted host/URL at the outbound-connect sink.
    """
    url = request.args.get("url", "http://example.com")
    with urllib.request.urlopen(url, timeout=4) as resp:  # <-- SINK
        body = resp.read(2048)
    return Response(body, mimetype="text/plain")


@app.post("/xxe")
def xxe():
    """SOURCE socket -> SINK XML parser  =>  XML external entity / injection.

    Try:  POST an XML document as the request body.
    EyalSec reports: tainted document reaching the expat/ElementTree parse sink.
    """
    root = ET.fromstring(request.get_data())  # <-- SINK
    return {"root_tag": root.tag, "text": (root.text or "").strip()}


@app.get("/redos")
def redos():
    """SOURCE socket -> SINK re.search  =>  regular-expression DoS / injection.

    Try:  /redos?pattern=(a+)+$&text=aaaaaaaaaaaaaaaaaaaaX
    EyalSec reports: tainted pattern at the regex-compile sink.
    """
    pattern = request.args.get("pattern", "hello")
    text = request.args.get("text", "hello world")
    match = re.search(pattern, text)  # <-- SINK
    return {"pattern": pattern, "matched": bool(match)}


@app.get("/csv")
def csv_injection():
    """SOURCE socket -> SINK csv.writer  =>  CSV / formula injection.

    Try:  /csv?row=name,=cmd|'/C calc'!A0
    EyalSec reports: tainted field at the csv sink (dangerous leading =,+,-,@).
    """
    row = request.args.get("row", "a,b,c")
    sio = io.StringIO()
    csv.writer(sio).writerow(row.split(","))  # <-- SINK
    return Response(sio.getvalue(), mimetype="text/csv")


@app.get("/format")
def format_string():
    """SOURCE socket -> SINK str.format  =>  format-string injection / info leak.

    Try:  /format?template=hi {name}
          /format?template={secrets[api_key]}   (leaks a server secret)
    EyalSec reports: tainted format template at the str.format sink.
    """
    template = request.args.get("template", "hi {name}")
    rendered = template.format(name="guest", secrets=APP_SECRETS)  # <-- SINK
    return {"template": template, "rendered": rendered}


@app.get("/import")
def dynamic_import():
    """SOURCE socket -> SINK importlib.import_module  =>  dynamic import injection.

    Try:  /import?module=math
          /import?module=os     (attacker chooses which module loads)
    EyalSec reports: tainted module name at the import sink.
    """
    import importlib

    module = request.args.get("module", "math")
    mod = importlib.import_module(module)  # <-- SINK
    return {"module": module, "attributes": [a for a in dir(mod) if not a.startswith("_")][:12]}


@app.get("/mkfifo")
def mkfifo():
    """SOURCE socket -> SINK os.mkfifo  =>  path injection into a filesystem call.

    Try:  /mkfifo?name=demo.fifo
          /mkfifo?name=../../tmp/escape.fifo
    EyalSec reports: tainted path at the mkfifo posix sink.
    """
    name = request.args.get("name", "demo.fifo")
    path = os.path.join(tempfile.gettempdir(), name)
    try:
        os.mkfifo(path)  # <-- SINK
        made = True
        os.unlink(path)
    except OSError as exc:
        made, path = False, f"{path} ({exc})"
    return {"path": path, "created": made}


@app.get("/ctypes")
def ctypes_load():
    """SOURCE socket -> SINK ctypes.CDLL  =>  native library / FFI load injection.

    Try:  /ctypes?lib=libc.so.6
    EyalSec reports: tainted library path at the ctypes/FFI sink.
    """
    lib = request.args.get("lib", "libc.so.6")
    handle = ctypes.CDLL(lib)  # <-- SINK
    return {"lib": lib, "loaded": bool(handle._name)}


# ===========================================================================
# NON-SOCKET SOURCES
# These prove the taint engine covers every entry point, not just the network.
# ===========================================================================

@app.get("/source/file")
def source_file():
    """SOURCE file-read -> SINK sqlite3.execute  =>  file-borne SQL injection.

    The query text comes from sample/tainted_input.txt (armed with
    ES2_MAKE_FILE_VULN), NOT from the request - an attacker who can write that
    file owns the query. Edit the file and re-hit this route to see it move.
    EyalSec reports: file source -> SQL sink.
    """
    with open(os.path.join(SAMPLE_DIR, "tainted_input.txt")) as fh:
        value = fh.read().strip()  # <-- tainted at the file source
    query = "SELECT id, name FROM users WHERE name = '" + value + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return {"file_value": value, "query": query, "rows": rows}


@app.get("/source/env")
def source_env():
    """SOURCE env var -> SINK os.system  =>  environment-borne command injection.

    DEMO_INPUT is read from the process environment (armed with
    ES2_MAKE_ENV_VULN) and flows straight into a shell. run-eyalsec.sh sets
    DEMO_INPUT='127.0.0.1; id' so you can watch it fire.
    EyalSec reports: env source -> shell sink.
    """
    value = os.environ.get("DEMO_INPUT", "127.0.0.1")  # <-- tainted at the env source
    cmd_str = "ping -c 1 " + value
    code = os.system(cmd_str)  # <-- SINK
    return {"env_DEMO_INPUT": value, "ran": cmd_str, "exit_code": code}


@app.get("/source/foreign")
def source_foreign():
    """SOURCE foreign-code -> loading a world-writable module.

    Loads a module from a file that ANY user can write (mode 0666). With
    ES2_MAKE_FOREIGN_VULN armed, es-python emits `foreign-code:<path>` at load
    time - the supply-chain / other-user-tampering primitive.
    EyalSec reports: foreign-code:<path>.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("eyalsec_demo_foreign", FOREIGN_MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # <-- foreign-code load
    return {"loaded_from": FOREIGN_MODULE, "message": mod.MESSAGE}


# --------------------------------------------------------------------------- #
# Catalog - single source of truth, also renders the landing page.
# --------------------------------------------------------------------------- #
ENDPOINTS = [
    # group, method, path, example, source, sink, vuln, reports
    ("Socket source (HTTP request data)", "GET", "/sqli", "/sqli?name=x' OR '1'='1",
     "socket", "sqlite3.execute", "SQL injection", "Tainted SQL statement string at the DB sink"),
    ("Socket source (HTTP request data)", "GET", "/cmd", "/cmd?host=127.0.0.1; id",
     "socket", "os.system", "OS command injection", "Tainted command string at the shell sink"),
    ("Socket source (HTTP request data)", "GET", "/cmd-subprocess", "/cmd-subprocess?host=127.0.0.1; whoami",
     "socket", "subprocess(shell=True)", "Command injection", "Tainted argument at the subprocess sink"),
    ("Socket source (HTTP request data)", "GET", "/eval", "/eval?expr=6*7",
     "socket", "eval", "Code injection", "Tainted source passed to eval"),
    ("Socket source (HTTP request data)", "GET", "/exec", "/exec?code=x=1",
     "socket", "exec", "Code injection", "Tainted source passed to exec"),
    ("Socket source (HTTP request data)", "POST", "/pickle", "curl --data-binary @payload.pkl :5000/pickle",
     "socket", "pickle.loads", "Insecure deserialization", "Tainted bytes at the pickle gadget sink"),
    ("Socket source (HTTP request data)", "POST", "/marshal", "curl --data-binary @payload.marshal :5000/marshal",
     "socket", "marshal.loads", "Deserialization", "Tainted bytes at the marshal sink"),
    ("Socket source (HTTP request data)", "GET", "/path", "/path?file=../flag.txt",
     "socket", "open()", "Path traversal", "Tainted path at the file-open sink"),
    ("Socket source (HTTP request data)", "GET", "/ssrf", "/ssrf?url=http://169.254.169.254/",
     "socket", "urllib / socket connect", "SSRF", "Tainted host/URL at the outbound-connect sink"),
    ("Socket source (HTTP request data)", "POST", "/xxe", "curl --data-binary @doc.xml :5000/xxe",
     "socket", "ElementTree.fromstring", "XXE / XML injection", "Tainted document at the XML-parse sink"),
    ("Socket source (HTTP request data)", "GET", "/redos", "/redos?pattern=(a+)+$&text=aaaaaaaaaaX",
     "socket", "re.search", "ReDoS / regex injection", "Tainted pattern at the regex sink"),
    ("Socket source (HTTP request data)", "GET", "/csv", "/csv?row=name,=cmd|'/C calc'!A0",
     "socket", "csv.writer", "CSV / formula injection", "Tainted field at the csv sink"),
    ("Socket source (HTTP request data)", "GET", "/format", "/format?template={secrets[api_key]}",
     "socket", "str.format", "Format-string injection", "Tainted template at the str.format sink"),
    ("Socket source (HTTP request data)", "GET", "/import", "/import?module=os",
     "socket", "importlib.import_module", "Dynamic import injection", "Tainted module name at the import sink"),
    ("Socket source (HTTP request data)", "GET", "/mkfifo", "/mkfifo?name=../escape.fifo",
     "socket", "os.mkfifo", "Path injection (posix)", "Tainted path at the mkfifo sink"),
    ("Socket source (HTTP request data)", "GET", "/ctypes", "/ctypes?lib=libc.so.6",
     "socket", "ctypes.CDLL", "Native/FFI load injection", "Tainted library path at the FFI sink"),

    ("Other taint sources", "GET", "/source/file", "/source/file",
     "file", "sqlite3.execute", "File-borne SQL injection", "File source flows to the SQL sink"),
    ("Other taint sources", "GET", "/source/env", "/source/env",
     "env", "os.system", "Env-borne command injection", "Env source flows to the shell sink"),
    ("Other taint sources", "GET", "/source/foreign", "/source/foreign",
     "foreign-code", "module load", "Supply-chain / tampered code", "foreign-code:<path> at load time"),
]

# CLI demos (documented on the landing page; not HTTP routes).
# group, source, script, command, flow, reports
CLI_DEMOS = [
    ("Process-launch sources (command-line demos)",
     "stdin", "demos/stdin_demo.py",
     "echo '6*7' | es-python demos/stdin_demo.py",
     "stdin source -> eval",
     "stdin source reaching the eval sink"),
    ("Process-launch sources (command-line demos)",
     "input()", "demos/input_demo.py",
     "es-python demos/input_demo.py",
     "input() source -> eval",
     "input() source reaching the eval sink"),
    ("Process-launch sources (command-line demos)",
     "argv", "demos/argv_demo.py",
     "es-python demos/argv_demo.py '127.0.0.1; id'",
     "argv source -> os.system",
     "argv source reaching the shell sink"),

    # These three exist to show what a runtime taint engine can do that no
    # scanner, hook, agent or filter can. See the README section of the same
    # name for why each one is out of reach for the other tool classes.
    ("What only runtime taint can do (command-line demos)",
     "make_vuln, taint 1", "demos/secret_exfil_server.py",
     "es-python demos/secret_exfil_server.py --selftest",
     "tainted secret -> socket.sendall",
     "Secret aborted at socket sendall before one byte reaches the wire, "
     "while ordinary traffic on the same socket keeps flowing"),
    ("What only runtime taint can do (command-line demos)",
     "foreign-writable file", "demos/uncatchable_plugin.py",
     "es-python demos/uncatchable_plugin.py",
     "world-writable file read as data -> exec",
     "foreign-code:<path> - the path is recovered from the taint chain, "
     "even though exec only ever saw a bare string named <string>"),
    ("What only runtime taint can do (command-line demos)",
     "make_vuln, taint 7", "demos/taint_gauntlet.py",
     "es-python demos/taint_gauntlet.py",
     "secret -> 15 transformations -> socket.sendall",
     "The same taint number arrives at the sink after hex, base64, rot13, "
     "UTF-16, memoryview and container round-trips leave nothing to match on"),
]


@app.get("/")
def index():
    groups = {}
    for row in ENDPOINTS:
        groups.setdefault(row[0], []).append(row[1:])
    # Rendered in pure Python (see landing.py) to stay crash-proof under
    # es-python, whose string ABI is incompatible with markupsafe's C speedups.
    return Response(landing.render(groups, CLI_DEMOS), mimetype="text/html")


if __name__ == "__main__":
    # Bind to loopback by default so a careless run is not internet-exposed.
    host = os.environ.get("DEMO_HOST", "127.0.0.1")
    port = int(os.environ.get("DEMO_PORT", "5000"))
    print("=" * 74)
    print(" vulnerable-python  -  INTENTIONALLY INSECURE  -  isolated lab use only")
    print(f" listening on http://{host}:{port}/")
    print("=" * 74)
    app.run(host=host, port=port, debug=False)
