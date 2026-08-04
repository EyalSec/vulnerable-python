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
import importlib
import io
import logging
import marshal
import os
import pickle
import random
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

from flask import Flask, Response, request

import demo_credentials
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


def setup_shadow_module():
    """Plant a file named after a stdlib module, earlier on sys.path than the
    real one. `colorsys` is chosen because nothing in this app (or in flask)
    imports it, so the import in /source/shadow-import is a genuine
    sys.modules miss - which is the only condition under which the detector
    runs at all.
    """
    shadow_dir = os.path.join(tempfile.gettempdir(), "eyalsec_demo_shadow")
    os.makedirs(shadow_dir, exist_ok=True)
    with open(os.path.join(shadow_dir, "colorsys.py"), "w") as fh:
        fh.write(
            "# Not the standard library's colorsys. This is the shadowing file.\n"
            "EYALSEC_SHADOW = True\n"
            "def rgb_to_hls(r, g, b):\n"
            "    return ('attacker-controlled implementation', r, g, b)\n"
        )
    return shadow_dir


FOREIGN_MODULE = setup_fixtures()
SHADOW_DIR = setup_shadow_module()


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
    try:
        with urllib.request.urlopen(url, timeout=4) as resp:  # <-- SINK
            body = resp.read(2048)
    except Exception as exc:
        # The interesting SSRF targets do NOT return a friendly 200: IMDSv2
        # answers a tokenless GET with 401, and a closed internal port refuses
        # the connection outright. Both are still successful forgeries - the
        # request left this server for an address the attacker chose, which is
        # exactly what the sink reports. So report the outcome instead of
        # rendering a 500 that makes a working demo look broken.
        return {"url": url, "reached": False,
                "error": f"{exc.__class__.__name__}: {exc}",
                "note": "the outbound connect still happened - the sink fired "
                        "on the tainted target before any reply came back"}
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

    Try:  /redos?pattern=(a%2B)%2B%24&text=aaaaaaaaaaaaaaaaaaaaaaX

    Percent-encode the "+" and "$". A bare "+" in a query string decodes to a
    space, so `(a+)+$` arrives as `(a ) $` - a pattern that matches nothing
    and backtracks not at all. Add more a's to widen the blowup; each one
    doubles the work: 18 a's takes 0.08s, 20 takes 0.29s, 22 takes 1.1s and
    24 takes 6.2s on the box this was measured on.

    EyalSec reports: tainted pattern at the regex-compile sink, plus `redos`
    once the engine's step counter crosses its threshold. Recorded blind spot:
    the counter increments per opcode dispatch, and a blowup living entirely
    inside a single-width repeat (SRE_OP_REPEAT_ONE) does not dispatch, so it
    can stay under the threshold.
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


# ===========================================================================
# COMPOSITE FINDINGS
# Every route below ends at the SAME sink - a real socket send, or a log
# record. What changes is where the data came from, and the taint SOURCE is
# what decides the label es-python reports:
#
#     hardcoded (12)    -> `credential exfiltration` / `credential logging`
#     weak-random (11)  -> `predictable token`
#     env (5)           -> `secret disclosure`
#
# That is the entire reason those sources exist. A secret sitting in a
# variable is not an incident; a secret leaving the process is. No scanner
# can make that distinction, because it depends on data that only exists at
# runtime, at a call site that looks identical in all three cases.
# ===========================================================================

log = logging.getLogger("vulnerable-python")


def _send_over_socket(payload):
    """Send `payload` over a real socket, to a throwaway loopback listener.

    The listener exists only so there is a genuine `sendall()` on a genuine
    socket for the sink to fire on. The connect target is a hardcoded literal,
    so it is untainted and the `ssrf` discriminator correctly stays quiet.
    """
    if isinstance(payload, str):
        payload = payload.encode()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        client = socket.create_connection(listener.getsockname())
        try:
            client.sendall(payload)  # <-- SINK
        finally:
            client.close()
        conn, _ = listener.accept()
        conn.close()
    finally:
        listener.close()
    return len(payload)


@app.get("/weak-random")
def weak_random_token():
    """SOURCE weak-random -> SINK socket.sendall  =>  predictable token.

    A password-reset token built from the non-cryptographic PRNG, then handed
    to whoever asked for it. Guessable by anyone who can observe or reproduce
    the generator state - and it looks exactly like a good token.

    Try:  /weak-random
    EyalSec reports: `predictable token` at the socket send, origin
    `weak-random:getrandbits`. Arm with --make-weakrandom-vuln (flag/env only;
    there is no dashboard category for it). Instrumenting getrandbits covers
    randrange / randint / choice / shuffle / sample / randbytes too - they all
    route through it. `uuid4` is deliberately NOT covered: it uses os.urandom
    and is a correct choice.
    """
    token = "%032x" % random.getrandbits(128)  # <-- weak-random source
    sent = _send_over_socket("reset-token=" + token)
    return {"token": token, "bytes_sent": sent,
            "note": "generated with random.getrandbits, not secrets.token_hex"}


@app.get("/credential-exfil")
def credential_exfil():
    """SOURCE hardcoded -> SINK socket.sendall  =>  credential exfiltration.

    A hardcoded API key from demo_credentials.py leaves the process over a
    socket. This is the shape of a leaked key in an outbound request, a crash
    report, or a telemetry payload.

    Try:  /credential-exfil
    EyalSec reports: `credential exfiltration` at the socket send, origin
    `hardcoded:demo_credentials.py:<line>`. Arm with --make-secret-vuln.
    NOTE: the scan hooks the builtin compile(), so it runs on the first,
    UNCACHED import of demo_credentials.py. `rm -rf __pycache__` and restart
    to see it fire again - a __pycache__ hit performs no compile at all.
    """
    key = demo_credentials.STRIPE_API_KEY
    sent = _send_over_socket("Authorization: Bearer " + key)
    return {"sent_header": "Authorization: Bearer " + key, "bytes_sent": sent,
            "source_file": "demo_credentials.py"}


@app.get("/credential-logging")
def credential_logging():
    """SOURCE hardcoded -> SINK logging  =>  credential logging.

    The same secret, same taint number, different sink: written to the
    application log, where it is retained, shipped to a log aggregator, and
    read by everyone with log access.

    Try:  /credential-logging
    EyalSec reports: `credential logging`. The logging hook inspects
    record.msg and each of record.args, NOT record.getMessage(), so it sees
    the secret even though this call never formats the string itself.
    """
    token = demo_credentials.GITHUB_TOKEN
    log.warning("provisioning repository with token %s", token)  # <-- SINK
    return {"logged_token": token, "sink": "logging.Logger.handle"}


@app.get("/secret-disclosure")
def secret_disclosure():
    """SOURCE env -> SINK socket.sendall  =>  secret disclosure.

    Environment variables are where deployments keep their secrets, so an env
    value crossing a socket gets its own label rather than a generic send.

    Try:  /secret-disclosure          (uses DEMO_SECRET, else HOME)
    EyalSec reports: `secret disclosure` at the socket send. Arm with
    ES2_MAKE_ENV_VULN. Worth knowing: with the env source armed, es-python
    taints EVERY os.environ value, so on a real app this is a source that
    wants a rule scoping it.
    """
    value = os.environ.get("DEMO_SECRET") or os.environ.get("HOME", "/home/demo")
    sent = _send_over_socket("telemetry-env=" + value)
    return {"value": value, "bytes_sent": sent}


@app.get("/log-forging")
def log_forging():
    """SOURCE socket -> SINK logging  =>  log forging.

    A newline in attacker-controlled data lets them write a whole extra log
    line - forging an audit trail, or hiding in one.

    Try:  /log-forging?user=alice
          /log-forging?user=alice%0A2026-01-01 00:00:00 ADMIN login succeeded
    EyalSec reports: `log forging` when a tainted message or arg carries CR
    or LF.
    """
    user = request.args.get("user", "alice")
    log.info("login for %s", user)  # <-- SINK
    return {"user": user, "sink": "logging.Logger.handle"}


# ===========================================================================
# SOURCES ADDED AFTER THE FIRST RELEASE
# Neither of these is a data source in the ordinary sense. `ssl-unverified`
# reclassifies bytes the socket source already tainted; `shadow-import` is a
# code-provenance finding that taints nothing at all and posts its own event.
# ===========================================================================

@app.get("/source/tls-unverified")
def source_tls_unverified():
    """SOURCE ssl-unverified -> SINK sqlite3.execute  =>  trusted-looking bytes.

    TLS with certificate verification switched off. The connection is still
    encrypted, so every "is it HTTPS?" check passes, but the peer was never
    authenticated - anyone in the path can be the peer. es-python
    reclassifies the decrypted plaintext so the data carries that fact all
    the way to the sink.

    Try:  /source/tls-unverified              (defaults to example.com:443)
          /source/tls-unverified?host=...
    EyalSec reports: origin `ssl-unverified:<host>`, or
    `ssl-unverified:<host> (hostname-unchecked)` when the chain is verified
    but check_hostname is off. This one folds under the SOCKET gate
    (ES2_MAKE_SOCKET_VULN) and is the only new source alive in a socketonly
    build. Needs outbound network; returns a plain error if there is none.
    """
    host = request.args.get("host", "example.com")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # <-- the peer is now unauthenticated
    try:
        with socket.create_connection((host, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                tls.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                banner = tls.recv(256).decode("latin-1")  # <-- ssl-unverified source
    except OSError as exc:
        return {"host": host, "error": f"no outbound TLS from this box ({exc})",
                "note": "the source still exists; this endpoint just needs egress"}
    first = banner.splitlines()[0] if banner.splitlines() else ""
    query = "SELECT id, name FROM users WHERE bio = '" + first + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return {"host": host, "verified": False, "banner": first,
            "query": query, "rows": rows}


@app.get("/source/shadow-import")
def source_shadow_import():
    """SOURCE shadow-import -> an event at import time, no taint involved.

    A file named after a standard-library module, sitting earlier on sys.path
    than the real one. `import colorsys` then loads the attacker's file. This
    is the dependency-confusion / path-shadowing primitive, and it is invisible
    to the foreign-code detector because a file you wrote in your own cwd is
    not writable by *another* user - so it gets its own emitter.

    Try:  /source/shadow-import
    EyalSec reports: `shadow import`, origin `shadow-import:<path>`, taint
    number 13. Folds under the FOREIGN gate (ES2_MAKE_FOREIGN_VULN). It fires
    only on a sys.modules MISS - once per module name per process, capped at
    64 remembered names - so the event appears once even though this route
    re-imports on every hit.
    """
    sys.modules.pop("colorsys", None)
    if SHADOW_DIR not in sys.path:
        sys.path.insert(0, SHADOW_DIR)
    importlib.invalidate_caches()
    mod = importlib.import_module("colorsys")  # <-- shadow-import
    return {"module": "colorsys",
            "loaded_from": getattr(mod, "__file__", "?"),
            "real_stdlib_path": os.path.join(os.path.dirname(os.__file__), "colorsys.py"),
            "is_shadow": getattr(mod, "EYALSEC_SHADOW", False)}


# ===========================================================================
# THIRD-PARTY ADAPTER SINKS
# Non-stdlib libraries are covered by declarative adapters - one row each in
# Lib/_eyalsec_hooks/registry.py, attached lazily through a sys.meta_path
# finder. No vendored fork, no C change. 42 rows ship today; the ones below
# are the ones that need no database server to reach.
#
# Each route degrades to a plain message when the library is not installed,
# so the app runs with flask alone.
# ===========================================================================

def _optional(module_name, pip_name=None):
    """Import an optional demo dependency, or explain how to get it."""
    try:
        return importlib.import_module(module_name), None
    except ImportError:
        return None, (f"{module_name} is not installed in this interpreter - "
                      f"`pip install {pip_name or module_name}` to run this endpoint")


@app.get("/adapter/jinja2")
def adapter_jinja2():
    """SOURCE socket -> SINK jinja2.Environment.from_string  =>  SSTI.

    Server-side template injection: the attacker controls the TEMPLATE, not
    the data substituted into it, so they get the template language's full
    object graph and from there arbitrary execution.

    Try:  /adapter/jinja2?template=hello {{ 7*7 }}
          /adapter/jinja2?template={{ ''.__class__.__mro__[1].__subclasses__() }}
    EyalSec reports: `ssti jinja2`.

    NOTE: this route compiles the template and deliberately does NOT render
    it. The adapter fires at from_string, so compiling is enough to show the
    sink - and rendering would pull in markupsafe's C speedups, whose stock
    PyUnicode layout is incompatible with es-python's string ABI and segfaults
    at render. Any app meant to run under es-python should avoid C-extension
    template engines. Same reason the landing page here is pure Python.
    """
    jinja2, missing = _optional("jinja2")
    if missing:
        return {"skipped": missing}
    template = request.args.get("template", "hello {{ name }}")
    jinja2.Environment().from_string(template)  # <-- SINK (compiled, not rendered)
    return {"template": template, "compiled": True, "rendered": False,
            "why_not_rendered": "markupsafe C speedups segfault under es-python"}


@app.get("/adapter/mark-safe")
def adapter_mark_safe():
    """SOURCE socket -> SINK markupsafe.Markup  =>  XSS via escaping opt-out.

    `Markup(x)` is Jinja's and Flask's "I promise this is safe HTML" wrapper,
    and django.utils.safestring.mark_safe is the same shape. Wrapping
    attacker data in it turns autoescaping off for exactly that value.

    Try:  /adapter/mark-safe?html=<b>hi</b>
          /adapter/mark-safe?html=<img src=x onerror=alert(1)>
    EyalSec reports: `xss mark_safe`.
    """
    markupsafe, missing = _optional("markupsafe")
    if missing:
        return {"skipped": missing}
    html = request.args.get("html", "<b>hi</b>")
    marked = markupsafe.Markup(html)  # <-- SINK
    return {"html": html, "marked_safe": str(marked), "escaped": False}


@app.get("/adapter/yaml")
def adapter_yaml():
    """SOURCE socket -> SINK yaml.load (unsafe loader)  =>  deserialization RCE.

    PyYAML's unsafe loaders construct arbitrary Python objects, so a YAML
    document is a code-execution format unless you use safe_load.

    Try:  /adapter/yaml?doc=a: 1
          /adapter/yaml?doc=!!python/object/apply:os.system ["id"]
    EyalSec reports: `yaml unsafe load`. The adapter's predicate checks the
    loader, so a correct `yaml.safe_load` call is not reported.
    """
    yaml, missing = _optional("yaml", "PyYAML")
    if missing:
        return {"skipped": missing}
    doc = request.args.get("doc", "a: 1")
    loaded = yaml.load(doc, Loader=yaml.UnsafeLoader)  # <-- SINK
    return {"doc": doc, "loaded": repr(loaded)}


@app.get("/adapter/jwt")
def adapter_jwt():
    """SOURCE socket -> SINK jwt.decode  =>  unverified token accepted.

    Decoding a JWT without verifying its signature means the attacker writes
    the claims. `alg: none` is the same bug with a standards-blessed name.

    Try:  /adapter/jwt?token=<any jwt>
    EyalSec reports: `jwt unverified` (predicate: signature verification off)
    or `jwt none alg` (predicate: the call accepts `alg: none`). Two adapter
    rows, same patched method, different predicates.
    """
    jwt, missing = _optional("jwt", "PyJWT")
    if missing:
        return {"skipped": missing}
    token = request.args.get(
        "token",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJndWVzdCIsInJvbGUiOiJhZG1pbiJ9.not-a-real-signature")
    try:
        claims = jwt.decode(token, options={"verify_signature": False})  # <-- SINK
    except Exception as exc:
        return {"token": token, "error": f"{exc.__class__.__name__}: {exc}"}
    return {"token": token, "claims": claims, "signature_verified": False}


@app.get("/adapter/sqlalchemy")
def adapter_sqlalchemy():
    """SOURCE socket -> SINK sqlalchemy.text  =>  SQL injection.

    `text()` is SQLAlchemy's escape hatch out of the query builder. Whatever
    goes in is sent as SQL, so building it by concatenation reintroduces
    exactly the injection the ORM existed to prevent.

    Try:  /adapter/sqlalchemy?name=alice
          /adapter/sqlalchemy?name=x' OR '1'='1
    EyalSec reports: `sql injection`. No database connection is needed - the
    sink is the statement construction, which is where the bug already is.
    """
    sqlalchemy, missing = _optional("sqlalchemy", "SQLAlchemy")
    if missing:
        return {"skipped": missing}
    name = request.args.get("name", "alice")
    stmt = sqlalchemy.text("SELECT * FROM users WHERE name = '" + name + "'")  # <-- SINK
    return {"name": name, "statement": str(stmt)}


@app.get("/adapter/mongo")
def adapter_mongo():
    """SOURCE socket -> SINK pymongo Collection.find  =>  NoSQL injection.

    MongoDB's `$where` takes a JavaScript expression, so attacker data landing
    there is server-side code execution, not just a filter bypass.

    Try:  /adapter/mongo?where=this.name == 'alice'
          /adapter/mongo?where=1 == 1
    EyalSec reports: `nosql mongodb`. The extractor walks the filter document
    (bounded: depth 6, 512 nodes) and yields every $-prefixed key plus the
    VALUE of $where / $expr / $function / $accumulator / $jsonSchema - so it
    reports the dangerous operators, not every user-supplied field.
    No server needed: the adapter fires when find() is called.
    """
    pymongo, missing = _optional("pymongo")
    if missing:
        return {"skipped": missing}
    where = request.args.get("where", "this.name == 'alice'")
    client = pymongo.MongoClient("mongodb://127.0.0.1:27017/",
                                 serverSelectionTimeoutMS=200, connect=False)
    cursor = client.demo.users.find({"$where": where})  # <-- SINK
    try:
        rows = [str(d) for d in cursor]
        note = "a mongod answered"
    except Exception as exc:
        rows, note = [], f"no mongod reachable ({exc.__class__.__name__}) - sink already fired"
    return {"where": where, "filter": {"$where": where}, "rows": rows, "note": note}


@app.get("/adapter/redis")
def adapter_redis():
    """SOURCE socket -> SINK redis Redis.eval  =>  Lua script injection.

    redis-py's ordinary commands are NOT a sink: RESP is length-prefixed, so a
    value cannot escape its field, and storing user data in redis is the
    normal case. `eval` is different - it ships a Lua program to the server.

    Try:  /adapter/redis?script=return 1
          /adapter/redis?script=return redis.call('KEYS', '*')
    EyalSec reports: `nosql redis`. Worth reading as a coverage decision:
    Redis.execute_command was deliberately dropped from the registry because
    it fired on 100% of correct traffic. Only the genuine code-injection sink
    is kept.
    """
    redis, missing = _optional("redis")
    if missing:
        return {"skipped": missing}
    script = request.args.get("script", "return 1")
    client = redis.Redis(host="127.0.0.1", port=6379, socket_connect_timeout=1)
    try:
        result = repr(client.eval(script, 0))  # <-- SINK
        note = "a redis server answered"
    except Exception as exc:
        result, note = None, f"no redis reachable ({exc.__class__.__name__}) - sink already fired"
    return {"script": script, "result": result, "note": note}


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
    # %2B, not a bare "+": in a query string "+" decodes to a space, which turns
    # the catastrophic pattern into the harmless "(a ) $" and the demo into a
    # no-op. Same reason the text below is spelled out rather than repeated.
    ("Socket source (HTTP request data)", "GET", "/redos",
     "/redos?pattern=(a%2B)%2B%24&text=aaaaaaaaaaaaaaaaaaaaaaX",
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
    ("Other taint sources", "GET", "/source/tls-unverified", "/source/tls-unverified",
     "ssl-unverified", "sqlite3.execute", "Unauthenticated TLS peer",
     "ssl-unverified:<host> - encrypted, but the peer was never verified"),
    ("Other taint sources", "GET", "/source/shadow-import", "/source/shadow-import",
     "shadow-import", "module load", "Stdlib shadowing / dependency confusion",
     "shadow-import:<path> - a stdlib name loaded from outside the stdlib"),

    # Same sink every time. The SOURCE picks the label - that is the point.
    ("Composite findings (the source picks the label)", "GET", "/weak-random", "/weak-random",
     "weak-random", "socket.sendall", "Predictable token",
     "predictable token - a guessable secret leaving the process"),
    ("Composite findings (the source picks the label)", "GET", "/credential-exfil", "/credential-exfil",
     "hardcoded", "socket.sendall", "Credential exfiltration",
     "credential exfiltration - a hardcoded key leaving the process"),
    ("Composite findings (the source picks the label)", "GET", "/credential-logging", "/credential-logging",
     "hardcoded", "logging", "Credential logging",
     "credential logging - the same secret, written to the log instead"),
    ("Composite findings (the source picks the label)", "GET", "/secret-disclosure", "/secret-disclosure",
     "env", "socket.sendall", "Secret disclosure",
     "secret disclosure - an environment value leaving the process"),
    ("Composite findings (the source picks the label)", "GET", "/log-forging",
     "/log-forging?user=alice%0AADMIN login ok",
     "socket", "logging", "Log forging", "log forging - CR/LF in a tainted log message or arg"),

    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/jinja2",
     "/adapter/jinja2?template={{ 7*7 }}",
     "socket", "jinja2 Environment.from_string", "SSTI", "ssti jinja2"),
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/mark-safe",
     "/adapter/mark-safe?html=<img src=x onerror=alert(1)>",
     "socket", "markupsafe.Markup", "XSS via escaping opt-out", "xss mark_safe"),
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/yaml",
     "/adapter/yaml?doc=!!python/object/apply:os.system [\"id\"]",
     "socket", "yaml.load (unsafe loader)", "Deserialization RCE", "yaml unsafe load"),
    # No ?token= here on purpose: the route ships a sample JWT claiming
    # role=admin, so the link works as a click. Pass your own to see it decode.
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/jwt",
     "/adapter/jwt",
     "socket", "jwt.decode", "Unverified token accepted", "jwt unverified / jwt none alg"),
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/sqlalchemy",
     "/adapter/sqlalchemy?name=x' OR '1'='1",
     "socket", "sqlalchemy.text", "SQL injection", "sql injection"),
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/mongo",
     "/adapter/mongo?where=1 == 1",
     "socket", "pymongo Collection.find", "NoSQL injection", "nosql mongodb"),
    ("Third-party adapter sinks (optional libraries)", "GET", "/adapter/redis",
     "/adapter/redis?script=return redis.call('KEYS', '*')",
     "socket", "redis Redis.eval", "Lua script injection", "nosql redis"),
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

    ("Database driver sinks (command-line demo)",
     "make_vuln, taint 1", "demos/driver_sinks.py",
     "ES_DEMO_PG_DSN=... es-python demos/driver_sinks.py",
     "tainted value -> psycopg2 / psycopg3 / mysqlclient / mariadb / "
     "oracledb / python-ldap",
     "The injectable statement is reported at each driver's own C or Cython "
     "sink; the bound-parameter form beside it stays silent. Needs a "
     "throwaway database - skips cleanly with nothing configured"),
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
