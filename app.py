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
EyalSec ships `es-python`, a security-instrumented Python runtime that tracks
untrusted data from *sources* to dangerous *sinks* as the program runs.
Detection runs inside the program, not beside it. This app is a live target
for it.

Run this exact file two ways:

  * Under plain python3  -> it is a normal, silently exploitable web app.
                            Nothing is logged. The vulnerability just works.
  * Under es-python      -> every attack that reaches a sink is reported to
                            the EyalSec dashboard (Observe mode), or aborted
                            with a RuntimeError at the sink (Protect mode,
                            ES2_RAISE=1). The code did not change - the
                            runtime did.

The code below is plain standard-library Python. It is byte-for-byte identical
regardless of which runtime runs it - that is the whole point. EyalSec adds
zero source changes to the app it protects.

Each route demonstrates exactly one (taint source -> sink) pair. See the
ENDPOINTS catalog at the bottom, which also drives the landing page at "/".
"""

import builtins
import csv
import ctypes
import importlib
import importlib.machinery
import importlib.util
import io
import logging
import marshal
import mmap
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
import foreign_lab
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
    once the match runs past its work threshold. Known blind spot: a blowup
    that lives entirely inside a single-character repeat (such as `a*`) can
    stay under the threshold.
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
    there is no dashboard category for it). The getrandbits source covers
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
    NOTE: the scan runs when a module is compiled on import, so it runs on the
    first, UNCACHED import of demo_credentials.py. `rm -rf __pycache__` and restart
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
    EyalSec reports: `credential logging`. The logging sink inspects
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
    (ES2_MAKE_SOCKET_VULN). Needs outbound network; returns a plain error if there is none.
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
# THE FOREIGN GATE, IN FULL  (ES2_MAKE_FOREIGN_VULN / --make-foreign-vuln)
#
# Every other source answers "is this data attacker-controlled?". This one
# answers "could a user other than me have written this?" - a question about
# PROVENANCE, which is why it fires on code that no attacker has touched yet
# and on data that no request has carried.
#
# A file is foreign when any of three rules matches it:
#
#     owned by another (non-root) user
#     world-writable
#     group-writable, and the group has another real member
#
# Reads additionally accept a fourth: the immediate parent directory lets
# another user rename or replace the file. The sticky bit is honoured, so an
# ordinary file you own in /tmp is NOT foreign - see /foreign/controls.
#
# Root-owned files are trusted on purpose. Root can replace anything on the
# box, so treating root-owned code as untrusted would report the whole stdlib
# on every import and the signal would be worth nothing.
#
# The gate then drives three distinct behaviours, one per group of routes
# below: code-load events, data taint, and provenance recovery for exec/eval/
# compile of a bare string. `shadow-import` (/source/shadow-import, above)
# folds under this same gate.
#
# ONE EVENT PER PATH PER PROCESS. Each route uses its own fixture file for
# that reason; a repeat hit on the same route is deliberately silent until you
# restart the app.
# ===========================================================================

FOREIGN = foreign_lab.build()

# es-python builtins, with inert stand-ins so this file still runs under
# plain python3. Same trick as demos/es_compat.py, kept local so app.py imports
# nothing from demos/.
_make_vuln = getattr(builtins, "make_vuln", lambda obj, taint=None: obj)
_get_taint = getattr(builtins, "get_taint", lambda obj: None)


def _import_by_name(module_name, directory):
    """Import `module_name` from `directory` through a genuine sys.path entry.

    Forced to be a real import each time (sys.modules purge + invalidated
    caches) so the loader actually opens the file - a cached module performs no
    load and therefore produces no event.
    """
    sys.modules.pop(module_name, None)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    importlib.invalidate_caches()
    return importlib.import_module(module_name)


def _foreign_report(path, **extra):
    """Standard body: the path, the rule-by-rule verdict, and the route's data."""
    body = {"loaded_from": path, "verdict": foreign_lab.verdict(path)}
    body.update(extra)
    return body


# --------------------------------------------------------------------------- #
# 1. CODE LOADS. No taint, no sink, no data flow - the load is the finding.
# --------------------------------------------------------------------------- #

@app.get("/foreign/world-writable")
def foreign_world_writable():
    """SOURCE foreign-code -> `import` of a world-writable module.

    Mode 0666 on a file that is on sys.path. Any local user - a compromised
    service account, a container sharing the volume, a CI runner - can rewrite
    it between two runs of this app, and the next import executes whatever they
    left behind. The file's CONTENT is innocent right now, which is exactly why
    a scanner reading it finds nothing.

    Try:  /foreign/world-writable
    EyalSec reports: `foreign-code:<path>`, origin taint number 3, at the
    import. Under ES2_RAISE the import is aborted with a RuntimeError.
    """
    mod = _import_by_name("eyalsec_ww_module", FOREIGN["import_dir"])
    return _foreign_report(FOREIGN["ww_module"],
                           rule="world-writable (o+w)",
                           message=mod.MESSAGE)


@app.get("/foreign/other-user")
def foreign_other_user():
    """SOURCE foreign-code -> `import` of a module OWNED BY ANOTHER USER.

    The headline case, and the one that needs ./setup-foreign.sh (an
    unprivileged process cannot create a file it does not own). Note the mode
    is 0644: I cannot write this file at all. It is untrusted because the user
    who CAN write it is not me - which is what "supply chain" means once the
    package is already on disk.

    Try:  ./setup-foreign.sh   then   /foreign/other-user
    EyalSec reports: `foreign-code:/var/tmp/eyalsec-foreign/other_user_module.py`,
    with the owning uid and mode in the event body.
    """
    path = foreign_lab.sudo_fixture("other_user_module.py")
    if path is None:
        return foreign_lab.not_set_up("other_user_module.py",
                                      "a Python module owned by a different user")
    mod = _import_by_name("other_user_module", foreign_lab.SUDO_DIR)
    return _foreign_report(path,
                           rule="owned by another user (uid mismatch, not root)",
                           message=mod.MESSAGE)


@app.get("/foreign/group-writable")
def foreign_group_writable():
    """SOURCE foreign-code -> `import` of a GROUP-WRITABLE module.

    Mine, mode 0664, in a group somebody else belongs to. The subtlety is that
    the mode bits alone decide nothing: es-python resolves the group's real
    membership - including users whose PRIMARY group it is, who never appear in
    the group entry - and stays silent when the group is a private one-member
    group, which is what most distributions hand out. So this rule fires on
    genuinely shared write access and not on the default layout of a home
    directory.

    Try:  ./setup-foreign.sh   then   /foreign/group-writable
    EyalSec reports: `foreign-code:<path>` - or nothing at all if the group
    turns out to have exactly one member, which is a correct answer.
    """
    path = FOREIGN.get("group_module") or foreign_lab.sudo_fixture("group_writable_module.py")
    if path is None:
        gid, gname, others = foreign_lab.usable_shared_group()
        return {"status": "no usable group on this box",
                "detail": "every group this process belongs to has exactly one "
                          "real member, so a group-writable file here would be "
                          "private and es-python would correctly say nothing",
                "how": foreign_lab.SETUP_HINT}
    directory, name = os.path.split(path)
    mod = _import_by_name(name[:-3], directory)
    return _foreign_report(path,
                           rule="group-writable and the group has another member",
                           message=mod.MESSAGE)


@app.get("/foreign/pyc")
def foreign_pyc():
    """SOURCE foreign-code -> loading a world-writable `.pyc`, with no source.

    The same attack shipped as bytecode. There is no `.py` beside it, so there
    is nothing for a source scanner, a linter or a code review to read; the
    file is a marshalled code object that runs on import like any other module.
    Provenance is all that is left to judge it by, and provenance is what this
    detector uses.

    Try:  /foreign/pyc
    EyalSec reports: `foreign-code:<path>.pyc` at the bytecode load. Loads
    with no source on disk are covered as well as ordinary ones.
    """
    import py_compile

    py_compile.compile(FOREIGN["ww_pyc_source"], cfile=FOREIGN["ww_pyc"],
                       doraise=True)
    os.chmod(FOREIGN["ww_pyc"], 0o666)

    name = "eyalsec_ww_bytecode"
    sys.modules.pop(name, None)
    loader = importlib.machinery.SourcelessFileLoader(name, FOREIGN["ww_pyc"])
    spec = importlib.util.spec_from_file_location(name, FOREIGN["ww_pyc"],
                                                  loader=loader)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # <-- foreign-code load, bytecode only
    return _foreign_report(FOREIGN["ww_pyc"],
                           rule="world-writable .pyc, no source on disk",
                           message=mod.MESSAGE)


@app.get("/foreign/compile")
def foreign_compile():
    """SOURCE foreign-code -> `compile(src, path, "exec")` with a foreign path.

    An app that implements its own plugin loading does not call `import`; it
    reads a file and compiles it. es-python checks the FILENAME argument of
    the builtin `compile()` for exactly that, so a hand-rolled loader is
    covered the same way importlib is.

    Try:  /foreign/compile
    EyalSec reports: `compile`, origin `foreign-code:<path>`. The source string
    is itself tainted (it was read from a foreign file), so it would separately
    qualify as an untrusted code load - but the path-based event has already
    claimed this load, so there is no duplicate `compile (untrusted code)`
    event. You will still see the ordinary tainted-value event for the string
    reaching compile, which is a different finding about a different fact.
    """
    path = FOREIGN["ww_compile"]
    with open(path) as fh:
        src = fh.read()
    code = compile(src, path, "exec")  # <-- SINK: foreign path at compile()
    ns = {}
    exec(code, ns)
    return _foreign_report(path,
                           rule="world-writable file named as compile()'s filename",
                           compiled_names=[k for k in ns if not k.startswith("__")],
                           value=ns.get("COMPILED"))


@app.get("/foreign/exec-file")
def foreign_exec_file():
    """SOURCE foreign-code -> `exec(open(path).read())`, filename `<string>`.

    The load with no filename at all. The bytes were read as DATA, so by the
    time they reach exec the interpreter is looking at an anonymous string and
    every path-based control - audit hooks, allowlists, EDR file rules, a SAST
    pass over the repo - has nothing to key on. es-python follows the string's
    taint chain back to the read that produced it and reports the original
    path, so this lands as the same `foreign-code:<path>` event that a direct
    import would have produced.

    Try:  /foreign/exec-file
          /foreign/exec-file?sink=eval
          /foreign/exec-file?sink=compile
    EyalSec reports: `exec (foreign code)` / `eval (foreign code)` /
    `compile (foreign code)`. This raise is SYNCHRONOUS under ES2_RAISE - the
    source is never compiled and never runs, unlike the sink-side raises
    elsewhere in this app, which fire at the sink after the fact.
    See demos/uncatchable_plugin.py for the same idea as a CLI demo.
    """
    sink = request.args.get("sink", "exec")
    path = FOREIGN["ww_source"]
    with open(path) as fh:
        src = fh.read()  # <-- tainted: the file is foreign
    ns = {}
    if sink == "eval":
        result = eval(src.split("=", 1)[1].strip())  # <-- SINK
    elif sink == "compile":
        result = repr(compile(src, "<string>", "exec"))  # <-- SINK
    else:
        exec(src, ns)  # <-- SINK
        result = ns.get("RESULT")
    return _foreign_report(path, sink=sink, filename_seen_by_python="<string>",
                           result=result,
                           note="the path in the event was recovered from the "
                                "taint chain, not from the call")


# --------------------------------------------------------------------------- #
# 2. DATA TAINT. The file gate taints EVERY file read on the box; the foreign
#    gate taints only the reads another user could have controlled - which is
#    what makes it something you can leave armed in production.
# --------------------------------------------------------------------------- #

@app.get("/foreign/data/read")
def foreign_data_read():
    """SOURCE foreign file read -> SINK sqlite3.execute  =>  SQL injection.

    Same shape as /source/file, one gate down: this fires with
    ES2_MAKE_FILE_VULN switched OFF, because the file is world-writable and so
    its contents are attacker-controlled by definition. Arm only
    ES2_MAKE_FOREIGN_VULN and compare the two routes.

    Try:  /foreign/data/read
    EyalSec reports: a tainted SQL statement at the sqlite3 sink, origin the
    file's path.
    """
    path = FOREIGN["ww_sql"]
    with open(path) as fh:
        value = fh.read().strip()  # <-- tainted by the foreign gate alone
    query = "SELECT id, name FROM users WHERE name = '" + value + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return _foreign_report(path, value=value, query=query, rows=rows)


@app.get("/foreign/data/readlines")
def foreign_data_readlines():
    """SOURCE foreign file read -> SINK os.system  =>  command injection.

    `readlines()` rather than `read()`. It is a separate read path with its
    own taint marking and its own origin reporting, so it gets its own route: a
    per-line read used to reach the sink with the origin missing, and the
    dashboard would attribute the finding to the line of code instead of to the
    file.

    Try:  /foreign/data/readlines
    EyalSec reports: a tainted command string at the shell sink, origin the
    hosts file.
    """
    path = FOREIGN["ww_lines"]
    with open(path) as fh:
        lines = fh.readlines()  # <-- each line tainted
    target = lines[-1].strip() if lines else "127.0.0.1"
    cmd = "ping -c 1 " + target
    code = os.system(cmd)  # <-- SINK
    return _foreign_report(path, lines=[l.rstrip("\n") for l in lines],
                           ran=cmd, exit_code=code)


@app.get("/foreign/data/os-read")
def foreign_data_os_read():
    """SOURCE foreign fd -> SINK subprocess(shell=True)  =>  command injection.

    Raw `os.open` + `os.read`, with no file object anywhere. The verdict is
    made on the file DESCRIPTOR (`fstat`), which is why this still works when
    the code never touches a path after the open.

    Try:  /foreign/data/os-read
    EyalSec reports: a tainted argument at the subprocess sink.
    """
    path = FOREIGN["ww_cmd"]
    fd = os.open(path, os.O_RDONLY)
    try:
        raw = os.read(fd, 4096)  # <-- tainted: the fd is foreign
    finally:
        os.close(fd)
    target = raw.decode().strip()
    out = subprocess.run("ping -c 1 " + target, shell=True,  # <-- SINK
                         capture_output=True, text=True)
    return _foreign_report(path, target=target, exit_code=out.returncode,
                           stdout=out.stdout[-400:])


@app.get("/foreign/data/mmap")
def foreign_data_mmap():
    """SOURCE foreign mmap -> SINK sqlite3.execute  =>  SQL injection.

    A memory-mapped foreign file. There is no `read()` call at all - the bytes
    arrive by page fault - so a tool watching read calls would miss this
    entirely. es-python judges the file when it is mapped and taints every
    slice taken from it.

    Try:  /foreign/data/mmap
    EyalSec reports: a tainted SQL statement at the sqlite3 sink.
    """
    path = FOREIGN["ww_mmap"]
    with open(path, "rb") as fh:
        with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            value = mm[:].decode().strip()  # <-- tainted through the mapping
    query = "SELECT id, name FROM users WHERE name = '" + value + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return _foreign_report(path, value=value, query=query, rows=rows)


@app.get("/foreign/data/parent-dir")
def foreign_data_parent_dir():
    """SOURCE foreign-by-parent-directory -> SINK sqlite3.execute.

    The file is mine and mode 0600 - nobody else can open it. It is still
    untrusted, because its directory is world-writable and NOT sticky, so any
    user can rename it away and drop their own file in its place. Permissions
    on a file mean nothing if somebody else controls the name that points at
    it.

    This rule applies to READS only. A code load looks at the file's own bits,
    so importing this same file produces no event - the two answers differ on
    purpose, and /foreign/controls shows the pair.

    Try:  /foreign/data/parent-dir
    EyalSec reports: a tainted SQL statement, origin the swappable file.
    """
    path = FOREIGN["swappable_data"]
    with open(path) as fh:
        value = fh.read().strip()  # <-- tainted via the parent-directory rule
    query = "SELECT id, name FROM users WHERE name = '" + value + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return _foreign_report(path, value=value, query=query, rows=rows)


@app.get("/foreign/data/other-user")
def foreign_data_other_user():
    """SOURCE file owned by another user -> SINK sqlite3.execute.

    Config files, drop directories, spool files and shared caches are read by
    processes that never wrote them. A file owned by another account is the
    plainest form of that, and needs no permission mistake to be dangerous.

    Try:  ./setup-foreign.sh   then   /foreign/data/other-user
    EyalSec reports: a tainted SQL statement, origin the other user's file.
    """
    path = foreign_lab.sudo_fixture("other_user_query.txt")
    if path is None:
        return foreign_lab.not_set_up("other_user_query.txt",
                                      "a data file owned by a different user")
    with open(path) as fh:
        value = fh.read().strip()  # <-- tainted: owner is not me
    query = "SELECT id, name FROM users WHERE name = '" + value + "'"
    db = db_connect()
    try:
        rows = db.execute(query).fetchall()  # <-- SINK
    finally:
        db.close()
    return _foreign_report(path, value=value, query=query, rows=rows)


@app.get("/foreign/data/fifo")
def foreign_data_fifo():
    """SOURCE foreign FIFO -> SINK os.system  =>  command injection.

    A named pipe created by another user. There is no file content to inspect,
    no hash to pin, no mode bit that helps - the bytes only exist while they
    are in flight, and the only durable fact about them is who made the pipe.
    es-python judges non-regular files (FIFOs, character devices, pipes) on
    exactly that.

    The route opens the FIFO read-write so it can write and read back in one
    request; without that, opening a FIFO for reading blocks until a writer
    shows up.

    Try:  ./setup-foreign.sh   then   /foreign/data/fifo
    EyalSec reports: a tainted command string at the shell sink.
    """
    path = foreign_lab.sudo_fixture("other_user.fifo")
    if path is None:
        return foreign_lab.not_set_up("other_user.fifo",
                                      "a FIFO created by a different user")
    fd = os.open(path, os.O_RDWR)
    try:
        os.write(fd, b"127.0.0.1; id\n")
        raw = os.read(fd, 4096)  # <-- tainted: the FIFO's creator is not me
    finally:
        os.close(fd)
    target = raw.decode().strip()
    cmd = "ping -c 1 " + target
    code = os.system(cmd)  # <-- SINK
    return _foreign_report(path, target=target, ran=cmd, exit_code=code)


# --------------------------------------------------------------------------- #
# 3. UNTRUSTED CODE LOADS. exec/eval/compile of a bare string, where the
#    filename is `<string>` and provenance can only come from the taint chain.
#    A foreign-writable origin reports as `foreign-code:`; every other source
#    reports as `untrusted-code:<origin>`, so one rule covers the whole family.
# --------------------------------------------------------------------------- #

@app.get("/foreign/untrusted/socket")
def foreign_untrusted_socket():
    """SOURCE socket -> SINK exec  =>  `untrusted-code:socket:<ip>:<port>`.

    HTTP request data compiled and run. /exec already shows this as a code
    injection at the exec sink; what the foreign gate adds is a second, more
    specific finding that names the ORIGIN of the code - the connection it
    arrived on - rather than just the sink it reached.

    Try:  /foreign/untrusted/socket?code=x=6*7
          /foreign/untrusted/socket?code=6*7&sink=eval
          /foreign/untrusted/socket?code=__import__('os').system('id')
    EyalSec reports: `exec (untrusted code)` / `eval (untrusted code)` /
    `compile (untrusted code)`. The origin names the read the bytes came from:
    `untrusted-code:socket:<local>-<peer>` for code read straight off a socket,
    and `untrusted-code:fd:<n>` here, because werkzeug parses the request
    through a file wrapper over the connection rather than calling recv itself.
    Blocked synchronously under ES2_RAISE - the string is never compiled.
    """
    code_str = request.args.get("code", "x = 6 * 7")
    sink = request.args.get("sink", "exec")
    ns = {}
    if sink == "eval":
        result = eval(code_str)                            # <-- SINK
    elif sink == "compile":
        result = repr(compile(code_str, "<string>", "exec"))  # <-- SINK
    else:
        exec(code_str, ns)                                 # <-- SINK
        result = {k: repr(v) for k, v in ns.items() if not k.startswith("__")}
    return {"code": code_str, "sink": sink, "result": result,
            "origin_reported": "untrusted-code:socket:<peer ip>:<port>"}


@app.get("/foreign/untrusted/env")
def foreign_untrusted_env():
    """SOURCE env var -> SINK exec  =>  `untrusted-code:<env value>`.

    The same detector, a different origin: code taken from the environment. In
    a container the environment is set by whoever wrote the manifest, which is
    frequently not whoever wrote the app.

    Try:  DEMO_CODE='x = 1' in the environment, then /foreign/untrusted/env
          (run-eyalsec.sh sets one for you)
    EyalSec reports: `exec (untrusted code)`, origin `untrusted-code:env` - the
    origin names the SOURCE, not the value, so a rule can be written against it
    without knowing what the attacker sent. Arm ES2_MAKE_ENV_VULN as well as
    ES2_MAKE_FOREIGN_VULN: the untrusted-code detector reports the load, and
    the env gate is what makes the string untrusted in the first place.
    """
    code_str = os.environ.get("DEMO_CODE", "x = 6 * 7")  # <-- env source
    ns = {}
    exec(code_str, ns)  # <-- SINK
    return {"env_DEMO_CODE": code_str,
            "result": {k: repr(v) for k, v in ns.items() if not k.startswith("__")},
            "note": "needs ES2_MAKE_ENV_VULN too - foreign mode reports the "
                    "load, the env gate is what makes the string untrusted"}


@app.get("/foreign/untrusted/tainted")
def foreign_untrusted_tainted():
    """SOURCE make_vuln -> SINK exec  =>  a source-scoped untrusted code load.

    `make_vuln(value, n)` tags a value with taint number n, which is how you
    mark something es-python has no way to know is untrusted - a field
    out of your own database, a message off a queue, a template from a CMS. The
    code load is reported with that number, so a dashboard rule can be scoped
    to this one source and raise on it while everything else stays in observe
    mode.

    Try:  /foreign/untrusted/tainted
          /foreign/untrusted/tainted?n=7&code=6*7
    EyalSec reports: `exec (untrusted code)`, origin `untrusted-code:make_vuln`,
    carrying taint number n. Inert under plain python3, where make_vuln is a
    no-op stand-in.
    """
    n = int(request.args.get("n", "7"))
    code_str = _make_vuln(request.args.get("code", "x = 6 * 7"), n)
    ns = {}
    exec(code_str, ns)  # <-- SINK
    return {"code": code_str, "taint_number": _get_taint(code_str),
            "result": {k: repr(v) for k, v in ns.items() if not k.startswith("__")}}


# --------------------------------------------------------------------------- #
# 4. THE SILENT HALF. A detector is only worth having if it also knows when to
#    say nothing, and every case below is one somebody would reasonably expect
#    to fire.
# --------------------------------------------------------------------------- #

@app.get("/foreign/controls")
def foreign_controls():
    """Six loads and reads that must produce NO foreign-code event.

    Fully silent - nothing at all is reported:

      root-owned module      root can replace anything anyway; flagging root
                             would report the entire standard library.
      my own private file    the ordinary case - mode 0600, my uid.
      my own private module  the same file, imported instead of read.
      sticky-dir file        mine, in /tmp: world-writable but STICKY, so no
                             other user may rename it. This one is the reason
                             the parent-directory rule has a sticky-bit
                             exception at all; without it every temp file on
                             the box reads as foreign.

    No foreign-code event, but not silent either - and the difference is the
    interesting part:

      allowlisted module     world-writable, but under a prefix the operator
                             put in ES2_FOREIGN_CODE_ALLOW. The allowlist
                             exempts the CODE LOAD; the file is still
                             world-writable, so importlib's read of its source
                             is still tainted and the ordinary compile-sink
                             event still fires. Unset the variable and the
                             foreign-code event comes back on top.
      swappable module       mode 0600 in a world-writable directory. Loading
                             it as CODE is not reported: the parent-directory
                             rule applies to READS. The read importlib does to
                             get the source is a read, so that produces its own
                             tainted-value event - which is exactly the fact
                             /foreign/data/parent-dir demonstrates.

    Try:  /foreign/controls
    EyalSec reports: no `foreign-code:` origin from any of the six. Any event
    with one is a false positive worth telling us about.
    """
    results = []

    root_mod = foreign_lab.sudo_fixture("root_owned_module.py")
    if root_mod:
        _import_by_name("root_owned_module", foreign_lab.SUDO_DIR)
        results.append({"case": "root-owned module", "path": root_mod,
                        "verdict": foreign_lab.verdict(root_mod)})
    else:
        results.append({"case": "root-owned module", "status": "not set up",
                        "how": foreign_lab.SETUP_HINT})

    with open(FOREIGN["private_data"]) as fh:
        fh.read()
    results.append({"case": "my own private file (0600 in a 0700 dir)",
                    "path": FOREIGN["private_data"],
                    "verdict": foreign_lab.verdict(FOREIGN["private_data"])})

    _import_by_name("eyalsec_private_mod", FOREIGN["shield_dir"])
    results.append({"case": "my own private module",
                    "path": FOREIGN["private_module"],
                    "verdict": foreign_lab.verdict(FOREIGN["private_module"])})

    with open(FOREIGN["sticky_data"]) as fh:
        fh.read()
    results.append({"case": "my file in a sticky world-writable dir (/tmp)",
                    "path": FOREIGN["sticky_data"],
                    "verdict": foreign_lab.verdict(FOREIGN["sticky_data"])})

    _import_by_name("eyalsec_trusted_mod", FOREIGN["allow_dir"])
    results.append({"case": "world-writable but allowlisted",
                    "path": FOREIGN["allowlisted_module"],
                    "allowlist": os.environ.get("ES2_FOREIGN_CODE_ALLOW", "(unset)"),
                    "silent_only_if": f"ES2_FOREIGN_CODE_ALLOW covers "
                                      f"{FOREIGN['allow_dir']}",
                    "verdict": foreign_lab.verdict(FOREIGN["allowlisted_module"])})

    _import_by_name("eyalsec_swappable_mod", FOREIGN["open_dir"])
    results.append({"case": "0600 module in a world-writable dir (code load, "
                            "not a read)",
                    "path": FOREIGN["swappable_module"],
                    "verdict": foreign_lab.verdict(FOREIGN["swappable_module"])})

    return {"expected_foreign_code_events": 0,
            "note": "the last two entries still produce an ordinary "
                    "tainted-value event for the source read importlib "
                    "performs - see the docstring; what none of them produce "
                    "is a foreign-code load event",
            "controls": results}


@app.get("/foreign/explain")
def foreign_explain():
    """Not a vulnerability - the predicate, run against any path you name.

    Shows which of the four rules matches, and the two verdicts (code loads
    consult the file's own bits; reads also accept the parent directory).

    Try:  /foreign/explain?path=/etc/passwd
          /foreign/explain?path=/tmp
          /foreign/explain?path=<any file on the box>
    """
    path = request.args.get("path", FOREIGN["ww_module"])
    return foreign_lab.verdict(path)


# ===========================================================================
# THIRD-PARTY LIBRARY SINKS
# es-python also covers popular non-stdlib libraries; 42 library sinks ship
# today. The ones below are the ones that need no database server to reach.
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
    it. The sink fires at from_string, so compiling is enough to show it - and
    rendering would pull in markupsafe's compiled speedups extension, which is
    not supported under es-python. Same reason the landing page here is pure
    Python.
    """
    jinja2, missing = _optional("jinja2")
    if missing:
        return {"skipped": missing}
    template = request.args.get("template", "hello {{ name }}")
    jinja2.Environment().from_string(template)  # <-- SINK (compiled, not rendered)
    return {"template": template, "compiled": True, "rendered": False,
            "why_not_rendered": "markupsafe compiled speedups are not supported under es-python"}


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
    EyalSec reports: `yaml unsafe load`. The sink's predicate checks the
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
    or `jwt none alg` (predicate: the call accepts `alg: none`). Two checks
    on the same call, different predicates.
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
    No server needed: the sink fires when find() is called.
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
    Redis.execute_command is deliberately not a sink, because
    it would fire on 100% of correct traffic. Only the genuine code-injection sink
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

    # The foreign gate in full. Three behaviours - code-load events, data
    # taint, provenance recovery for exec/eval/compile - plus the cases that
    # must stay silent. See the section header above the routes.
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/world-writable", "/foreign/world-writable",
     "foreign-code", "import", "Any local user can rewrite the module",
     "foreign-code:<path> at the import"),
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/other-user", "/foreign/other-user",
     "foreign-code", "import", "Module owned by another user (needs ./setup-foreign.sh)",
     "foreign-code:<path> - untrusted because of WHO owns it, not the mode bits"),
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/group-writable", "/foreign/group-writable",
     "foreign-code", "import", "Group-writable by a shared group (needs ./setup-foreign.sh)",
     "foreign-code:<path> - real group membership is resolved, not just the g+w bit"),
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/pyc", "/foreign/pyc",
     "foreign-code", ".pyc load", "Bytecode with no source to scan",
     "foreign-code:<path>.pyc at the sourceless load"),
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/compile", "/foreign/compile",
     "foreign-code", "compile()", "Hand-rolled plugin loader",
     "foreign-code:<path> on compile()'s filename argument"),
    ("Foreign gate: code loads (ES2_MAKE_FOREIGN_VULN)", "GET",
     "/foreign/exec-file", "/foreign/exec-file?sink=exec",
     "foreign-code", "exec / eval / compile", "Code load with no filename at all",
     "exec|eval|compile (foreign code) - the path comes from the taint chain, "
     "and the raise is synchronous: the source never runs"),

    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/read", "/foreign/data/read",
     "foreign file", "sqlite3.execute", "SQL injection with the FILE gate off",
     "Tainted statement - the foreign gate taints only reads another user could control"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/readlines", "/foreign/data/readlines",
     "foreign file", "os.system", "Per-line read reaching a shell",
     "Tainted command string, origin the file (not the line of code)"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/os-read", "/foreign/data/os-read",
     "foreign fd", "subprocess(shell=True)", "Raw fd read, no file object",
     "Tainted argument - the verdict is made on the file descriptor"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/mmap", "/foreign/data/mmap",
     "foreign mmap", "sqlite3.execute", "Bytes that arrive by page fault",
     "Tainted statement - no read() call happens at all"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/parent-dir", "/foreign/data/parent-dir",
     "foreign parent dir", "sqlite3.execute", "0600 file in a world-writable directory",
     "Tainted statement - permissions on a file mean nothing if someone else "
     "controls the name that points at it"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/other-user", "/foreign/data/other-user",
     "other user's file", "sqlite3.execute", "Shared config / spool file (needs ./setup-foreign.sh)",
     "Tainted statement, origin the other user's file"),
    ("Foreign gate: untrusted data from a foreign file", "GET",
     "/foreign/data/fifo", "/foreign/data/fifo",
     "foreign FIFO", "os.system", "Named pipe made by another user (needs ./setup-foreign.sh)",
     "Tainted command string - nothing but the creator's uid to judge it by"),

    ("Foreign gate: untrusted code from any source", "GET",
     "/foreign/untrusted/socket", "/foreign/untrusted/socket?code=x=6*7",
     "socket", "exec / eval / compile", "Request data run as code",
     "untrusted-code:socket:<local>-<peer> - names the read the code arrived "
     "on, not just the sink it reached"),
    ("Foreign gate: untrusted code from any source", "GET",
     "/foreign/untrusted/env", "/foreign/untrusted/env",
     "env", "exec", "Environment-supplied code",
     "untrusted-code:env - needs ES2_MAKE_ENV_VULN as well"),
    ("Foreign gate: untrusted code from any source", "GET",
     "/foreign/untrusted/tainted", "/foreign/untrusted/tainted?n=7",
     "make_vuln, taint 7", "exec", "Application-marked untrusted code",
     "untrusted-code:make_vuln carrying taint number 7, so a rule can be "
     "scoped to this one source"),

    ("Foreign gate: what must stay silent", "GET",
     "/foreign/controls", "/foreign/controls",
     "-", "-", "Root-owned, private, sticky-dir, allowlisted, swappable-module",
     "No foreign-code event from any of the six. Four are silent outright; the "
     "allowlisted and swappable ones still taint the source READ, which is the "
     "distinction the route is there to show"),
    ("Foreign gate: what must stay silent", "GET",
     "/foreign/explain", "/foreign/explain?path=/etc/passwd",
     "-", "-", "Not a vulnerability - the predicate itself",
     "Which of the four rules matches a path you name, and both verdicts"),

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
     "foreign-writable main script", "demos/foreign_main_script.py",
     "ES2_MAKE_FOREIGN_VULN=1 es-python demos/foreign_main_script.py",
     "world-writable script -> run script",
     "foreign-code:<path> for the SCRIPT ITSELF, emitted before its first "
     "statement runs - there is no import to hook and no application code yet "
     "that could check anything"),
    ("What only runtime taint can do (command-line demos)",
     "stdin, argv, env, make_vuln", "demos/untrusted_code_demo.py",
     "echo 'x=6*7' | ES2_MAKE_STDIN_VULN=1 ES2_MAKE_FOREIGN_VULN=1 "
     "es-python demos/untrusted_code_demo.py 'y=1+1'",
     "any tainted string -> exec / eval / compile",
     "untrusted-code:<origin> - one rule covers every route into exec, and an "
     "untainted literal in the same file is deliberately not reported"),
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
     "The injectable statement is reported at each driver's own statement "
     "sink; the bound-parameter form beside it stays silent. Needs a "
     "throwaway database - skips cleanly with nothing configured"),
]


@app.get("/")
def index():
    groups = {}
    for row in ENDPOINTS:
        groups.setdefault(row[0], []).append(row[1:])
    # Rendered in pure Python (see landing.py): markupsafe's compiled speedups
    # are not supported under es-python.
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
