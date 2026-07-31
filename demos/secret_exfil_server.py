#!/usr/bin/env python3.13
"""SOURCE make_vuln(taint 1) -> SINK socket.sendall  =>  secret exfiltration, BLOCKED.

  ############################################################################
  #  WARNING: part of an intentionally vulnerable demo app. Isolated lab      #
  #  machines only.                                                           #
  ############################################################################

The demo
--------
A plain TCP echo server holds one secret:

    SECRET = make_vuln(b"top_important_secret", 1)

`make_vuln(obj, 1)` marks that object as tainted and stamps it with **user
taint number 1**. The number is the handle you write policy against: it names
*this specific value*, not a category of traffic.

The server echoes whatever a client sends. But if the client sends the magic
word `data`, the server tries to hand back the secret. That is the exfiltration
path - and it is the one thing this server must never do.

With a matching raise rule armed, es-python aborts `sendall` **before a single
byte reaches the wire**, and the application sees a `RuntimeError`:

    RuntimeError: EyalSec: untrusted data from make_vuln reached sink socket sendall

The two properties that matter
------------------------------
1. **The block is synchronous.** The raise happens before the send loop, not
   after it. A sink that reported *after* sending would be a notification, not
   a control - the secret would already be gone, and the app's own
   `except RuntimeError` would hide the fact. Here the receiver gets nothing.

2. **The rule is scoped to the secret, not to the socket.** The rule matches
   taint number 1, so ordinary echo traffic flows normally and only the secret
   is stopped. A server that blocked every tainted `sendall` would just be a
   broken server; this one keeps working and cannot leak.

Arming the block
----------------
Raising is driven by the machine config your dashboard pushes, so create a rule
on the machine running this demo:

    Source: 1   (the custom taint number, i.e. make_vuln(..., 1))
    Event:  sendall
    Mode:   Raise

Without that rule the demo runs in Observe mode: the secret IS sent, and the
event is reported to the dashboard instead. Both outcomes are worth showing -
Observe proves the detection, Protect proves the control.

Run it
------
    # one-command demo: starts the server, drives it, prints the outcome
    python3 demos/secret_exfil_server.py --selftest

    # or as a real server, then talk to it from another terminal
    python3 demos/secret_exfil_server.py
    printf 'hello\\n' | nc 127.0.0.1 1024      # echoed back
    printf 'data\\n'  | nc 127.0.0.1 1024      # the exfiltration attempt

Under stock CPython the secret is handed over every time, with no record.
"""
import os
import socket
import sys
import threading

from es_compat import ES_PYTHON, banner, check_vuln, get_taint, make_vuln

# Deliberately NOT named DEMO_HOST / DEMO_PORT: app.py already reads those for
# the web app, and exporting them for it would silently move this server.
HOST = os.environ.get("EXFIL_HOST", "127.0.0.1")
PORT = int(os.environ.get("EXFIL_PORT", "1024"))
BUFFER_SIZE = 1024

# The secret this server must never let out. Taint number 1 is what the
# dashboard rule matches on.
SECRET = make_vuln(b"top_important_secret", 1)


def handle_client(client_socket, address):
    with client_socket:
        print(f"[server] connected by {address}")
        while True:
            data = client_socket.recv(BUFFER_SIZE).strip()
            if not data:
                break

            # Deliberately NOT `print(data)`. Under es-python the received bytes
            # are socket-tainted, and stdout is a sink too - printing them would
            # trip an unscoped raise rule before we ever reach the interesting
            # part. Report the length, which is an ordinary untainted int.
            print(f"[server] received {len(data)} bytes")

            try:
                if data == b"data":
                    # <-- SINK. The exfiltration attempt. Under an armed raise
                    #     rule this call raises and sends nothing at all.
                    client_socket.sendall(b"data is: " + SECRET)
                    print("[server] secret was SENT (no raise rule armed)")
                else:
                    client_socket.sendall(data)
            except RuntimeError as exc:
                # es-python aborted the send. Nothing reached the wire.
                print(f"[server] BLOCKED: {exc}")
                try:
                    client_socket.sendall(b"refused\n")
                except RuntimeError:
                    pass


def serve_forever(server_socket):
    while True:
        try:
            client_socket, address = server_socket.accept()
        except OSError:
            # The listening socket was closed under us (selftest shutdown).
            return
        handle_client(client_socket, address)


def serve_once(server_socket):
    """Accept exactly one client, serve it, and return. Used by --selftest.

    Serving one connection and returning is what lets the selftest join this
    thread before closing the listening socket. Closing a socket that another
    thread is blocked in accept() on is how you get 'Bad file descriptor' and,
    at interpreter shutdown with a daemon thread mid-write, an abort.
    """
    try:
        client_socket, address = server_socket.accept()
    except OSError:
        return
    handle_client(client_socket, address)


def make_server_socket(port=PORT):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, port))
    server_socket.listen()
    return server_socket


def selftest():
    """Start the server in a thread, drive both paths, report what happened."""
    banner("secret exfiltration -> socket.sendall")
    print(f" secret       : {len(SECRET)} bytes (not printed - stdout is a sink too)")
    print(f" tainted      : {check_vuln(SECRET)}")
    print(f" taint number : {get_taint(SECRET)}")
    if not ES_PYTHON:
        print(" NOTE: no taint engine here - the secret will simply be handed over.")
    print()

    # Port 0 lets the kernel pick a free port, so a selftest never collides with
    # a real server run or with a second selftest.
    echoed = leaked = b""
    server_socket = make_server_socket(port=0)
    server_thread = threading.Thread(target=serve_once, args=(server_socket,))
    server_thread.start()
    try:
        with socket.create_connection(server_socket.getsockname(), timeout=5) as client:
            client.settimeout(2)

            # 1) ordinary traffic: must keep working
            client.sendall(b"hello\n")
            try:
                echoed = client.recv(BUFFER_SIZE)
            except OSError:
                pass

            # 2) the exfiltration attempt
            client.sendall(b"data\n")
            try:
                leaked = client.recv(BUFFER_SIZE)
            except OSError:
                pass
    finally:
        # Join BEFORE closing: serve_once has returned once the client socket
        # above is closed, so the listener is not in accept() when it goes away.
        server_thread.join(timeout=5)
        server_socket.close()

    # Comparisons produce ordinary untainted bools, so reporting on the replies
    # this way is safe even when every sink is set to raise.
    echo_worked = echoed == b"hello"
    secret_leaked = SECRET in leaked

    print()
    print(f"[client] sent 'hello' -> echoed back correctly : {echo_worked}")
    print(f"[client] sent 'data'  -> secret in the reply   : {secret_leaked}")
    print()
    if secret_leaked:
        print(" RESULT: the secret LEAKED.")
        if ES_PYTHON:
            print("         es-python is in Observe mode - the flow was reported to the")
            print("         dashboard but not stopped. Arm the rule to block it:")
            print("           Source: 1   Event: sendall   Mode: Raise")
        else:
            print("         Stock CPython. No event, no record, no way to know.")
    else:
        print(" RESULT: the secret did NOT leave the process.")
        print("         sendall was aborted before the first byte hit the wire.")
        if echo_worked:
            print("         Ordinary echo traffic still worked - the rule is scoped to")
            print("         taint number 1, so only the secret is stopped.")
        else:
            print("         NOTE: the echo was blocked too, so this run used the blunt")
            print("         ES2_RAISE=1 (every sink raises). A dashboard rule scoped to")
            print("         Source 1 blocks only the secret and leaves the echo working.")
    return 0


def main():
    if "--selftest" in sys.argv:
        return selftest()

    banner("secret exfiltration -> socket.sendall")
    print(f" secret taint number: {get_taint(SECRET)}")
    with make_server_socket() as server_socket:
        print(f" listening on {HOST}:{PORT} - send 'data' to attempt the exfiltration")
        print("=" * 78)
        serve_forever(server_socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
