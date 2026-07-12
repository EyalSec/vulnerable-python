#!/usr/bin/env python3.13
"""SOURCE argv -> SINK os.system  =>  command-line-borne command injection.

Elements of sys.argv are tainted under ES2_MAKE_ENV_VULN (the env gate also
covers argv, since both are attacker-influenced process input).

Run under es-python:
    ES2_MAKE_ENV_VULN=1 ~/opt/eyalsec/bin/python3.13 demos/argv_demo.py '127.0.0.1; id'

EyalSec reports: argv source reaching the shell sink.
"""
import os
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"  # <-- tainted at the argv source
cmd = "ping -c 1 " + target
print("running:", cmd)
os.system(cmd)   # <-- SINK
