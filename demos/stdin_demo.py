#!/usr/bin/env python3.13
"""SOURCE stdin -> SINK eval  =>  standard-input-borne code injection.

The stdin source is process-launch-bound, so it is a CLI demo rather than an
HTTP route. Data read from sys.stdin is tainted under ES2_MAKE_STDIN_VULN.

Run under es-python:
    echo '6*7' | ES2_MAKE_STDIN_VULN=1 ~/opt/eyalsec/bin/python3.13 demos/stdin_demo.py

EyalSec reports: stdin source reaching eval.
"""
import sys

line = sys.stdin.readline().strip()   # <-- tainted at the stdin source
print("read from stdin:", repr(line))
print("eval result:", repr(eval(line)))   # <-- SINK
