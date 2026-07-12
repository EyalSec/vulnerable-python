#!/usr/bin/env python3.13
"""SOURCE input() -> SINK eval  =>  interactive-input code injection.

input() reads from stdin, so it is armed by the same ES2_MAKE_STDIN_VULN gate.

Run under es-python:
    ES2_MAKE_STDIN_VULN=1 ~/opt/eyalsec/bin/python3.13 demos/input_demo.py
    (then type an expression, e.g.  __import__('os').getuid()  )

EyalSec reports: input() source reaching eval.
"""
expr = input("expression> ")          # <-- tainted at the input() source
print("eval result:", repr(eval(expr)))   # <-- SINK
