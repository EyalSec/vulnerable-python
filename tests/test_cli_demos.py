"""The command-line demos under plain Python: each must run to the end and
report that the flow went through, since nothing here tracks taint.

Each case is the "as configured" run from run-demos.sh.
"""

import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CASES = [
    ("demos/secret_exfil_server.py", ["--selftest"], {"ES2_MAKE_SOCKET_VULN": "1"}, None,
     "RESULT: the secret LEAKED."),
    ("demos/uncatchable_plugin.py", [], {"ES2_MAKE_FOREIGN_VULN": "1"}, None,
     "RESULT: the plugin ran."),
    ("demos/foreign_main_script.py", [], {"ES2_MAKE_FOREIGN_VULN": "1"}, None,
     "RESULT: the script ran."),
    ("demos/untrusted_code_demo.py", ["y = 1 + 1"],
     {"ES2_MAKE_FOREIGN_VULN": "1", "ES2_MAKE_STDIN_VULN": "1",
      "ES2_MAKE_ENV_VULN": "1", "DEMO_CODE": "z = 3"}, "x = 6 * 7\n",
     "RESULT: every load ran."),
    ("demos/taint_gauntlet.py", [], {"ES2_MAKE_SOCKET_VULN": "1"}, None,
     "RESULT: the payload left the process."),
]


@pytest.mark.parametrize("script,args,env,stdin,expected", CASES, ids=[c[0] for c in CASES])
def test_demo_runs_through_under_plain_python(script, args, env, stdin, expected):
    proc = subprocess.run(
        [sys.executable, script, *args],
        cwd=ROOT,
        env={**os.environ, **env},
        input=stdin,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert expected in proc.stdout, proc.stdout
    assert "Plain python3" in proc.stdout
