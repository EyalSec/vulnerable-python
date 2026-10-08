"""Fake credentials, hardcoded on purpose, for the `hardcoded` taint source.

  ############################################################################
  #  Every value in this file is FAKE and randomly generated for the demo.   #
  #  None of them authenticates against anything. Do not put a real key in   #
  #  this repository.                                                        #
  ############################################################################

Why this is a separate module instead of a constant in app.py
-------------------------------------------------------------
The `hardcoded` source scans a module's source when it is imported and
compiled. That has two consequences the demo has to respect, and neither is a
bug:

  1. The script you run directly (`python app.py`) is NOT scanned, so a
     literal written directly in the main script is not seen. An *imported*
     module is.

  2. A `__pycache__` hit means the module is not compiled again, so the
     literals are seen on the first (uncached) import only. `rm -rf __pycache__` to see the
     source fire again.

So the credentials live here, this module is imported by app.py, and the
endpoints that use it document the cache caveat.

Arming: `--make-secret-vuln`, `ES2_MAKE_SECRET_VULN=1`, or
`--make-everything-vuln`. Note the flag says `secret` while the taint source
is named `hardcoded` (taint number 12). There is no dashboard machine-config
category for it - it is flag/env only.

es-python taints these values when the module is loaded, with origin
`hardcoded:<file>:<line>`. The finding then fires where the value is USED:
`credential exfiltration` at a socket send, `credential logging` at a log
record. That is the whole point of the source - a secret sitting in a variable
is not yet an incident.
"""

# Matched by the provider-key regex route (the `sk-` shape), regardless of the
# variable name.
STRIPE_API_KEY = "sk-live-9f2b7c41ea8d4f60b3c95a7e12d84f36"

# Matched by the provider-key regex route (the `ghp_` shape).
GITHUB_TOKEN = "ghp_4Qm8vRt2XwZ9kLp3NfB6dHs1JyC7eA0gTuV5"

# Matched by the name-driven route: the target name's last word is a credential
# word, and the value is token-shaped (no whitespace, length >= 12, not a path
# or URL, no format placeholders) with Shannon entropy >= 3.0.
DATABASE_PASSWORD = "Xr7fQ2mNb9wKp4Ts6Vz1"

# A dict-key shape, also covered by the name-driven route.
SERVICE_ACCOUNTS = {
    "billing_api_key": "b8Kd3Wq7Rn2Tf6Ym9Jc4Lx1Vh5Zs0Pg",
}

# DELIBERATELY NOT MATCHED, and worth seeing next to the ones that are: the
# token-shape filter rejects any value containing whitespace, so a passphrase
# is missed by design. This is an intended trade, not an oversight - matching it would drag in every English
# sentence assigned to a variable whose name happens to end in "password".
LEGACY_PASSWORD = "correct horse battery staple"

# Also not matched: a placeholder, which the value filter rejects outright.
PLACEHOLDER_API_KEY = "changeme"
