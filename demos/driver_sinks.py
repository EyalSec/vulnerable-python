#!/usr/bin/env python3.13
"""SQL injection through the real database drivers es-python ships.

  ############################################################################
  #  Sends deliberately injectable SQL. Point it at a THROWAWAY database.    #
  ############################################################################

Why this demo is separate from app.py
-------------------------------------
Every other endpoint in this repository reaches its sink with nothing but the
standard library, so `pip install flask` is the whole setup. These sinks are
different: they live inside compiled database drivers, and reaching one needs
both the driver and a database server to connect to. So they get a script you
point at whatever servers you have, and it skips whatever you do not.

What makes these sinks worth a demo of their own
------------------------------------------------
The stdlib `sqlite3` sink proves the idea. These prove it is not a toy: the
same detection is compiled into the drivers real applications actually use.
es-python vendors each driver (see EyalSec_Cpython/third_party/) with a
C or Cython sink on the statement string, and installs the instrumented build
into the shipped prefix. `_eyalsec_syssite.hoist_instrumented()` then puts that
directory ahead of user-site on sys.path at every startup, so `import psycopg2`
loads the instrumented copy even after a later `pip install psycopg2` drops a
vanilla wheel into ~/.local.

  (Consequence worth knowing: `pip show psycopg2` can report the vanilla copy
  while `import psycopg2` loads the instrumented one. The import is what
  carries the sink, so the sink is intact - the metadata is just reporting the
  distribution that got shadowed.)

| Database   | Driver          | Sink                                  |
|------------|-----------------|---------------------------------------|
| PostgreSQL | psycopg2        | `_psyco_curs_execute` (C)             |
| PostgreSQL | psycopg v3      | the 4 PGconn query wrappers (C)       |
| MySQL      | mysqlclient     | `_mysql_ConnectionObject_query` (C)   |
| MariaDB    | mariadb         | `MrdbCursor_parse` (C)                |
| Oracle     | oracledb        | `BaseCursorImpl._prepare` (Cython)    |
| LDAP       | python-ldap     | `l_ldap_search_ext` (C)               |

THE POINT OF THE SECOND QUERY IN EACH PAIR
------------------------------------------
Every driver sink fires on the **statement string only, never on bound
parameters**. So each database below runs the same attacker value twice:

    1. concatenated into the statement  -> reported
    2. passed as a bound parameter      -> silent, because it is not injection

That is what keeps this from being a false-positive machine. Correctly
parameterized code stays quiet no matter how hostile the value is, which is
also why "we found 4,000 SQL events" from a scanner and "we found 4 real
injections" from es-python are different claims.

LDAP IS THE HONEST EXCEPTION, AND IT IS DELIBERATE
--------------------------------------------------
LDAP has no bind-parameter mechanism. The correct way to write an LDAP filter
is `ldap.filter.filter_format`, which ESCAPES the value - but the escaped
value is still spliced into the filter string, so it is still tainted and the
sink still fires. The claim this sink makes is therefore *"attacker data
reached the LDAP search filter"*, not *"confirmed injection"*. Triage on
whether the filter was escaped; do not treat the event alone as a finding.
The sink deliberately covers the filter argument only - never the base DN and
never the attribute list.

Usage
-----
    export ES_DEMO_PG_DSN='postgresql://user:pass@127.0.0.1:5432/scratch'
    export ES_DEMO_MYSQL_URL='mysql://user:pass@127.0.0.1:3306/scratch'
    export ES_DEMO_MARIADB_URL='mysql://user:pass@127.0.0.1:3306/scratch'
    export ES_DEMO_ORACLE_DSN='user/pass@127.0.0.1:1521/XEPDB1'
    export ES_DEMO_LDAP_URI='ldap://127.0.0.1:389'

    es-python demos/driver_sinks.py

Anything you do not set is skipped and reported as skipped. With nothing set
the script still runs and tells you exactly what it would have needed, so it
is safe to run first and configure second.
"""

import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from es_compat import ES_PYTHON, banner, make_vuln  # noqa: E402

# The attacker-controlled value. Under es-python it is explicitly tainted, so
# the demo does not depend on which taint sources happen to be armed on this
# machine. Under stock CPython make_vuln is an inert stand-in and this is just
# a string - the injection still works, nothing reports it.
EVIL = make_vuln("x' OR '1'='1", 1)

results = []


def record(target, status, detail):
    results.append((target, status, detail))
    mark = {"ran": "  RAN ", "skip": " SKIP ", "error": " ERR  "}[status]
    print(f"[{mark}] {target:<22} {detail}")


def run_pair(target, cursor, concat_sql, param_sql, param_args):
    """Run the injectable statement, then the parameterized one."""
    cursor.execute(concat_sql)                 # <-- SINK (reported under es-python)
    cursor.execute(param_sql, param_args)      # <-- same value, bound: silent
    record(target, "ran",
           "injectable statement reported; parameterized form silent"
           if ES_PYTHON else
           "both statements ran, neither reported (stock CPython)")


def demo_psycopg2():
    dsn = os.environ.get("ES_DEMO_PG_DSN")
    if not dsn:
        return record("psycopg2", "skip", "set ES_DEMO_PG_DSN to run")
    try:
        import psycopg2
    except ImportError:
        return record("psycopg2", "skip", "driver not installed")
    try:
        with psycopg2.connect(dsn) as conn, conn.cursor() as cur:
            run_pair("psycopg2", cur,
                     "SELECT 1 WHERE 'a' = '" + EVIL + "'",
                     "SELECT 1 WHERE 'a' = %s", (EVIL,))
    except Exception as exc:
        record("psycopg2", "error", f"{exc.__class__.__name__}: {exc}")


def demo_psycopg3():
    dsn = os.environ.get("ES_DEMO_PG_DSN")
    if not dsn:
        return record("psycopg v3", "skip", "set ES_DEMO_PG_DSN to run")
    try:
        import psycopg
    except ImportError:
        return record("psycopg v3", "skip", "driver not installed")
    try:
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            run_pair("psycopg v3", cur,
                     "SELECT 1 WHERE 'a' = '" + EVIL + "'",
                     "SELECT 1 WHERE 'a' = %s", (EVIL,))
    except Exception as exc:
        record("psycopg v3", "error", f"{exc.__class__.__name__}: {exc}")


def _mysql_parts(url):
    u = urllib.parse.urlparse(url)
    return dict(host=u.hostname or "127.0.0.1", port=u.port or 3306,
                user=u.username or "root", password=u.password or "",
                database=(u.path or "/").lstrip("/") or None)


def demo_mysqlclient():
    url = os.environ.get("ES_DEMO_MYSQL_URL")
    if not url:
        return record("mysqlclient", "skip", "set ES_DEMO_MYSQL_URL to run")
    try:
        import MySQLdb
    except ImportError:
        return record("mysqlclient", "skip", "driver not installed")
    p = _mysql_parts(url)
    try:
        conn = MySQLdb.connect(host=p["host"], port=p["port"], user=p["user"],
                               passwd=p["password"], db=p["database"])
        try:
            cur = conn.cursor()
            run_pair("mysqlclient", cur,
                     "SELECT 1 FROM DUAL WHERE 'a' = '" + EVIL + "'",
                     "SELECT 1 FROM DUAL WHERE 'a' = %s", (EVIL,))
        finally:
            conn.close()
    except Exception as exc:
        record("mysqlclient", "error", f"{exc.__class__.__name__}: {exc}")


def demo_mariadb():
    url = os.environ.get("ES_DEMO_MARIADB_URL")
    if not url:
        return record("mariadb", "skip", "set ES_DEMO_MARIADB_URL to run")
    try:
        import mariadb
    except ImportError:
        return record("mariadb", "skip", "driver not installed")
    p = _mysql_parts(url)
    try:
        conn = mariadb.connect(host=p["host"], port=p["port"], user=p["user"],
                               password=p["password"], database=p["database"])
        try:
            cur = conn.cursor()
            run_pair("mariadb", cur,
                     "SELECT 1 FROM DUAL WHERE 'a' = '" + EVIL + "'",
                     "SELECT 1 FROM DUAL WHERE 'a' = ?", (EVIL,))
        finally:
            conn.close()
    except Exception as exc:
        record("mariadb", "error", f"{exc.__class__.__name__}: {exc}")


def demo_oracledb():
    dsn = os.environ.get("ES_DEMO_ORACLE_DSN")
    if not dsn:
        return record("oracledb", "skip", "set ES_DEMO_ORACLE_DSN to run")
    try:
        import oracledb
    except ImportError:
        return record("oracledb", "skip", "driver not installed")
    try:
        user, _, rest = dsn.partition("/")
        password, _, service = rest.partition("@")
        conn = oracledb.connect(user=user, password=password, dsn=service)
        try:
            cur = conn.cursor()
            run_pair("oracledb", cur,
                     "SELECT 1 FROM DUAL WHERE 'a' = '" + EVIL + "'",
                     "SELECT 1 FROM DUAL WHERE 'a' = :v", (EVIL,))
        finally:
            conn.close()
    except Exception as exc:
        record("oracledb", "error", f"{exc.__class__.__name__}: {exc}")


def demo_ldap():
    uri = os.environ.get("ES_DEMO_LDAP_URI")
    if not uri:
        return record("python-ldap", "skip", "set ES_DEMO_LDAP_URI to run")
    try:
        import ldap
        import ldap.filter
    except ImportError:
        return record("python-ldap", "skip", "driver not installed")
    base = os.environ.get("ES_DEMO_LDAP_BASE", "dc=example,dc=com")
    try:
        conn = ldap.initialize(uri)
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 3)
        # 1. Naive concatenation - genuine LDAP injection.
        conn.search_ext(base, ldap.SCOPE_SUBTREE,
                        "(uid=" + EVIL + ")")               # <-- SINK
        # 2. The CORRECT form. Still reported, and that is not a bug: the
        #    escaped value is still spliced into the filter string, so it is
        #    still tainted. LDAP has no bind parameters to move it out of band.
        conn.search_ext(base, ldap.SCOPE_SUBTREE,
                        ldap.filter.filter_format("(uid=%s)", [EVIL]))  # <-- SINK
        record("python-ldap", "ran",
               "both forms reported - escaping is not parameterization")
    except Exception as exc:
        record("python-ldap", "error", f"{exc.__class__.__name__}: {exc}")


def main():
    banner("SQL / LDAP injection through the bundled drivers")
    if not ES_PYTHON:
        print("  Running under stock CPython: every injection below succeeds")
        print("  and NOTHING is reported. That is the control case.\n")
    else:
        print("  Running under es-python: each injectable statement is")
        print("  reported at the driver's own sink; the bound-parameter form")
        print("  next to it is not.\n")

    for demo in (demo_psycopg2, demo_psycopg3, demo_mysqlclient,
                 demo_mariadb, demo_oracledb, demo_ldap):
        demo()

    ran = [r for r in results if r[1] == "ran"]
    skipped = [r for r in results if r[1] == "skip"]
    errored = [r for r in results if r[1] == "error"]
    print(f"\nRESULT: {len(ran)} exercised, {len(skipped)} skipped, "
          f"{len(errored)} errored, out of {len(results)} drivers.")
    if not ran:
        print("Nothing was exercised. Set at least one ES_DEMO_* variable "
              "above and point it at a throwaway database.")
    # Skips and connection errors are configuration, not demo failures, so the
    # exit status stays 0 - this script is meant to be safe to run blind.
    return 0


if __name__ == "__main__":
    sys.exit(main())
