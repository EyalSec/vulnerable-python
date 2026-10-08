#!/usr/bin/env python3.13
"""Fixtures and predicates for the foreign-code lab (`/foreign/*` in app.py).

  ############################################################################
  #  WARNING: this module deliberately creates world-writable files and a    #
  #  world-writable directory under the system temp dir. Isolated lab use    #
  #  only - see the warning at the top of app.py.                            #
  ############################################################################

The FOREIGN gate (`--make-foreign-vuln` / `ES2_MAKE_FOREIGN_VULN=1`) is the
only es-python source that is about PROVENANCE rather than about data. It
answers one question - "could a user other than me have written this?" - and
then does three separate things with the answer:

  1. CODE LOAD EVENT. Loading code from such a file emits `foreign-code:<path>`
     at load time, whether it arrives by `import`, by running the script, from
     a `.pyc`, or through `compile()`. No taint, no sink, no data flow is
     needed: the load itself is the finding.
  2. DATA TAINT. Reading data from such a file taints the data, with the FILE
     gate switched off. `ES2_MAKE_FILE_VULN=1` taints every file read on the
     box; the foreign gate taints only the reads an attacker could have
     controlled, which is why it can be left on in production.
  3. UNTRUSTED CODE LOAD. `exec`/`eval`/`compile` of a string recovers the
     provenance of the string from its taint chain, so a code load whose
     filename is `<string>` still reports where the bytes came from - as
     `foreign-code:<path>` when they came from a foreign-writable file, and as
     `untrusted-code:<origin>` for every other source (socket, stdin, env,
     argv, make_vuln).

`shadow-import` also folds under this gate; it has its own route in app.py.

What counts as foreign (three rules on the file itself):

    owner is another non-root user        -> foreign
    world-writable (mode bit o+w)         -> foreign
    group-writable AND the group has
      another real member                 -> foreign

Root-owned files are trusted: root can do anything anyway, so treating
/usr/lib/python3.13/*.py as attacker-controlled would report the whole stdlib.

Reads (not code loads) additionally consult the IMMEDIATE PARENT directory: if
another user can rename or replace the file, the file is foreign even when its
own bits are private. That check honours the sticky bit, so an ordinary file
you own in /tmp (mode 1777, sticky) is NOT foreign - only a non-sticky
world-writable directory lets someone swap your file out.

`verdict()` below re-implements those rules in pure Python so every route can
show its own arithmetic. It is a mirror for the demo's benefit, not the
detector: es-python makes this decision at the open itself, before your code
gets a file object at all.
"""

import grp
import os
import pwd
import stat
import tempfile

# No-sudo fixtures: everything that can be arranged by an unprivileged user.
LAB_DIR = os.path.join(tempfile.gettempdir(), "eyalsec_foreign_lab")

# Fixtures that genuinely need a second user, created by ./setup-foreign.sh.
# Kept at a fixed path so the script and the app agree without configuration.
SUDO_DIR = "/var/tmp/eyalsec-foreign"

SETUP_HINT = ("run ./setup-foreign.sh (needs sudo) - this case requires a file "
              "owned by a DIFFERENT user, which an unprivileged process cannot "
              "create for itself")


# --------------------------------------------------------------------------- #
# The predicate, mirrored from Python/transfer.c for display purposes.
# --------------------------------------------------------------------------- #
def _group_has_other_member(gid, me):
    """Does group `gid` contain a real user other than uid `me`?

    Mirrors `_es_group_has_other_user`: supplementary members from the group
    entry first, then users whose PRIMARY gid is this group (those never appear
    in gr_mem). Root is not special here - only in the owner rule.
    """
    try:
        entry = grp.getgrgid(gid)
    except KeyError:
        return False, []
    others = []
    for name in entry.gr_mem:
        try:
            if pwd.getpwnam(name).pw_uid != me:
                others.append(name)
        except KeyError:
            continue
    for pw in pwd.getpwall():
        if pw.pw_gid == gid and pw.pw_uid != me and pw.pw_name not in others:
            others.append(pw.pw_name)
    return bool(others), others


def _owner_name(uid):
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def verdict(path):
    """Explain, rule by rule, whether es-python calls `path` foreign.

    Returns a dict shaped for a JSON response: the three file-itself rules
    (which decide CODE LOADS), the parent-directory rule (which additionally
    decides READS), and the resulting two verdicts.
    """
    me = os.geteuid()
    try:
        st = os.stat(path)
    except OSError as exc:
        return {"path": path, "error": str(exc), "exists": False}

    owner_is_other = st.st_uid != me and st.st_uid != 0
    world_writable = bool(st.st_mode & stat.S_IWOTH)
    group_writable = bool(st.st_mode & stat.S_IWGRP)
    group_shared, group_others = (_group_has_other_member(st.st_gid, me)
                                  if group_writable else (False, []))

    reasons = []
    if owner_is_other:
        reasons.append(f"owned by another user ({_owner_name(st.st_uid)}), not by me "
                       f"({_owner_name(me)}) and not by root")
    if world_writable:
        reasons.append("world-writable (o+w): any user on the box can rewrite it")
    if group_writable and group_shared:
        reasons.append(f"group-writable and group {grp.getgrgid(st.st_gid).gr_name} "
                       f"has another member ({', '.join(group_others[:3])})")

    parent = os.path.dirname(os.path.realpath(path)) or "/"
    parent_swappable, parent_why = _dir_enables_swap(parent, me)

    return {
        "path": path,
        "exists": True,
        "owner": _owner_name(st.st_uid),
        "group": grp.getgrgid(st.st_gid).gr_name if _gr_ok(st.st_gid) else st.st_gid,
        "mode": oct(st.st_mode & 0o7777),
        "rules": {
            "owned_by_another_user": owner_is_other,
            "world_writable": world_writable,
            "group_writable_with_another_member": group_writable and group_shared,
            "parent_dir_allows_swap": parent_swappable,
        },
        "parent_dir": parent,
        "parent_dir_reason": parent_why,
        # A code load looks at the file only. A read also accepts the parent.
        "foreign_for_code_load": bool(reasons),
        "foreign_for_reads": bool(reasons) or parent_swappable,
        "why": reasons or ["none of the three file rules match"],
    }


def _gr_ok(gid):
    try:
        grp.getgrgid(gid)
        return True
    except KeyError:
        return False


def _dir_enables_swap(path, me):
    """Mirror of `_es_dir_enables_foreign_swap` - can another user rename or
    replace a file inside this directory? The sticky bit is what makes /tmp
    safe despite being world-writable: it restricts rename/unlink to the file's
    owner, so a file you own there cannot be swapped out from under you.
    """
    try:
        st = os.stat(path)
    except OSError as exc:
        return False, f"cannot stat {path}: {exc}"
    if st.st_uid != me and st.st_uid != 0:
        return True, f"{path} is owned by {_owner_name(st.st_uid)}, who can rename anything in it"
    if st.st_mode & stat.S_ISVTX:
        return False, f"{path} is sticky ({oct(st.st_mode & 0o7777)}): only the owner may rename"
    if st.st_mode & stat.S_IWOTH:
        return True, f"{path} is world-writable and NOT sticky: anyone can swap files in it"
    if st.st_mode & stat.S_IWGRP and _group_has_other_member(st.st_gid, me)[0]:
        return True, f"{path} is group-writable and the group has another member"
    return False, f"{path} is a shield: no other user can rename its contents"


def usable_shared_group():
    """A group this process belongs to that has another real member.

    The group-writable rule needs one; most boxes give a user a private group
    of exactly themselves, in which case there is nothing to demonstrate until
    ./setup-foreign.sh creates one.
    """
    me = os.geteuid()
    for gid in os.getgroups():
        shared, others = _group_has_other_member(gid, me)
        if shared:
            try:
                return gid, grp.getgrgid(gid).gr_name, others
            except KeyError:
                return gid, str(gid), others
    return None, None, []


# --------------------------------------------------------------------------- #
# Fixtures an unprivileged process can build for itself.
# --------------------------------------------------------------------------- #
FOREIGN_MODULE_SRC = (
    "# Any user on this box can rewrite this file, so any user on this box\n"
    "# decides what this process executes on the next import.\n"
    "MESSAGE = 'imported from a file another user can write'\n"
    "def greet(name):\n"
    "    return 'hello ' + name\n"
)


def _write(path, text, mode=None):
    with open(path, "w") as fh:
        fh.write(text)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except OSError:
            pass
    return path


def build():
    """Create every no-sudo fixture and return a name -> path map.

    Each foreign-code route gets its OWN file on purpose: the detector reports
    one event per resolved path per process, so two routes sharing a file would
    leave the second one silent and look like a miss.
    """
    os.makedirs(LAB_DIR, exist_ok=True)
    os.chmod(LAB_DIR, 0o755)

    paths = {}

    # (1) World-writable module, imported by NAME through sys.path.
    import_dir = os.path.join(LAB_DIR, "importable")
    os.makedirs(import_dir, exist_ok=True)
    paths["import_dir"] = import_dir
    paths["ww_module"] = _write(os.path.join(import_dir, "eyalsec_ww_module.py"),
                                FOREIGN_MODULE_SRC, 0o666)

    # (2) A world-writable .pyc, with NO .py beside it. Bytecode is the version
    #     of this attack a source scanner cannot read at all.
    paths["pyc_dir"] = os.path.join(LAB_DIR, "pyc_only")
    os.makedirs(paths["pyc_dir"], exist_ok=True)
    paths["ww_pyc_source"] = os.path.join(LAB_DIR, "eyalsec_pyc_src.py")
    _write(paths["ww_pyc_source"], FOREIGN_MODULE_SRC.replace(
        "imported from", "loaded as bytecode from"))
    paths["ww_pyc"] = os.path.join(paths["pyc_dir"], "eyalsec_ww_bytecode.pyc")

    # (3) Source read as DATA and then executed - the load whose filename is
    #     "<string>", where provenance can only come from the taint chain.
    paths["ww_source"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_source.py"),
                                "RESULT = 6 * 7\n", 0o666)
    paths["ww_compile"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_compile.py"),
                                 "COMPILED = 'compiled from a foreign path'\n", 0o666)

    # (4) Data fixtures. Each one is a plain file that happens to be writable by
    #     everybody, which is all it takes for its bytes to arrive tainted.
    paths["ww_sql"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_query.txt"),
                             "alice' OR '1'='1", 0o666)
    paths["ww_lines"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_hosts.txt"),
                               "127.0.0.1\n127.0.0.1; id\n", 0o666)
    paths["ww_cmd"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_cmd.txt"),
                             "127.0.0.1; whoami\n", 0o666)
    paths["ww_mmap"] = _write(os.path.join(LAB_DIR, "eyalsec_ww_mapped.txt"),
                              "bob' UNION SELECT id, secret FROM users --", 0o666)

    # (5) Parent-directory swap: a file I own, mode 0600, in a world-writable
    #     directory with NO sticky bit. Nobody can read it through its own
    #     permissions - they replace it instead.
    open_dir = os.path.join(LAB_DIR, "unshielded")
    os.makedirs(open_dir, exist_ok=True)
    os.chmod(open_dir, 0o777)                       # deliberately NOT sticky
    paths["open_dir"] = open_dir
    paths["swappable_data"] = _write(os.path.join(open_dir, "private_but_swappable.txt"),
                                     "charlie' OR '1'='1", 0o600)
    paths["swappable_module"] = _write(os.path.join(open_dir, "eyalsec_swappable_mod.py"),
                                       FOREIGN_MODULE_SRC, 0o600)

    # (6) Silent controls. Every one of these is loaded and read by
    #     /foreign/controls and must produce NO event.
    shield_dir = os.path.join(LAB_DIR, "shielded")
    os.makedirs(shield_dir, exist_ok=True)
    os.chmod(shield_dir, 0o700)
    paths["shield_dir"] = shield_dir
    paths["private_data"] = _write(os.path.join(shield_dir, "mine.txt"),
                                   "private data", 0o600)
    paths["private_module"] = _write(os.path.join(shield_dir, "eyalsec_private_mod.py"),
                                     FOREIGN_MODULE_SRC, 0o600)
    # Sticky-parent control: my own private file directly in /tmp (mode 1777).
    paths["sticky_data"] = _write(
        os.path.join(tempfile.gettempdir(), "eyalsec_sticky_control.txt"),
        "private data under a sticky world-writable dir", 0o600)
    # Allowlist control: world-writable, but inside a directory the operator
    # named in ES2_FOREIGN_CODE_ALLOW (run-eyalsec.sh sets it to this path).
    allow_dir = os.path.join(LAB_DIR, "operator_trusted")
    os.makedirs(allow_dir, exist_ok=True)
    paths["allow_dir"] = allow_dir
    paths["allowlisted_module"] = _write(os.path.join(allow_dir, "eyalsec_trusted_mod.py"),
                                         FOREIGN_MODULE_SRC, 0o666)

    # (7) Group-writable, if this box has a group that makes it meaningful.
    gid, gname, _others = usable_shared_group()
    if gid is not None:
        gw = _write(os.path.join(LAB_DIR, "eyalsec_group_writable.py"),
                    FOREIGN_MODULE_SRC)
        try:
            os.chown(gw, -1, gid)
            os.chmod(gw, 0o664)
            paths["group_module"] = gw
            paths["group_name"] = gname
        except OSError:
            pass

    return paths


def sudo_fixture(name):
    """Path to a ./setup-foreign.sh fixture, or None when it is not set up."""
    path = os.path.join(SUDO_DIR, name)
    return path if os.path.exists(path) else None


def not_set_up(name, what):
    """The JSON body a route returns when its sudo fixture is missing."""
    return {"fixture": os.path.join(SUDO_DIR, name),
            "status": "not set up",
            "needs": what,
            "how": SETUP_HINT}
