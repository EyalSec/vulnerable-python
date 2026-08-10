#!/usr/bin/env bash
#
# setup-foreign.sh - build the foreign-code fixtures that need a SECOND USER.
#
#   ##########################################################################
#   #  Isolated lab machines only. This script deliberately creates files    #
#   #  owned by another user, a shared group, and a world-readable FIFO, so  #
#   #  that es-python's foreign-code detector has something real to detect.  #
#   #  Undo everything with:  ./setup-foreign.sh --remove                    #
#   ##########################################################################
#
# Most of the foreign-code lab (`/foreign/*` in app.py) builds itself at
# startup, because "world-writable" and "world-writable parent directory" are
# things any unprivileged process can arrange. Three cases are not:
#
#   * a file OWNED BY ANOTHER USER            - rule 1 of the predicate
#   * a file GROUP-WRITABLE by a shared group - rule 3 of the predicate
#   * a FIFO created by another user          - the non-regular-file branch
#
# ...and one negative control that also needs root:
#
#   * a ROOT-OWNED file, which es-python deliberately trusts
#
# Everything lands in /var/tmp/eyalsec-foreign, which app.py reads at request
# time - so you can run this before or after starting the app.
#
set -euo pipefail

DIR=/var/tmp/eyalsec-foreign
GROUP=eyalsecdemo
# The second user. `nobody` exists on every Linux distribution and owns
# nothing, which makes it the least surprising stand-in for "somebody else".
OTHER=nobody

ME=${SUDO_USER:-$(id -un)}

if [ "${1:-}" = "--remove" ]; then
    sudo rm -rf "$DIR"
    if getent group "$GROUP" >/dev/null; then
        sudo gpasswd -d "$OTHER" "$GROUP" >/dev/null 2>&1 || true
        sudo gpasswd -d "$ME" "$GROUP" >/dev/null 2>&1 || true
        sudo groupdel "$GROUP" 2>/dev/null || true
    fi
    echo "removed $DIR and group $GROUP"
    exit 0
fi

if ! getent passwd "$OTHER" >/dev/null; then
    echo "no '$OTHER' account on this box - edit OTHER= at the top of this script" >&2
    exit 1
fi

echo "creating foreign-code fixtures in $DIR (second user: $OTHER)"
sudo mkdir -p "$DIR"
sudo chmod 755 "$DIR"

# --------------------------------------------------------------------------- #
# 1. A module owned by another user. Mode 0644 - note that "foreign" here has
#    nothing to do with the mode bits: I cannot write this file at all, and it
#    is still untrusted, because the user who CAN write it is not me.
# --------------------------------------------------------------------------- #
sudo tee "$DIR/other_user_module.py" >/dev/null <<'PY'
# Owned by another user. They decide what this process imports.
MESSAGE = 'imported from a module owned by another user'
def greet(name):
    return 'hello ' + name
PY
sudo chown "$OTHER" "$DIR/other_user_module.py"
sudo chmod 644 "$DIR/other_user_module.py"

# --------------------------------------------------------------------------- #
# 2. Data owned by another user: a SQL fragment and a command argument.
# --------------------------------------------------------------------------- #
printf "alice' OR '1'='1" | sudo tee "$DIR/other_user_query.txt" >/dev/null
sudo chown "$OTHER" "$DIR/other_user_query.txt"
sudo chmod 644 "$DIR/other_user_query.txt"

printf '127.0.0.1; id\n' | sudo tee "$DIR/other_user_cmd.txt" >/dev/null
sudo chown "$OTHER" "$DIR/other_user_cmd.txt"
sudo chmod 644 "$DIR/other_user_cmd.txt"

# --------------------------------------------------------------------------- #
# 3. A FIFO created by another user. A pipe has no contents to scan and no
#    path a policy can pin: it is judged purely on who created it.
#    /foreign/data/fifo writes to it and reads it back in the same request, so
#    there is no second process to babysit.
# --------------------------------------------------------------------------- #
sudo rm -f "$DIR/other_user.fifo"
sudo -u "$OTHER" mkfifo -m 666 "$DIR/other_user.fifo" 2>/dev/null || {
    # `nobody` usually has /sbin/nologin as its shell, so `sudo -u` may refuse.
    # Falling back to a root-created FIFO keeps the demo working: root is not
    # "me" either, but root IS trusted by the owner rule, so we chown it to
    # $OTHER afterwards to get a genuinely foreign creator.
    sudo mkfifo -m 666 "$DIR/other_user.fifo"
    sudo chown "$OTHER" "$DIR/other_user.fifo"
}

# --------------------------------------------------------------------------- #
# 4. A shared group, and a file that is group-writable by it. The file is mine
#    and is not world-writable; it is foreign because somebody ELSE is in the
#    group that may write it. es-python resolves real group membership -
#    including users whose PRIMARY group this is - rather than trusting the
#    mode bits alone, so a private one-member group would (correctly) produce
#    nothing here.
# --------------------------------------------------------------------------- #
getent group "$GROUP" >/dev/null || sudo groupadd "$GROUP"
sudo usermod -aG "$GROUP" "$ME"
sudo usermod -aG "$GROUP" "$OTHER"

sudo tee "$DIR/group_writable_module.py" >/dev/null <<'PY'
# Mine, mode 0664, group eyalsecdemo - and somebody else is in that group.
MESSAGE = 'imported from a module a shared group can write'
def greet(name):
    return 'hello ' + name
PY
sudo chown "$ME:$GROUP" "$DIR/group_writable_module.py"
sudo chmod 664 "$DIR/group_writable_module.py"

printf "bob' OR '1'='1" | sudo tee "$DIR/group_writable_query.txt" >/dev/null
sudo chown "$ME:$GROUP" "$DIR/group_writable_query.txt"
sudo chmod 664 "$DIR/group_writable_query.txt"

# --------------------------------------------------------------------------- #
# 5. Negative control: a root-owned file. Root can replace any file on the box
#    regardless of permissions, so calling root-owned code "untrusted" would
#    report the entire standard library on every import. es-python treats uid 0
#    as trusted, and this file proves it stays silent.
# --------------------------------------------------------------------------- #
sudo tee "$DIR/root_owned_module.py" >/dev/null <<'PY'
# Owned by root. Loading this must produce NO event.
MESSAGE = 'imported from a root-owned module - deliberately silent'
PY
sudo chown root:root "$DIR/root_owned_module.py"
sudo chmod 644 "$DIR/root_owned_module.py"

echo
ls -l "$DIR"
echo
echo "done. Routes now live:"
echo "  /foreign/other-user       (owned by $OTHER)"
echo "  /foreign/group-writable   (group $GROUP, shared with $OTHER)"
echo "  /foreign/data/other-user  (data owned by $OTHER)"
echo "  /foreign/data/fifo        (FIFO created by $OTHER)"
echo "  /foreign/controls         (now also covers the root-owned control)"
echo
echo "note: '$ME' was added to group '$GROUP', which only affects NEW logins."
echo "      Nothing in the demo depends on this process being in that group -"
echo "      the detector reads the file's group, not yours."
