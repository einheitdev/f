#!/usr/bin/env bash
# fd and f-confd share /run/f. Restarting fd must not take f-confd's
# socket with it.
#
# Found by the office deployment rehearsal (2026-08-14). Both units
# declared `RuntimeDirectory=f`; systemd deletes a RuntimeDirectory
# when the unit that declares it stops, and only f-confd.service set
# `RuntimeDirectoryPreserve=yes`. So `systemctl restart fd` unlinked
# /run/f entirely and recreated it holding only control.sock —
# f-confd stayed `active`, stayed bound to the now-unlinked inode,
# logged nothing, and was unreachable forever after.
#
# What that costs is the whole point: `apply system confirmed` is the
# anti-lockout rollback, and it refused with "f-confd is not running"
# on a box where systemd said it was. Worse, HANDBOOK.md §3.3
# prescribes `systemctl restart fd` as a recovery step, so following
# the handbook disarmed the protection the handbook's own §3.1 tells
# you to rely on.
#
# The assertion is deliberately about the SOCKET and not about
# `systemctl is-active`: is-active was true the entire time this was
# broken, which is exactly why nothing caught it.
source "$(dirname "$0")/hwlib.sh"
hw::require_root
trap hw::finish EXIT

CONFD_SOCK=/run/f/confd.sock
CONFD_PUB=/run/f/confd.pub

# The rig sits on the smoke policy with f-confd disabled; bring it up
# for the test and put it back however this exits.
STARTED_CONFD=0
if ! systemctl is-active --quiet f-confd; then
  systemctl start f-confd || hw::abort "cannot start f-confd"
  STARTED_CONFD=1
fi
restore_confd() {
  if [ "$STARTED_CONFD" -eq 1 ]; then
    systemctl stop f-confd 2>/dev/null || true
  fi
}
trap 'restore_confd; hw::finish' EXIT

# Settle: the socket appears after the bind, not after the fork.
for _ in $(seq 1 20); do
  [ -S "$CONFD_SOCK" ] && break
  sleep 0.5
done

sock_count() {
  local n=0
  [ -S "$CONFD_SOCK" ] && n=$((n + 1))
  [ -S "$CONFD_PUB" ] && n=$((n + 1))
  echo "$n"
}

assert_eq "f-confd sockets present before the restart" \
  "$(sock_count)" 2

# The exact step HANDBOOK.md 3.3 tells an operator to take.
systemctl restart fd
for _ in $(seq 1 20); do
  systemctl is-active --quiet fd && break
  sleep 0.5
done
sleep 2

assert_str "f-confd still active after fd restart" \
  "$(systemctl is-active f-confd)" "active"

# The defect: this was 0, while is-active above still said "active".
assert_eq "f-confd sockets SURVIVE an fd restart" \
  "$(sock_count)" 2

# fd's own socket must still be there too — the fix must not have
# been "stop creating the directory".
assert_eq "fd control socket present" \
  "$([ -S /run/f/control.sock ] && echo 1 || echo 0)" 1

# Deliberately NOT asserted here: that the CLI stops reporting
# `no_confd`. Only `apply system confirmed` reaches f-confd, and it
# arms a revert timer against the live system config — a check that
# cannot run on a rig kept walk-up-ready. A `show system` probe was
# tried and removed instead of kept: it PASSED against the defect,
# because `show system` never talks to f-confd at all, and a check
# that survives the bug it is filed under is worse than no check.
