#!/bin/sh
# The remote half of `make deploy`, piped to the target host over ssh.
#
# Usage: sh deploy-remote.sh <installed-path>
# Expects <installed-path>.new to already be in place, as scp leaves it.
set -e

path="$1"
[ -n "$path" ] || { echo "usage: $0 <path>" >&2; exit 2; }

# Staged next to the target and moved into place rather than written over
# it: replacing a running executable in place fails with ETXTBSY, and a
# rename swaps the directory entry while a running `stop-bots tick` keeps
# the old inode until it exits. Nothing to restart: cron runs the new one
# at the next minute.
chmod 755 "$path.new"
mv "$path.new" "$path"

printf 'deployed:   '
"$path" --version
