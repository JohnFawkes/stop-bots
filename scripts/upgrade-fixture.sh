#!/bin/sh
# Records what a released stop-bots wrote, for the upgrade tests in
# tests/upgrade.rs:
#
#   scripts/upgrade-fixture.sh <path to the released binary> <version>
#
# e.g., for 0.2.1, from a fresh directory outside this checkout:
#
#   mkdir /tmp/sb-0.2.1 && cd /tmp/sb-0.2.1
#   gh release download v0.2.1 -R ivankovic/stop-bots -p '*x86_64*.tar.gz' -p SHA256SUMS
#   grep 'x86_64.*tar.gz$' SHA256SUMS | sha256sum -c   # 0.1.x: sha256sum -c *.tar.gz.sha256
#   tar xzf stop-bots-0.2.1-x86_64-unknown-linux-musl.tar.gz
#   cd - && scripts/upgrade-fixture.sh /tmp/sb-0.2.1/stop-bots-0.2.1-*/stop-bots 0.2.1
#
# Run it from the root of this checkout. It drives the binary through its own
# CLI in a throwaway directory (never this checkout, never /etc), changing one
# of nearly every kind of setting from its default, then writes:
#
#   tests/fixtures/db/db-<version>.sql                     the database, dumped
#   tests/fixtures/upgrade/<version>/example.com           the NGINX site it wrote
#   tests/fixtures/upgrade/<version>/firewall.nft          the firewall script
#
# The throwaway directory's paths are rewritten to the ones a real host has
# (/etc/nginx, /etc/stop-bots/nginx), so the fixtures do not change with
# the directory they were made in. Nothing else is edited.
#
# Every command used exists from 0.1.0 on; a later release that renames one
# breaks the CLI contract, and this script is the first place to notice.
set -eu

bin=$(realpath "$1")
version=$2
repo=$(pwd)
[ -f "$repo/Cargo.toml" ] || { echo "run this from the root of the checkout" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/nginx/sites-enabled" "$work/managed" "$work/conf.d"
cp "$repo/tests/fixtures/nginx/sites-enabled/example.com" "$work/nginx/sites-enabled/"
cp "$repo/tests/fixtures/botlists/well-known-bots-sample.json" "$work/bots.json"
cp "$repo/tests/fixtures/logs/auth.log" "$work/auth.log"

# The binary runs in the throwaway directory with a clean environment: the
# overrides keep every file it writes inside it, and with no SSH_CLIENT a
# newer build does not count this shell's session in the lockout check.
sb() {
    (cd "$work" && env -i PATH=/usr/bin:/bin HOME="$work" \
        STOP_BOTS_NGINX_DIR="$work/managed" \
        STOP_BOTS_NGINX_CONF_D="$work/conf.d" \
        STOP_BOTS_HOST_CONF="$work/host.conf" \
        STOP_BOTS_SSH_CLIENT= \
        "$bin" "$@" --db "$work/db.sqlite3")
}

sb update-bot-lists --source-id well-known-bots --source bots.json
sb scan-sites --root "$work/nginx"
sb set-category --category search --policy blocked
sb set-category --category ai --policy allowed --site example.com
sb set-detector web-scanners --enabled false
sb set-detector asset-ratio --enabled true
sb set-detector probe-paths --ttl-days 9
sb set-detector ssh-scanners --threshold 7 --window-hours 48
sb set-geo-mode --mode allowlist
sb add-country --country hr
sb trust --address 192.0.2.10
sb trust --user-agent UptimeRobot
sb add-firewall-rule --address 203.0.113.7
sb add-firewall-rule --address 198.51.100.0/24 --port 22
sb add-firewall-rule --address 192.0.2.1 --action allow
sb set-block-response --response gone
sb set-robots-txt --enabled true
sb set-rate-limit --enabled true --rps 7 --burst 11
sb set-site-rule --site example.com --rule http-1x --enabled true
sb exempt-path --site example.com --path /blog/
sb apply-blocks --root "$work/nginx" --no-reload
sb render-firewall --out firewall.nft --ssh-log auth.log

# $work itself last: it is a prefix of the other three.
real_paths() {
    sed -e "s|$work/nginx|/etc/nginx|g" \
        -e "s|$work/conf.d|/etc/nginx/conf.d|g" \
        -e "s|$work/managed|/etc/stop-bots/nginx|g" \
        -e "s|$work|/var/lib/stop-bots|g"
}

out="$repo/tests/fixtures/upgrade/$version"
mkdir -p "$out"
{
    echo "-- A database as stop-bots $version wrote it: \`sqlite3 db.sqlite3 .dump\` of a"
    echo "-- file the released $version binary created and filled through its own CLI."
    echo "-- Made by scripts/upgrade-fixture.sh, which lists every command; regenerate"
    echo "-- it only if it turns out not to be what $version wrote."
    echo "--"
    echo "-- \`.dump\` leaves out the schema version, so it is added as the last line."
    sqlite3 "$work/db.sqlite3" .dump | real_paths
    echo "PRAGMA user_version=$(sqlite3 "$work/db.sqlite3" 'PRAGMA user_version');"
} >"$repo/tests/fixtures/db/db-$version.sql"
real_paths <"$work/nginx/sites-enabled/example.com" >"$out/example.com"
real_paths <"$work/firewall.nft" >"$out/firewall.nft"
echo "wrote tests/fixtures/db/db-$version.sql and $out/"
