#!/usr/bin/env python3
"""Judge a host's real logs with every detector, and report who would be blocked.

    scripts/replay-logs.py --access-log access.log [--ssh-log auth.log] \\
        [--kernel-log kern.log] [--config-root nginx/] \\
        [--binary target/release/stop-bots] [--no-fetch]

Nothing is blocked or stored on the host: every detector runs with
`run-detector --dry-run`, against a database and host settings of its own in
a temporary directory, so the host's own settings and blocks play no part.
Detectors that are off by default are run too, because what they would catch
is the question. Without `--no-fetch` the crawlers' published ranges are
downloaded first, as `spoofed-crawlers` needs them and every detector uses them
to leave a verified crawler alone.

`--config-root` is a copy of the host's NGINX config (its `/etc/nginx`, say),
scanned for sites first. Without one, `probe-paths` cannot tell which
applications the host runs, and a request for `/wp-login.php` on a host with no
WordPress is not counted as a probe.

The report, on stdout as Markdown, has three parts:

- **Per detector**: how many addresses it would block, and how many of those
  look like a visitor: an address that fetched a stylesheet, script or image
  successfully, sent a `Referer`, and asked for something missing or forbidden
  in at most one request in ten. That
  is a heuristic, not ground truth, and it is what to read first: a detector
  that convicts visitors is a detector that blocks people.
- **Visitors that would be blocked**, each with the detectors that convict it
  and what it asked for.
- **Addresses that logged in over SSH and would be blocked.** On the host, a
  login spares an address from every detector for seven days after it, as the
  scheduled SSH log reader records it; `run-detector` does not record logins, so
  here they are listed with their last login instead, to be judged by hand. Most
  are the host's own operators.
- **Busy and never convicted**: the public addresses with the most requests
  that no detector convicts and that do not look like visitors. A column of
  403s is a client the web server's policy already turns away by user agent;
  the rest are what to look at for a bot that gets through. Private and
  loopback addresses are left out, since no detector ever blocks them; on a
  host running stop-bots, loopback is mostly its own `status` check.

A host that already runs stop-bots under-reports the third part: an address
its firewall blocked stops appearing in the log. The first two are unaffected.

**The report names real visitors' addresses.** Keep it, and the logs, out of
this repository and anywhere public.
"""

import argparse
import collections
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Every detector `run-detector` takes, and the log each reads. `honeypot` and
# `robots-violators` are left out: both judge requests for the robots.txt this
# script cannot know the host served. `robots-txt` follows `set-humans-only`.
DETECTORS = {
    "ssh-scanners": "ssh",
    "web-scanners": "access",
    "spoofed-crawlers": "access",
    "probe-paths": "access",
    "injection": "access",
    "asset-ratio": "access",
    "rotating-ua": "access",
    "refererless": "access",
    "login-attempts": "access",
    "request-rate": "access",
    "port-scanners": "kernel",
}

LOG_FLAG = {"access": "--access-log", "ssh": "--ssh-log", "kernel": "--kernel-log"}

WOULD_BLOCK = re.compile(r"^Would block (\S+) for ")

# NGINX's and Apache's `combined` format. A line that is not one is skipped:
# the detectors judge the whole log, and this only describes who is in it.
COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+ "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

ACCEPTED = re.compile(r"^(?P<when>\w{3} +\d+ [\d:]+) .*Accepted \S+ for \S+ from (?P<ip>\S+) port ")

ASSET = re.compile(r"\.(css|js|mjs|png|jpe?g|gif|svg|webp|avif|ico|woff2?)(\?|$)", re.I)


class Address:
    """What one address did, as far as the report needs it."""

    def __init__(self):
        self.requests = 0
        self.ok = 0
        self.client_errors = 0
        self.forbidden = 0
        self.missing = 0
        self.assets = 0
        self.referred = 0
        self.agents = collections.Counter()
        self.paths = collections.Counter()

    def looks_like_a_visitor(self):
        # A scanner fetches a favicon too, and some send a referer; what it
        # cannot avoid is asking for things that are not there.
        return (
            self.assets > 0
            and self.referred > 0
            and self.client_errors * 10 <= self.requests
        )

    def top_agent(self):
        return self.agents.most_common(1)[0][0] if self.agents else ""

    def sample_paths(self, n=3):
        return ", ".join(path for path, _ in self.paths.most_common(n))


def read_access_log(path):
    addresses = collections.defaultdict(Address)
    first = last = None
    lines = 0
    with open(path, encoding="utf-8", errors="replace") as log:
        for line in log:
            match = COMBINED.match(line)
            if not match:
                continue
            lines += 1
            first = first or match["time"]
            last = match["time"]
            seen = addresses[match["ip"]]
            seen.requests += 1
            status = int(match["status"])
            if 200 <= status < 400:
                seen.ok += 1
                if ASSET.search(match["path"]):
                    seen.assets += 1
            elif 400 <= status < 500:
                seen.client_errors += 1
                seen.forbidden += status == 403
                seen.missing += status == 404
            if match["referer"] not in ("", "-"):
                seen.referred += 1
            seen.agents[match["agent"]] += 1
            seen.paths[match["path"][:80]] += 1
    return addresses, lines, first, last


def ssh_logins(path):
    """Each address's last successful SSH login, as the log stamps it."""
    last = {}
    if path:
        with open(path, encoding="utf-8", errors="replace") as log:
            for line in log:
                match = ACCEPTED.match(line)
                if match:
                    last[match["ip"]] = match["when"]
    return last


def stop_bots(binary, env, *args):
    return subprocess.run(
        [binary, *args], env=env, capture_output=True, text=True, check=False
    )


def convictions(binary, env, logs):
    """Each detector's convicted addresses, or the reason it did not run."""
    found, skipped = {}, {}
    for detector, kind in DETECTORS.items():
        if kind not in logs:
            skipped[detector] = f"no {kind} log given"
            continue
        out = stop_bots(
            binary, env, "run-detector", detector, "--dry-run", LOG_FLAG[kind], logs[kind]
        )
        if out.returncode != 0:
            skipped[detector] = (out.stderr or out.stdout).strip().splitlines()[-1]
            continue
        found[detector] = {
            match[1]
            for match in map(WOULD_BLOCK.match, out.stdout.splitlines())
            if match
        }
    return found, skipped


def report(addresses, lines, first, last, found, skipped, logins):
    by_address = collections.defaultdict(set)
    for detector, convicted in found.items():
        for address in convicted:
            by_address[address].add(detector)

    print("# Replay of every detector\n")
    print(f"{lines} requests from {len(addresses)} addresses, {first} to {last}.\n")

    print("## Per detector\n")
    print(
        "| Detector | Would block | Of which look like visitors | Of which logged in over SSH "
        "| Only this detector |"
    )
    print("|---|---:|---:|---:|---:|")
    for detector in DETECTORS:
        if detector in skipped:
            print(f"| {detector} | not run: {skipped[detector]} | | | |")
            continue
        convicted = found[detector]
        visitors = sum(1 for a in convicted if is_visitor(a, addresses, logins))
        operators = sum(1 for a in convicted if a in logins)
        alone = sum(1 for a in convicted if by_address[a] == {detector})
        print(f"| {detector} | {len(convicted)} | {visitors} | {operators} | {alone} |")
    print(f"\n{len(by_address)} distinct addresses would be blocked in all.\n")

    print("## Visitors that would be blocked\n")
    visitors = sorted(
        (a for a in by_address if is_visitor(a, addresses, logins)),
        key=lambda a: -addresses[a].requests,
    )
    if not visitors:
        print("None.\n")
    else:
        print("| Address | Detectors | Requests | Assets | Referred | User agent | Most asked |")
        print("|---|---|---:|---:|---:|---|---|")
        for a in visitors:
            seen = addresses[a]
            print(
                f"| {a} | {', '.join(sorted(by_address[a]))} | {seen.requests} | "
                f"{seen.assets} | {seen.referred} | {cell(seen.top_agent())} | "
                f"{cell(seen.sample_paths())} |"
            )
        print()

    print("## Addresses that logged in over SSH and would be blocked\n")
    operators = sorted(a for a in by_address if a in logins)
    if not operators:
        print("None.\n")
    else:
        print("| Address | Detectors | Last SSH login | Most asked |")
        print("|---|---|---|---|")
        for a in operators:
            asked = addresses[a].sample_paths() if a in addresses else ""
            print(f"| {a} | {', '.join(sorted(by_address[a]))} | {logins[a]} | {cell(asked)} |")
        print()

    print("## Busy and never convicted\n")
    busy = sorted(
        (
            a
            for a, seen in addresses.items()
            if a not in by_address and not seen.looks_like_a_visitor() and is_public(a)
        ),
        key=lambda a: -addresses[a].requests,
    )[:25]
    print("| Address | Requests | 403 | 404 | User agent | Most asked |")
    print("|---|---:|---:|---:|---|---|")
    for a in busy:
        seen = addresses[a]
        print(
            f"| {a} | {seen.requests} | {seen.forbidden} | {seen.missing} | "
            f"{cell(seen.top_agent())} | {cell(seen.sample_paths())} |"
        )


def is_visitor(address, addresses, logins):
    """Looks like a visitor, and is not one of the host's own SSH users."""
    return (
        address in addresses
        and address not in logins
        and addresses[address].looks_like_a_visitor()
    )


def is_public(address):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def cell(text, width=70):
    text = text.replace("|", "\\|")
    return text if len(text) <= width else text[: width - 1] + "…"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--access-log", required=True)
    parser.add_argument("--ssh-log")
    parser.add_argument("--kernel-log")
    parser.add_argument("--config-root")
    parser.add_argument("--binary", default=shutil.which("stop-bots") or "stop-bots")
    parser.add_argument("--no-fetch", action="store_true")
    args = parser.parse_args()

    logs = {"access": args.access_log}
    if args.ssh_log:
        logs["ssh"] = args.ssh_log
    if args.kernel_log:
        logs["kernel"] = args.kernel_log

    with tempfile.TemporaryDirectory(prefix="stop-bots-replay-") as scratch:
        env = dict(
            os.environ,
            STOP_BOTS_DB=os.path.join(scratch, "db.sqlite3"),
            STOP_BOTS_HOST_CONF=os.path.join(scratch, "host.conf"),
        )
        open(env["STOP_BOTS_HOST_CONF"], "w").close()
        if not args.no_fetch:
            fetched = stop_bots(args.binary, env, "update-crawler-ranges")
            if fetched.returncode != 0:
                sys.exit(f"update-crawler-ranges failed:\n{fetched.stderr}")
        if args.config_root:
            scanned = stop_bots(args.binary, env, "scan-sites", "--root", args.config_root)
            if scanned.returncode != 0:
                sys.exit(f"scan-sites failed:\n{scanned.stderr}")
            print(scanned.stdout.splitlines()[0], file=sys.stderr)
        found, skipped = convictions(args.binary, env, logs)

    addresses, lines, first, last = read_access_log(args.access_log)
    report(addresses, lines, first, last, found, skipped, ssh_logins(args.ssh_log))


if __name__ == "__main__":
    main()
