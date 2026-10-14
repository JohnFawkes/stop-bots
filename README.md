# Stop Bots

[![CI](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ivankovic/stop-bots/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/stop-bots.svg)](https://crates.io/crates/stop-bots)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A590%25-brightgreen)](https://github.com/ivankovic/stop-bots/blob/main/CONTRIBUTING.md#coverage)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue)](https://github.com/ivankovic/stop-bots/blob/main/LICENSE)

A TUI, a web console and a CLI that help you configure your server to stop bad bots without
hiding behind a CDN.

It works alongside NGINX and your existing firewall (nftables or iptables):

- **NGINX config.** It classifies known bots by category (scanners, search engines, AI
  crawlers) and blocks or allows them by injecting a rule into your site configs. It scans the
  NGINX log to detect bots dynamically and block them even if no ruleset tracks them yet.
- **A firewall script.** Block entire countries, datacenter IP ranges, known bot IP ranges or any
  IP address that repeatedly tries to log into your server unsuccessfully. Every block records
  why it exists.

![Each screen in sequence: Dashboard, Bot settings, Firewall, NGINX and Blocks](https://raw.githubusercontent.com/ivankovic/stop-bots/main/docs/screenshots/tour.gif)

The app tries its best to not lock you out of the server, but you use it at your own risk. And
note that it is licensed under AGPL, so if you are using it commercially, make sure you obey the
license, or [get an alternative license](#cant-use-agpl-software).

## How it compares

Stop Bots covers ground that usually takes two or three tools: blocking at the HTTP layer in
NGINX, at the IP layer in the firewall, and detection from your logs. It does this in one local
binary, with a screen to review and undo every block. It doesn't need an account or a cloud
service, and it doesn't send anything about your traffic anywhere.

- **[fail2ban](https://github.com/fail2ban/fail2ban)** and **[sshguard](https://www.sshguard.net/)**
  ban addresses from log patterns at the firewall. They cover many more services (mail, FTP,
  anything with a log line), but they don't manage NGINX bot rules and have no UI. Use one of
  them if you need protection beyond SSH and the web.
- **[CrowdSec](https://github.com/crowdsecurity/crowdsec)** detects from logs too, enforces through
  separate firewall and NGINX bouncers, and shares signals with a central API in exchange for a
  community blocklist. Its web console is a hosted service. Use it if you run a fleet, want shared
  threat intelligence or a WAF, and are happy with that architecture.
- **[NGINX Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker)**
  and **[ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt)** are curated lists, and
  Stop Bots uses both as sources. Use them directly if a static user-agent block is all you want.
- **[Anubis](https://github.com/TecharoHQ/anubis)** makes every visitor solve a proof-of-work
  challenge before reaching your app. It catches crawlers that fake their user agent and rotate
  residential addresses, which list-based blocking misses, at the cost of challenging humans and
  sometimes good bots. It complements Stop Bots rather than replacing it.
- **Cloudflare**, even on the free plan, filters bots and AI crawlers at its edge with no work
  on your server, as long as all your traffic goes through it. Stop Bots is for when you don't
  want that.

# Quick start

## Install

On Debian or Ubuntu, from the APT repository:

```
curl -fsSL https://ivankovic.github.io/stop-bots/key.gpg \
  | sudo tee /usr/share/keyrings/stop-bots.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/stop-bots.gpg] \
https://ivankovic.github.io/stop-bots stable main" \
  | sudo tee /etc/apt/sources.list.d/stop-bots.list
sudo apt update && sudo apt install stop-bots
```

Or `cargo install stop-bots` with Rust 1.88 or newer, or a static binary for `x86_64` or
`aarch64` Linux from the GitHub [releases](https://github.com/ivankovic/stop-bots/releases).
Installing starts nothing.

It is tested on **Debian and Ubuntu with systemd and NGINX**. It needs `nft`, or
`iptables-restore` and `ip6tables-restore`, for the firewall. Apache and Caddy are not
supported.

## Run it

`sudo stop-bots` starts the TUI. It needs root, because it rewrites `/etc/nginx` and loads
firewall rules. `?` shows every key on every screen.

`stop-bots web` serves the same screens in a browser, on `127.0.0.1:8787` only. Reach it from
your laptop over an SSH tunnel, `ssh -L 8787:127.0.0.1:8787 your-server`, then open
<http://127.0.0.1:8787/>. `sudo stop-bots install web` runs it as a service.

Or from the CLI, for scripts:

```
sudo stop-bots status
sudo stop-bots batch --dry-run --diff
sudo stop-bots batch --apply
sudo stop-bots install firewall
sudo stop-bots status
```

`stop-bots --help` lists every command.

## Keep it running

The detectors read your logs every minute, **but only while the TUI or the web console is
running.** On a server where neither is, let cron do it:

```
# One full pass a night. Refreshes the lists, scans the logs, applies both.
0 4 * * * root /usr/bin/stop-bots batch --apply

# And detection every ten minutes, without re-downloading lists that change weekly.
*/10 * * * * root /usr/bin/stop-bots batch --apply --no-fetch
```

## Undo

`sudo stop-bots uninstall all` puts the host back as it was. Run it with `--dry-run` first to
see every step.

# What it protects against

## In NGINX

- **Known bots**, by category (scanner, search engine, AI crawler), from
  [ArcJet's Well-Known Bots](https://github.com/arcjet/well-known-bots),
  [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) and the
  [NGINX Ultimate Bad Bot Blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker).
  Allow or block each category, and override single bots per site.
- **Too many requests**, with NGINX's own rate limiting.
- **Requests that don't look like a browser**: six separate rules per site, such as a missing
  `Accept` header or an outdated TLS version. All are off by default.
- **Politely, first**: a generated `robots.txt` listing every bot you block.

A blocked request gets a 403 by default. You can choose another status code, closing the
connection, or a tarpit that answers one byte per second.

## From your logs

Each detector is a separate switch, and each block is timed and records the log line behind it.

| Detector | Default | Blocks |
|---|---|---|
| SSH and web scanners | on | many failed SSH logins, or many different 404s |
| Forged crawlers | on | a client claiming to be Googlebot, Bingbot or GPTBot from an address that crawler doesn't use |
| Probing for secrets | on | a single request for `/.env`, `/.git/config` and the like |
| Injection attempts | on | a single request carrying an exploit, such as Shellshock or Log4Shell |
| Honeypot | off | a client that visits a path only `robots.txt` mentions |
| Fetches no assets | off | many pages, and never a stylesheet, script or image |
| Rotating user agent | off | many user agents from one address |
| Crawls with no referer | off | many deep pages, never with a `Referer` |

The last three can catch real people, which is why they are off, and none of the three ever
blocks a verified search engine.

## By address

- **Whole countries**, or everything except a list of countries.
- **Known-bad addresses**, from FireHOL level 1, Tor exit nodes and blocklist.de.
- **Whole hosting providers**: AWS, Google Cloud and DigitalOcean.
- **Anything else**, by hand.

All of these are off by default.

## Nothing happens without you

Changing a setting only changes what *would* be written. In the TUI and the console, applying
shows what would change first and asks; on the CLI, `--dry-run` shows the same. Unless you force
it, every apply refuses rules that would cut off an SSH session connected right now. Applying
automatically is a setting, and it is off.

# The web console's security model

`sudo stop-bots install web` runs the console as a service, split so that the part you log
into is not root.

**Two processes, and only one of them is root:**

- **The console**, `stop-bots-web.service`, runs as the `stop-bots` user. It writes its
  database and nothing else, and reads no host file: `/var/log` is hidden from it, and it
  gets the two logs its detectors need from the helper. It holds no Linux capability, has no
  access to netlink, so it cannot change the firewall, sees `/run` read-only, and cannot see
  systemd's sockets or D-Bus.
- **The helper**, `stop-bots-helper.service`, runs as root. systemd starts it when the console
  first connects to `/run/stop-bots/helper.sock` (`stop-bots-helper.socket`). Only root and the
  `stop-bots` group can open that socket, and the helper also checks the user of each caller.
  It writes the NGINX config and the firewall script, and runs `nginx -t`, the NGINX reload
  and `nft`. It accepts a fixed set of requests: apply NGINX, apply the firewall, set up Web
  Access, find the sites, check the host's health, and read the next part of the NGINX access
  log or of sshd's login lines. No request contains a path, a command or config text. The NGINX commands, the NGINX config root and the log paths come from
  `/etc/stop-bots/host.conf`, which only root can write, not from the database.

**What someone who takes over the console can do, and what they cannot.** If an attacker gets
code running in the console, they have the `stop-bots` user and what it can reach:

- They can do what a logged-in operator can do: change the blocking policy, block or unblock
  any address, and apply. The detectors run in the console, so they can also make it block or
  unblock anything.
- They can read what the console reads: the NGINX access log and sshd's authentication lines,
  through the helper, and the database with the password hash. Not the rest of `/var/log`, and
  not the journal of any other service.
- They cannot get root through the console. They cannot write to `/etc`, cron, systemd units
  or binaries, cannot ask systemd to start anything, and cannot choose what the helper runs or
  which files it writes or deletes. The helper treats the database as hostile: it finds the
  sites to change on disk, checks again everything it writes from the database, and deletes
  only the files stop-bots generated.

The helper has the sandbox the console had before 0.1: `ProtectSystem=strict`, with write
access only to the database, `/etc/stop-bots`, the NGINX config root, the log directories that
config names (`nginx -t` opens them for writing) and `/run`. This stops a write to cron,
systemd units or binaries that the helper was tricked into. It does not stop code that runs as
the helper: that code is root, and root that can ask systemd to reload NGINX can ask it for
more. If you later add a site that logs somewhere new, re-run `install web` so the helper's
unit grants it.

Both processes yield to the host: they run at `Nice=10` with idle I/O priority, and systemd
throttles each at a quarter of RAM and stops it at half. `sudo stop-bots status` warns if the
console runs as root, if it has no helper, or if the helper cannot read a log the detectors
need.

# Contributing

Contributions are welcome, especially bug reports. If something misbehaves, blocks the wrong
traffic or misses a bot it should have caught, please
[open an issue](https://github.com/ivankovic/stop-bots/issues). [CONTRIBUTING.md](CONTRIBUTING.md)
describes how to report a bug, how to send a change, and how the project is built, tested and
laid out. Code contributions need a one-time [Contributor License Agreement](CLA.md).

# License

Copyright (C) 2026 Marko Ivankovic

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3 of the License.

See the [LICENSE](https://github.com/ivankovic/stop-bots/blob/main/LICENSE) file for the
full text of the License.

## Can't use AGPL software?

Alternative licensing is available. If the AGPL doesn't work for you, for example because you
want to ship a modified version without publishing its source, contact me at
[marko@ivankovic.me](mailto:marko@ivankovic.me) to discuss a commercial license.
