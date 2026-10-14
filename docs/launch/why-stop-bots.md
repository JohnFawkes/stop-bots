<!--
DRAFT for Marko to edit before posting. Not part of the documentation.

Written in your voice from what the code, the README and the roadmap say.
Every factual claim about stop-bots was checked against the 0.1.1 source;
the personal framing (why you started, what your server runs) is a guess
and is marked [EDIT]. Delete this comment before publishing.
-->

# Why I built stop-bots instead of using fail2ban, CrowdSec, Cloudflare or Anubis

I run a few small sites on my own server. [EDIT: one or two lines on what they are.] Like
everyone else who does, I watched the access log fill up over the last couple of years:
scanners asking for `/.env` and `/.git/config` a hundred times a day, things claiming to be
Googlebot from addresses Google has never used, and AI crawlers fetching every page of every
site, again, every week.

None of that is new, and there are good tools for it. I used some of them. This post is about
why I ended up writing another one, and where it is worse than the alternatives, because it
is in several places.

## What I wanted

Three things, on a server I administer myself:

1. Block bots by what they are (scanner, AI crawler, search engine), from lists other people
   maintain, without hand-editing a regex in every NGINX site.
2. Catch the ones no list knows yet from my own logs, and block their addresses in the
   firewall, with a record of why.
3. See all of it in one place and undo any of it, without sending my traffic to anybody.

And one thing I did not want: a tool that edits my firewall at 3am and locks me out.

## The alternatives, honestly

**fail2ban** is the obvious answer, and for many people it is the right one. It bans
addresses from log patterns, for nearly any service. But it does nothing about user agents in
the web server, it has no idea what an AI crawler is, and writing and maintaining filters for
the web-side patterns I cared about was more work than I wanted. If you need SSH, mail and FTP
covered, keep fail2ban.

**CrowdSec** is the closest thing to what I wanted, and more capable in several ways: shared
threat intelligence, a WAF, a large catalogue of scenarios. It is also a bigger architecture
than a few sites need: an agent, separate bouncers for the firewall and NGINX, a central API
that receives your signals, and a console that is a hosted service. That is a fine trade for a
fleet. For one server I wanted a single local binary.

**Cloudflare**, even on the free plan, filters bots well and costs you no work. But all your
traffic has to go through it, and I want my sites served from my server. Stop-bots exists for
the people who made the same choice.

**Anubis** is a different and clever approach: make every visitor solve a proof-of-work
challenge before reaching the app. It catches crawlers that fake their user agent and rotate
residential addresses, which nothing based on lists or logs will. It also puts a component in
the request path and challenges real people. I see it as a complement, not a competitor; you
can run both.

## What stop-bots does

It is a TUI, a web console and a CLI over the same database. It does two things to your
server:

- It writes a blocking rule into each NGINX or Apache site, built from three public bot lists
  (ArcJet's well-known bots, ai.robots.txt and the NGINX Ultimate Bad Bot Blocker). You allow
  or block each category, and override single bots per site.
- It writes an nftables or iptables script that blocks addresses: ones its detectors found in
  your logs (SSH brute force, 404 scanning, probes for secrets, injection payloads, forged
  crawlers), and, if you want them, whole countries, reputation feeds or hosting providers.

Every block records the log line that caused it, and has a screen where you can look at it
and remove it.

## The part I spent the most time on

Most of the work was not detection. It was making it safe to point at a server you care
about.

- Nothing is applied unless you ask, and you can always see what would change first: the TUI
  and the console show it and ask, and on the CLI there is `batch --dry-run --diff`.
- Addresses that recently logged in over SSH are never blocked by a detector, and get an allow
  rule ahead of every block. An apply that would cut off an SSH session connected right now is
  refused unless you force it.
- A web server config that fails `nginx -t` is put back as it was before the reload.
- `uninstall all` takes every change back out.
- The web console, installed as a service, runs as an unprivileged user and asks a small root
  helper for the few things that need root, from a fixed list of requests.

Several of these came from running it on real servers and getting it wrong. [EDIT: these
three are from the code's own history; say whose servers they were.] The mobile apps
for Nextcloud and Jellyfin both send an `okhttp` user agent, which one public bad-bot list
blocks; they were refused for days before I noticed, which is why there is now a command that
lists who is being turned away. Another time, blocks sat detected in the database for most of
a day before the firewall script was rendered, which is why a new block now triggers a render
within minutes. And once a host ran for three weeks with tens of thousands of generated rules
and an empty kernel ruleset, which is why `stop-bots status` looks at what is actually loaded,
not at what was written.

## Where it falls short

- **No component in the request path.** It reads logs and writes config. A crawler with a
  browser's user agent, rotating through residential addresses and behaving politely, will get
  through. That is a deliberate boundary, not a backlog item; Anubis is the tool for that.
- **Debian and Ubuntu with systemd** are what is tested, with NGINX or Apache. The binaries are
  static and run elsewhere, but you would be the first.
- **No Caddy or Traefik.**
- **Behind a CDN it can do less.** If your traffic comes through Cloudflare anyway, the
  firewall half has little to block, and you need NGINX's real-IP module set up for the
  detectors to see visitors at all.
- **It only works while something runs it.** Detection runs inside the TUI or the console, or
  from cron. Applying automatically is off until you turn it on.

## Trying it

On Debian or Ubuntu there is an APT repository, and `cargo install stop-bots` works too.
Installing starts nothing. If you would rather not point it at a real server first, `make
demo` in a clone starts a throwaway container with NGINX and a log with a few bad requests in
it.

It is AGPL-3.0. Running it on your server does not make your sites AGPL.

Bug reports are what I want most, especially "it blocked something it should not have".

https://github.com/ivankovic/stop-bots

---

## For Hacker News

**Suggested title:**

> Show HN: Stop-bots – block bad bots with your own NGINX and firewall, no CDN

(Alternative: "Show HN: Stop-bots, a TUI to block scrapers and scanners from your own logs")

**Suggested first comment:**

> I built this for my own server after getting tired of hand-maintaining bot regexes and
> fail2ban filters. It blocks known bots by category in NGINX or Apache, detects scanners and
> forged crawlers from your logs, and writes an nftables or iptables script, all from one
> local binary with a TUI and a web console and no account. Most of the effort went into not
> locking you out: dry runs with diffs, an SSH guard, config tests with rollback, and a single
> `uninstall all`. It has no component in the request path, so it won't catch a crawler that
> perfectly imitates a browser, and it's tested on Debian and Ubuntu only; I'd especially like
> to hear where it blocks something it shouldn't.
