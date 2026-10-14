# The web console's security model

This is about the web console when it runs as a service. The TUI, the CLI and a
`sudo stop-bots web` started by hand are one root process each, with no split: use them
from a shell you already trust, and the hand-started console over an SSH tunnel, which is
its default.

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
  It writes the web server's config and the firewall script, and runs the web server's config
  test and reload (`nginx -t`, or `apache2ctl configtest`) and `nft`. It accepts a fixed set
  of requests: apply the web server config, apply the firewall, set up Web Access, find the
  sites, check the host's health, and read the next part of the access log or of sshd's login
  lines. No request contains a path, a command or config text. Which web server it is, its
  commands, its config root and the log paths come from `/etc/stop-bots/host.conf`, which only
  root can write, not from the database.

**What someone who takes over the console can do, and what they cannot.** If an attacker gets
code running in the console, they have the `stop-bots` user and what it can reach:

- They can do what a logged-in operator can do: change the blocking policy, block or unblock
  any address, and apply. The detectors run in the console, so they can also make it block or
  unblock anything.
- They can read what the console reads: the web server's access log and sshd's authentication
  lines, through the helper, and the database with the password hash. Not the rest of `/var/log`, and
  not the journal of any other service.
- They cannot get root through the console. They cannot write to `/etc`, cron, systemd units
  or binaries, cannot ask systemd to start anything, and cannot choose what the helper runs or
  which files it writes or deletes. The helper treats the database as hostile: it finds the
  sites to change on disk, checks again everything it writes from the database, and deletes
  only the files stop-bots generated.

The helper has the sandbox the console had before 0.1: `ProtectSystem=strict`, with write
access only to the database, `/etc/stop-bots`, the web server's config root, the log
directories that config names (its config test opens them for writing) and `/run`. This stops a
write to cron, systemd units or binaries that the helper was tricked into. It does not stop
code that runs as the helper: that code is root, and root that can ask systemd to reload the
web server can ask it for more. If you later add a site that logs somewhere new, or switch web
servers, re-run `install web` so the helper's unit grants it.

Both processes yield to the host: they run at `Nice=10` with idle I/O priority, and systemd
throttles each at a quarter of RAM and stops it at half. `sudo stop-bots status` warns if the
console runs as root, if it has no helper, or if the helper cannot read a log the detectors
need.

To report a vulnerability, see
[SECURITY.md](https://github.com/ivankovic/stop-bots/blob/main/SECURITY.md).
