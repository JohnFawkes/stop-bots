/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use stop_bots::blocks::SourceFilter;
use stop_bots::db::{Db, FirewallAction, FirewallRule, NewFirewallRule, RuleSource};
use stop_bots::present::terminal_safe;
use stop_bots::protection::Detector;
use stop_bots::{accesslog, botlist, ipranges, nginx, say, say_err, say_inline, sshlog, webserver};

const DEFAULT_DB_PATH: &str = stop_bots::db::SYSTEM_PATH;

/// Rejects `--threshold 0` at the command line.
///
/// Every detector compares `count >= threshold`, so zero matches every
/// address in the log regardless of what it did — one flag away from
/// "block every visitor", in a tool whose whole safety story is never
/// blocking someone by mistake. One is a defensible policy (fail2ban's
/// `maxretry` goes that low); zero is not a policy, it is a mistake, and
/// an error beats silently treating it as one.
fn min_threshold(raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a whole number"))?;
    if value == 0 {
        return Err(
            "a threshold of 0 matches every address in the log, whatever it did".to_string(),
        );
    }
    Ok(value)
}

/// Parses a detector subcommand's `--ttl-days`, refusing anything past
/// `MAX_TTL_DAYS` either way. Past the ceiling, the arithmetic that dates
/// the block wraps.
///
/// Only the magnitude is bounded, unlike the TUI, which refuses anything
/// under a day: a zero or negative TTL here writes a block
/// that is born expired, which the CLI tests use to prove expiry end to
/// end, and an operator typing one has asked for exactly that.
fn ttl_days_arg(raw: &str) -> Result<i64, String> {
    let max = stop_bots::protection::MAX_TTL_DAYS;
    match raw.parse::<i64>() {
        Ok(days) if (-max..=max).contains(&days) => Ok(days),
        _ => Err(format!(
            "a block lasts a whole number of days, at most {max}"
        )),
    }
}

/// Help text for the global `--db` flag.
const DB_HELP: &str =
    "Database path. Defaults to $STOP_BOTS_DB, then /var/lib/stop-bots/db.sqlite3, \
falling back to a per-user location if that is not writable";

/// Help text shared by every `--root` flag.
const ROOT_HELP: &str = "The web server's config root. Defaults to the one stored by \
`set-web-server --root`, else /etc/nginx, or /etc/apache2 for Apache";

/// Help text shared by every detector subcommand's `--access-log`.
const ACCESS_LOG_HELP: &str = "Read this access log instead of the stored one \
(`set-log-paths`), else /var/log/nginx/access.log, or for Apache /var/log/apache2/access.log \
(/var/log/httpd/access_log in RHEL's /etc/httpd)";

/// Help text shared by `status --json` and every `list-* --json`.
const JSON_HELP: &str = "Print one JSON object instead of text. Its field names are part of \
the stable contract from 1.0: fields may be added, never renamed or removed";

/// Help text shared by every detector subcommand's `--dry-run`.
const DRY_RUN_HELP: &str = "Show what would be blocked without storing anything";

/// Help text shared by every apply's `--no-confirm`.
const NO_CONFIRM_HELP: &str = "Apply without asking to keep the new firewall rules. On a \
terminal, an apply otherwise arms a revert first and asks \"Keep these firewall rules?\"; \
no answer within --confirm-timeout puts the previous rules back. Without a terminal on stdin \
(cron, scripts) nothing is asked and nothing is armed, flag or not";

/// Help text shared by every `--confirm-timeout`.
const CONFIRM_TIMEOUT_HELP: &str =
    "Seconds to answer \"Keep these firewall rules?\" before the previous rules are put back";

/// Help text shared by every detector subcommand's `--ttl-days`.
const TTL_HELP: &str = "How many days a block lasts. Defaults to this detector's stored TTL \
(`set-detector`)";

/// Printed under the list of commands by `-h` and `--help`. The list is
/// long and flat — clap 4 has one heading for every subcommand — so this
/// is the order to read it in, for someone who has just installed it.
const GETTING_STARTED: &str = "\
Getting started:
  sudo stop-bots set-web-server apache    Only on an Apache host; NGINX is the default
  sudo stop-bots batch --dry-run --diff   Show what a full pass would change, change nothing
  sudo stop-bots batch --apply            Fetch the lists, scan the logs, apply both
  sudo stop-bots install firewall         Load the applied firewall script at boot
  sudo stop-bots install cron             Run the detectors and list updates every minute
  sudo stop-bots uninstall all --dry-run  Show every step that puts the host back

`sudo stop-bots` with no command starts the TUI. `stop-bots <command> --help` says
more about one command.";

#[derive(Parser)]
// `version` is not decoration: this ships as a tagged GitHub release
// binary, so "is the thing on the server the thing I built?" is a
// question someone will actually have to answer.
#[command(
    name = "stop-bots",
    version,
    about = "Configure your server to stop bad bots, in NGINX or Apache and the firewall",
    after_help = GETTING_STARTED
)]
struct Cli {
    // Global, so it works before or after the subcommand, and read from
    // `STOP_BOTS_DB` when not given. Every subcommand used to declare its
    // own copy; `stop-bots scan-sites --db x` still parses the same way,
    // because a global flag is accepted after the subcommand too. A `//`
    // comment rather than `///`, which clap would print as long help.
    #[arg(long, global = true, env = "STOP_BOTS_DB", value_name = "PATH", help = DB_HELP)]
    db: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

// Conventions for everything below — written down in CONTRIBUTING.md
// under "CLI conventions", and checked by the tests at the bottom of this
// file:
//
// - A stored on/off setting takes an explicit value, `--enabled
//   true|false`, so both directions can be said. A presence flag is only
//   for how *this run* behaves (`--force`, `--dry-run`, `--no-fetch`).
// - A stored setting is changed by a `set-*` verb. Flags on a verb that
//   runs something (`batch`, `render-firewall`, `run-detector`) apply to
//   that run and are never written back.
// - A list of things has `add-*`, `remove-*` and `list-*` verbs, and an
//   `update-*` verb downloads every source of its kind unless one is named.
// - Help text names commands the way a user types them (`apply-blocks`),
//   never the Rust variant (`ApplyBlocks`) or a table or module name.
#[derive(Subcommand)]
enum Command {
    /// Discover the web server's sites under a config root and store them in the database
    #[command(alias = "scan")]
    ScanSites {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
    },
    /// Download and store the known-bot lists: every source, or one.
    #[command(alias = "update")]
    UpdateBotLists {
        /// Only this source: well-known-bots, ai-robots-txt, nginx-bad-bots
        /// or stop-bots-extras. Every one without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the bot list from a local file instead of downloading it,
        /// parsed as --source-id's format (well-known-bots' when none is
        /// given, as before every source was updated by default)
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Apply the current blocking policy to every discovered site
    ApplyBlocks {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Skip reloading the web server after writing config changes (e.g. for
        /// tests, or to review the written config before it goes live).
        /// Applying is a no-op without a reload, so real usage wants this
        /// left on.
        #[arg(long)]
        no_reload: bool,
        /// Print which files would change, and change nothing but storing
        /// the bot list built into this binary
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run, also print a unified diff of every file that
        /// would change
        #[arg(long, requires = "dry_run")]
        diff: bool,
    },
    /// Add a firewall rule blocking (or allowing) an IP address or CIDR range
    AddFirewallRule {
        /// IP address or CIDR range, e.g. 1.2.3.4 or 5.6.7.0/24
        #[arg(long)]
        address: String,
        /// Restrict the rule to a single TCP port
        #[arg(long)]
        port: Option<u16>,
        /// `block` or `allow`
        #[arg(long, default_value = "block")]
        action: String,
    },
    /// Never block an address or a user agent, whatever else matches it.
    ///
    /// A trusted address (an IP or a CIDR range) becomes an allow rule
    /// ahead of every other firewall rule — a detector's block, a
    /// reputation feed, a country, the allow-list catch-all — clears every
    /// web server block and rate limit, and is skipped by the detectors.
    ///
    /// A trusted user agent clears every web server block and rate limit
    /// for any client whose user agent contains it, ignoring case. Only the
    /// web server's: a client chooses its own user agent, so letting one past the log
    /// detectors too would let any scanner past them by copying it. Trust
    /// the address for that.
    ///
    /// Takes effect after `render-firewall` (addresses) and `apply-blocks`
    /// (both), like every other change here. `remove-trusted` takes it
    /// back; `list-trusted` lists them.
    AddTrusted {
        /// An IP address or CIDR range, e.g. 203.0.113.7 or 198.51.100.0/24
        #[arg(
            long,
            required_unless_present = "user_agent",
            conflicts_with = "user_agent"
        )]
        address: Option<String>,
        /// Part of a user agent, e.g. UptimeRobot
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Stop trusting an address or a user agent added with `add-trusted`
    RemoveTrusted {
        /// The address or CIDR range, as `list-trusted` shows it
        #[arg(
            long,
            required_unless_present = "user_agent",
            conflicts_with = "user_agent"
        )]
        address: Option<String>,
        /// The user agent, as `list-trusted` shows it
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// List the user agents this host's blocking policy is turning away.
    ///
    /// Reads the web server's access log and counts, per user agent, how many
    /// requests came back with the configured block response and how many
    /// were served. A client with refusals and nothing served is being
    /// stopped at the door; one with plenty served and a few refused is
    /// being told no by the application behind the web server.
    ///
    /// Bots appearing here is the policy working. What this is for is the
    /// other kind: a first-party app matching a pattern in a public bad-bot
    /// list, which is how Nextcloud's and Jellyfin's mobile clients -- all
    /// carrying `okhttp` -- were blocked on a real host for days before
    /// anyone noticed.
    ///
    /// Allow one with `stop-bots add-trusted --user-agent`.
    ListTurnedAway {
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// List every trusted address and user agent
    ListTrusted {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// List every stored firewall rule: its id, where it came from and why.
    ///
    /// Each rule shows its source — the detector that added it, or `cli`,
    /// `tui` or `web` for one added by hand — when it was added, when it
    /// expires, and the log line that triggered it. Rules from before 0.1
    /// have no source and show `before-0.1`. Newest first.
    ListFirewallRules {
        /// Only rules from this source: a detector's name (as `set-detector`
        /// takes it), `cli`, `tui`, `web` or `before-0.1`
        #[arg(long, value_parser = source_arg)]
        source: Option<SourceFilter>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Remove a firewall rule by id, or every rule from one source.
    ///
    /// Removing a detector's block also keeps that detector from adding
    /// it straight back from the same log lines: it leaves the address
    /// alone for as long as the block was meant to last. Trust the
    /// address (`add-trusted --address`) to exempt it for good.
    #[command(group(clap::ArgGroup::new("which").required(true).args(["id", "source"])))]
    RemoveFirewallRule {
        /// The rule's id, as `list-firewall-rules` shows it
        #[arg(long)]
        id: Option<i64>,
        /// Every rule from this source instead: a detector's name, `cli`,
        /// `tui`, `web` or `before-0.1`
        #[arg(long, value_parser = source_arg)]
        source: Option<SourceFilter>,
        /// Say how many rules --source would remove, and remove nothing
        #[arg(long, requires = "source")]
        dry_run: bool,
    },
    /// Switch a stored firewall rule off or back on, without deleting it.
    ///
    /// A disabled rule stays in the list, marked "(disabled)", and is left
    /// out of the next script `render-firewall` writes. Like every rule
    /// change, it takes effect once that script is applied.
    SetFirewallRule {
        /// The rule's id, as `list-firewall-rules` shows it
        #[arg(long)]
        id: i64,
        /// Whether the rule is rendered into the firewall script
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Write the firewall rules to a script for you to review and apply.
    ///
    /// Renders every stored rule into an nftables or iptables script, plus
    /// the rules derived from blocked crawler IP ranges, switched-on
    /// reputation feeds and the geo selection (see `set-geo-mode` and
    /// `add-country`). Derived rules are computed fresh on each render and
    /// never stored.
    ///
    /// Without --apply this only writes the script, to
    /// /etc/stop-bots/firewall.next.nft (or firewall.next.sh), which
    /// nothing loads. Review it, then run `render-firewall --apply`: that
    /// runs it and copies it to /etc/stop-bots/firewall.nft (or
    /// firewall.sh), the script `install firewall` loads at boot. `batch
    /// --apply` and "Apply everything" in the TUI do the same.
    ///
    /// Before writing anything, checks recent successful SSH logins (from
    /// /var/log/auth.log, /var/log/secure or journalctl) against every
    /// address about to be blocked, simulating the same first-match-wins
    /// order the script itself will evaluate. If any currently-connected
    /// client would be cut off, it refuses to write the script. If no SSH
    /// log could be read, it writes the script but refuses to apply it.
    /// --force overrides both.
    ///
    /// Allowlist geo mode needs the nftables backend: iptables has no
    /// loopback/established-connection allowance and silently permits all
    /// IPv6 (it skips IPv6 rules entirely), both fatal once a trailing
    /// "block everything else" rule is in play.
    RenderFirewall {
        /// Which firewall to write for. Defaults to the backend this host
        /// is set to (`set-firewall-backend`), which is nftables unless
        /// changed.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// Write the script to this file instead, for you to review or run
        /// yourself; nothing loads it at boot. With --apply it names the
        /// applied script instead, as `batch --out` does, and the script is
        /// written beside it as <name>.next.<ext>
        #[arg(long)]
        out: Option<PathBuf>,
        /// Run the script once it is written, if the lockout check allows,
        /// and make it the script loaded at boot
        #[arg(long)]
        apply: bool,
        /// Write, and with --apply run, the script even if it would block
        /// an IP with a recent successful SSH login, or no SSH log could be
        /// read to check
        #[arg(long)]
        force: bool,
        /// Check this SSH log file instead of auto-detecting one — for a
        /// non-standard log location, or a container where the real logs
        /// aren't at their usual path
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = NO_CONFIRM_HELP)]
        no_confirm: bool,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
    /// Put back the firewall rules from before the last apply.
    ///
    /// While an apply is waiting to be kept ("Keep these firewall rules?"),
    /// this reverts it now: the applied script, which an unconfirmed apply
    /// leaves alone, is loaded again — or, if there was none, the
    /// stop-bots nft table or iptables chains are deleted. The timer an
    /// interactive apply arms runs exactly this when nobody answers.
    ///
    /// With nothing waiting, it goes back to /etc/stop-bots/firewall.prev.nft
    /// (or .prev.sh), the applied script the last apply replaced, and swaps
    /// the two, so running it again goes forward again.
    RevertFirewall {
        /// The backend, for going back to the previous script. Defaults to
        /// the stored one; a waiting apply knows its own.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// The applied script. Defaults to /etc/stop-bots/firewall.nft, or
        /// firewall.sh for iptables
        #[arg(long)]
        out: Option<PathBuf>,
        /// Only revert the apply armed with this token (what the timer
        /// passes), and do nothing if it was kept
        #[arg(long, hide = true)]
        token: Option<String>,
        /// Wait this many seconds first: the timer, where there is no
        /// systemd to run it
        #[arg(long, hide = true, requires = "token")]
        after: Option<u64>,
    },
    /// Choose which firewall this host generates scripts for.
    ///
    /// Read by `render-firewall`, `batch`, the internal cron, `status` and
    /// `install firewall` whenever they are not told otherwise. The TUI's
    /// render popup sets the same value.
    SetFirewallBackend {
        /// nftables (the default) or iptables
        #[arg(long)]
        backend: FirewallBackend,
    },
    /// Run one detector over a log now, and block what it finds.
    ///
    /// Reads the whole log given (or the one stored with `set-log-paths`,
    /// or the usual place), runs the detector over it with its stored
    /// settings unless overridden here, and stores a block for each address
    /// it convicts. The schedule (`tick`, the TUI) runs the same detectors
    /// on its own, over each detector's window; this is for a log you want
    /// judged once, by hand.
    ///
    /// A stored block has no effect until the firewall script is applied
    /// (`render-firewall --apply`, `batch --apply`, or "Apply everything"),
    /// so this is safe to run unattended. Addresses that logged in over SSH,
    /// trusted ones, private ones, and those inside a verified crawler's
    /// published ranges are never blocked.
    ///
    /// ssh-scanners reads the SSH log; every other detector reads the web
    /// server's access log. spoofed-crawlers needs the crawler ranges
    /// (`update-crawler-ranges`), and honeypot and robots-violators need the
    /// generated robots.txt served (`set-robots-txt --enabled true`).
    RunDetector {
        /// Which detector, as `list-detectors` names it
        detector: DetectorArg,
        /// How much evidence from one address before it is blocked, for the
        /// detectors that count (ssh-scanners, web-scanners, asset-ratio,
        /// rotating-ua, refererless, login-attempts, request-rate). A count
        /// over the whole log given, except for request-rate, which takes
        /// requests a minute over its window, ending where the log ends.
        /// Defaults to the stored threshold (`set-detector`). Must be at
        /// least 1.
        #[arg(long, value_parser = min_threshold)]
        threshold: Option<usize>,
        #[arg(long, value_parser = ttl_days_arg, help = TTL_HELP)]
        ttl_days: Option<i64>,
        /// Read this SSH log file instead of auto-detecting one
        /// (ssh-scanners only)
        #[arg(long, conflicts_with = "access_log")]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
        #[arg(long, help = DRY_RUN_HELP)]
        dry_run: bool,
    },
    /// Set the extra probe paths, on top of the built-in list.
    ///
    /// Replaces the extra paths the probe-paths detector checks. The built-in
    /// list is never removable — switch the detector off instead. One path
    /// per line; blank lines and `#` comments are ignored. Each is looked
    /// for anywhere in the request path, so every entry must start with
    /// `/`, which keeps it to the start of a path segment, and must name
    /// something after it.
    SetProbePaths {
        /// Newline-separated paths. Pass an empty string to clear.
        #[arg(long)]
        paths: String,
    },
    /// List every probe path currently checked, built-in and extra
    ListProbePaths {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Set the honeypot trap path.
    ///
    /// Pick something that does *not* sound valuable: a path like `/admin`
    /// or `/backup` would also be guessed by scanners that never read
    /// robots.txt, which turns a precise "ignored robots.txt" signal into
    /// just another probe path.
    SetHoneypotPath {
        /// The trap path. Must start with `/`, and contain only characters
        /// a URL path spells literally.
        #[arg(long)]
        path: String,
    },
    /// List every detector with its switch, TTL and threshold.
    ///
    /// These are the settings the internal cron and `batch` run the
    /// detectors with. Change them with `set-detector`, and IPv4 /24
    /// escalation with `set-subnet-escalation`.
    ListDetectors {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Switch a detector on or off, and set its TTL, threshold and window.
    ///
    /// These are what the schedule (`stop-bots tick`, or the TUI while it
    /// is open) and `batch` use. Switching a detector off stops it adding
    /// blocks; it never removes the ones it already added, which expire on
    /// their own. Give no flags to print the detector's current settings.
    ///
    /// Only the detectors that count something take a threshold:
    /// ssh-scanners, web-scanners, asset-ratio, rotating-ua, refererless,
    /// login-attempts and request-rate. For the others one matching request
    /// is conclusive.
    ///
    /// robots-txt cannot be switched here: it runs exactly when "humans
    /// only" is on (`set-humans-only`).
    SetDetector {
        /// Which detector
        detector: DetectorArg,
        /// Whether it runs
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: Option<bool>,
        /// How many days each block it adds lasts, from 1 to 3650
        #[arg(long)]
        ttl_days: Option<i64>,
        /// How much evidence from one address before it is blocked: failed
        /// logins, 404'd paths, pages without assets, user agents,
        /// referer-less pages, login attempts or, for request-rate, requests
        /// a minute, depending on the detector. At least 2.
        #[arg(long)]
        threshold: Option<i64>,
        /// How far back evidence counts, in hours, from 1 to 720: a log
        /// line older than this is no reason to block. 24 unless changed,
        /// and 1 for asset-ratio, rotating-ua, refererless, login-attempts
        /// and request-rate.
        #[arg(long)]
        window_hours: Option<i64>,
        /// probe-paths only: also count /wp-login.php, /phpmyadmin and the
        /// other paths of an application where no site runs it
        /// (`list-probe-paths` shows each, and why). On for a database
        /// created by a release that has it; off on one an earlier release
        /// created, until you turn it on.
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        app_aware: Option<bool>,
    },
    /// Block a whole IPv4 /24 when several of its addresses are flagged.
    ///
    /// When on, a detector that flags at least --min addresses in one IPv4
    /// /24 in the same pass blocks the /24 instead. Off by default:
    /// blocking 256 addresses because three misbehaved is collateral by
    /// design. IPv6 needs no switch: a detection always blocks the /64,
    /// which is one network, the same as one IPv4 address.
    SetSubnetEscalation {
        /// Whether to escalate
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: Option<bool>,
        /// Flagged addresses in one /24 before it escalates. At least 2,
        /// and 3 unless changed.
        #[arg(long)]
        min: Option<i64>,
    },
    /// Block repeat offenders for longer.
    ///
    /// When on, a detector that blocks an address again after its earlier
    /// block ended doubles the block: twice the detector's TTL for the
    /// second offence, four times for the third, and eight times from the
    /// fourth on, but never more than 90 days (or the detector's own TTL,
    /// if that is longer). An address is forgotten 30 days after its last
    /// block ends, or when you unblock it by hand. Trusted addresses and
    /// addresses that log in over SSH are never blocked, so never counted.
    ///
    /// On for a database created by a release that has it; off on one an
    /// earlier release created, until you turn it on.
    SetRepeatOffenders {
        /// Whether repeat offenders are blocked for longer
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Tally which user agents are getting through successfully.
    ///
    /// Reads the web server's access log and adds up, per user agent, the requests
    /// that were answered successfully (anything but 4xx and 5xx) — a view
    /// of who is actually visiting, next to the detectors' view of who is
    /// misbehaving. Additive across runs: re-reading an overlapping or
    /// rotated log adds onto each user agent's count rather than resetting
    /// it.
    RecordAccessStats {
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
    },
    /// List recorded user-agent hit counts, most-seen first
    ListAccessStats {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Prune stale rows and compact the database.
    ///
    /// Drops user-agent statistics not seen in 90 days (and any excess over
    /// 20,000 rows, least recently seen first), clears lapsed firewall
    /// rules, and rewrites the file to hand free pages back to the
    /// filesystem if enough has accumulated to be worth it. The internal
    /// cron does this daily on its own. This runs it now, which is what a
    /// host that has already grown wants, and what a host with no `sqlite3`
    /// installed has no other way to do.
    Maintain {
        /// Compact the file even when there is little to reclaim. The
        /// scheduled job weighs that up for itself; this overrides it
        #[arg(long)]
        force_compact: bool,
    },
    /// Download the crawlers' published IP ranges: every crawler, or one.
    ///
    /// Downloads and stores the current CIDR lists Googlebot, Bingbot and
    /// GPTBot publish. A blocked category blocks its crawler's ranges in
    /// the firewall, and the spoofed-crawlers detector checks claims
    /// against them.
    UpdateCrawlerRanges {
        /// Only this crawler: googlebot, bingbot or gptbot. Every one
        /// without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "source_id")]
        source: Option<PathBuf>,
    },
    /// Download third-party CIDR feeds: every one switched on, or one.
    ///
    /// Downloads and stores a reputation list (firehol-level1, tor-exits,
    /// blocklist-de) or a cloud provider's published address space (aws,
    /// google-cloud, digitalocean). Without --source-id, every feed that is
    /// switched on. Fetching does *not* switch a feed on — see
    /// `set-reputation-source` — so refreshing a feed you deliberately
    /// disabled never silently re-enables it.
    UpdateReputationSources {
        /// Only this feed: firehol-level1, tor-exits, blocklist-de, aws,
        /// google-cloud or digitalocean. Every feed switched on without it
        #[arg(long)]
        source_id: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "source_id")]
        source: Option<PathBuf>,
    },
    /// Switch a third-party CIDR feed on or off.
    ///
    /// While on, every range it holds is blocked in the next script
    /// `render-firewall` writes. Nothing is added to the stored rule list,
    /// the same as crawler and country ranges.
    ///
    /// All feeds are off by default. Note what the cloud-provider ones
    /// actually do: they block *every* visitor hosted at that provider,
    /// including VPN endpoints, corporate egress and API clients — not
    /// just bots. Unlike the behavioural detectors there's no evidence
    /// involved, and a wrongly-blocked visitor has no way to tell you.
    ///
    /// In Blocklist geo mode a cloud-provider feed leaves TCP port 80 open,
    /// because Let's Encrypt validates from AWS: with it closed, no
    /// certificate on this host renews over HTTP.
    SetReputationSource {
        /// Which feed, as `list-reputation-sources` names it
        #[arg(long)]
        source_id: String,
        /// Whether its ranges are blocked
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// List the third-party CIDR feeds.
    ///
    /// Lists every third-party CIDR feed with its on/off state and how many
    /// ranges it currently holds.
    ListReputationSources {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Download country IP ranges: every selected country, or one.
    ///
    /// Downloads and stores IPdeny's current aggregated CIDR lists. One
    /// named with --country is not selected by this — see `add-country`.
    UpdateCountryRanges {
        /// Only this country, by its two-letter code, e.g. "us" or "nl".
        /// Every selected country without it
        #[arg(long)]
        country: Option<String>,
        /// Read the list from a local file instead of downloading it
        /// (parsed as this source's format). For a host with no outbound
        /// access — and what makes this path testable offline
        #[arg(long, requires = "country")]
        source: Option<PathBuf>,
    },
    /// Set the geo mode: blocklist or allowlist.
    ///
    /// "blocklist" (the default) blocks the selected countries and allows
    /// everything else; "allowlist" allows only the selected countries and
    /// blocks everything else. Switching modes doesn't touch the
    /// selected-country list itself, only how `render-firewall` reads it.
    SetGeoMode {
        /// blocklist or allowlist
        #[arg(long)]
        mode: GeoModeArg,
    },
    /// Add a country to the geo selection.
    ///
    /// Adds a country to the host-wide geo selection (fetch its ranges
    /// first with `update-country-ranges`). What this means depends on the
    /// geo mode — see `set-geo-mode`.
    AddCountry {
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// Remove a country from the host-wide geo selection
    RemoveCountry {
        /// Two-letter country code, e.g. "us" or "nl"
        #[arg(long)]
        country: String,
    },
    /// List the current geo mode and every selected country
    ListSelectedCountries {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Block a hosting provider's whole network, by its AS number.
    ///
    /// Every range the network announces is blocked in the next script
    /// `render-firewall` writes, like a cloud-provider feed: every visitor
    /// hosted there is turned away, not just bots — VPN endpoints, company
    /// networks and API clients included — and port 80 stays open for
    /// Let's Encrypt unless `set-cloud-port-80` closes it.
    ///
    /// `list-hosting-asns` names the providers on the built-in list, but any
    /// AS number is accepted. Nothing is downloaded by this: run
    /// `update-hosting-asns` for the ranges.
    AddHostingAsn {
        /// The AS number, e.g. 24940 or AS24940 (Hetzner)
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: u32,
    },
    /// Stop blocking a hosting provider's network, and forget its ranges
    RemoveHostingAsn {
        /// The AS number, as `list-hosting-asns` shows it
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: u32,
    },
    /// List the hosting providers that can be blocked by AS number.
    ///
    /// Every provider on the built-in list and every other AS number
    /// selected, with whether it is blocked and how many ranges it holds.
    ListHostingAsns {
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Download the blocked hosting providers' ranges: every one, or one.
    ///
    /// Downloads iptoasn.com's public table of which network announces which
    /// range (about 9 MB) once, and keeps the ranges of every AS number
    /// selected with `add-hosting-asn`. The rest of the table is not kept.
    UpdateHostingAsns {
        /// Only this AS number, which must be selected. Every selected one
        /// without it
        #[arg(long, value_parser = stop_bots::ipranges::hosting::parse_asn)]
        asn: Option<u32>,
        /// Read the table from a local file instead of downloading it: an
        /// ip2asn TSV, gzipped or plain. For a host with no outbound access
        /// — and what makes this path testable offline
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Set whether a category of bots is allowed or blocked.
    ///
    /// Without --site this is the host-wide default for the category:
    /// every bot in it follows it unless `set-bot` overrides that bot.
    /// With --site it overrides the default for that one site; `--policy
    /// default` removes the override again.
    ///
    /// Only changes what would be written: run `apply-blocks` to put it
    /// into the web server's config. While "humans only" is on, every category is
    /// blocked whatever is stored here.
    SetCategory {
        /// scanner, search or ai
        #[arg(long)]
        category: CategoryArg,
        /// allowed, blocked, or (with --site) default
        #[arg(long)]
        policy: PolicyArg,
        /// Override the policy for this site only, by its server_name
        #[arg(long)]
        site: Option<String>,
    },
    /// List the category policies, host-wide or for one site
    ListCategories {
        /// Show this site's overrides too, by its server_name
        #[arg(long)]
        site: Option<String>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Allow or block one bot, whatever its category says.
    ///
    /// Without --site this is the host-wide status of the bot; `--policy
    /// default` makes it follow its category again. With --site it
    /// overrides the bot for that one site only.
    ///
    /// Find a bot's slug with `list-bots`. Run `apply-blocks` afterwards to
    /// write the change into the web server's config.
    SetBot {
        /// The bot's slug, as `list-bots` shows it
        #[arg(long)]
        bot: String,
        /// allowed, blocked, or default
        #[arg(long)]
        policy: PolicyArg,
        /// Override the bot for this site only, by its server_name
        #[arg(long)]
        site: Option<String>,
    },
    /// List every known bot with its categories and status
    ListBots {
        /// Only bots whose slug or name contains this, ignoring case
        #[arg(long)]
        search: Option<String>,
        #[arg(long, help = JSON_HELP)]
        json: bool,
    },
    /// Turn NGINX rate limiting on or off, and set its parameters.
    ///
    /// When on, `apply-blocks` writes a `limit_req_zone` to
    /// /etc/nginx/conf.d/stop-bots-limits.conf (it has to live in `http`
    /// context, so it can't go in the per-site block) and adds a
    /// `limit_req ... burst=N nodelay; limit_req_status 429;` to each
    /// site. NGINX then does the enforcement itself, at request time —
    /// unlike everything else here, no log analysis is involved.
    ///
    /// Off by default: a limit tuned for the wrong site turns away real
    /// visitors, and unlike a bot-pattern block there's no user agent to
    /// inspect afterwards to work out who was caught.
    ///
    /// NGINX only: Apache has no request-rate limit of its own, and on an
    /// Apache host this setting writes nothing.
    SetRateLimit {
        /// Whether rate limiting is written into the site configs
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
        /// Sustained requests per second per client address. Generous by
        /// default (10): one page load can easily fire a dozen requests
        /// for assets.
        #[arg(long)]
        rps: Option<i64>,
        /// How many requests may exceed the rate before any are refused.
        #[arg(long)]
        burst: Option<i64>,
    },
    /// Switch one request-shape rule on or off for a site.
    ///
    /// Each rule turns away requests that don't look like a browser's, and
    /// each is off by default, one switch per rule so that if something of
    /// yours stops working you can tell which rule did it. Run
    /// `apply-blocks` afterwards to write it into the site config.
    SetSiteRule {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// One of http-1x, no-accept, no-accept-language, no-user-agent,
        /// ip-literal-host, old-tls
        #[arg(long)]
        rule: String,
        /// Whether requests the rule matches are turned away
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Exempt a path prefix from a site's blocking rules.
    ///
    /// Adds a request-path prefix that a site's blocking rules don't apply
    /// to. Run `apply-blocks` afterwards to write it into the site config.
    /// `remove-exempt-path` takes it back.
    AddExemptPath {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// The path prefix. Must start with `/`.
        #[arg(long)]
        path: String,
        /// Exempt only clients whose user agent contains this, ignoring
        /// case — e.g. `okhttp` for an app whose HTTP library a bot list
        /// blocks. Matched against the resolved path, so `..` cannot walk
        /// out of the exempt prefix.
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Remove a path exemption added with `add-exempt-path`.
    ///
    /// Give the same --site, --path and --user-agent it was added with. Run
    /// `apply-blocks` afterwards to write the change into the site config.
    RemoveExemptPath {
        /// The site's server_name, as `scan-sites` discovered it
        #[arg(long)]
        site: String,
        /// The path prefix. Must start with `/`.
        #[arg(long)]
        path: String,
        /// The user agent it was limited to, if it was
        #[arg(long)]
        user_agent: Option<String>,
    },
    /// Turn generation of a robots.txt on or off.
    ///
    /// When on, `apply-blocks` writes one to /etc/stop-bots/nginx/robots.txt
    /// (/etc/stop-bots/apache/robots.txt on Apache) and has each site serve
    /// it, with a `location = /robots.txt` block on NGINX or an `Alias` on
    /// Apache: one `User-agent:` line per currently-blocked bot under a shared
    /// `Disallow: /`, plus a `Disallow:` for the honeypot trap path.
    ///
    /// Off by default, because it *replaces* whatever the site already
    /// serves at /robots.txt — which may be hand-written and carry rules
    /// this tool knows nothing about.
    ///
    /// This is the polite layer under the 403, for the crawlers that
    /// honour it, and it is also what makes the honeypot work at all.
    SetRobotsTxt {
        /// Whether the robots.txt is generated and served
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Turn automatic applying of the web server's config on or off.
    ///
    /// When on, the schedule (`stop-bots tick` from `install cron`, or the
    /// TUI while it is open — not this command) re-writes every site's generated block and
    /// reloads the web server once an hour, whenever they have fallen behind the
    /// database. That happens constantly on a busy host: every user agent
    /// a detector blocks changes the generated block, which puts every
    /// site back to STALE within the minute.
    ///
    /// Off by default. It reloads a live web server with nobody watching,
    /// which is not something an upgrade should start doing on its own.
    ///
    /// The web server's config only. The firewall script has its own
    /// switch, `set-auto-apply-firewall`.
    SetAutoApply {
        /// Whether the internal cron applies the web server's config
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Turn automatic applying of the firewall script on or off.
    ///
    /// Separate from `set-auto-apply`, and separately off by default,
    /// because the risks are not comparable: a bad web server config is
    /// caught by its config test (`nginx -t`, `apache2ctl configtest`) and
    /// costs a failed reload, while a bad firewall
    /// ruleset locks you out of the host and no care taken here can undo
    /// that remotely.
    ///
    /// When on, the internal cron runs the script it renders instead of
    /// only writing it — but it refuses to apply unless the anti-lockout
    /// check actually ran. The interactive paths treat "the SSH log could
    /// not be read" as a pass, which is reasonable while a person is
    /// reading the result; unattended it is not, so this refuses. If the
    /// cron reports that, point `--ssh-log` at a readable log.
    ///
    /// An automatic apply is not asked about afterwards, as one from the
    /// TUI or a terminal is ("Keep these firewall rules?"): there is
    /// nobody to answer, so nothing is armed to revert it.
    SetAutoApplyFirewall {
        /// Whether the internal cron runs the firewall script
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Keep port 80 open in the cloud-provider feeds, for Let's Encrypt.
    ///
    /// Let's Encrypt fetches an http-01 challenge from several places, and
    /// all but one are in AWS. With this on, which it is by default, the
    /// AWS, Google Cloud and DigitalOcean feeds and the hosting providers
    /// blocked by AS number (`add-hosting-asn`) block every port but TCP 80,
    /// so certbot's `nginx`, `apache`, `webroot` and `standalone` plugins
    /// keep renewing. Turn it off on a host that renews over DNS, or has no
    /// certificate, to block those ranges on port 80 as well. Allowlist geo
    /// mode never opens the port.
    #[command(name = "set-cloud-port-80")]
    SetCloudPort80 {
        /// Whether the cloud-provider feeds and hosting providers leave port
        /// 80 open
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Check every firewall apply against the addresses that log in over SSH.
    ///
    /// On by default. Every apply, by hand or by cron, is refused when its
    /// rules would block an address that logged in over SSH in the last
    /// week, or the session it runs in. When no one has logged in for a
    /// week, an apply whose rules block every address not listed
    /// (Allowlist, Only trusted IPs) is refused too, as it would block
    /// whoever connects next.
    ///
    /// Turn it off on a server you never log into over SSH, such as one you
    /// reach through your provider's console. Addresses that do log in are
    /// still let through ahead of every block; only the check is skipped.
    #[command(name = "set-ssh-lockout-check")]
    SetSshLockoutCheck {
        /// Whether applies are checked against SSH logins
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Serve humans and nothing else.
    ///
    /// Blocks every catalogued bot whatever its category, and gives any
    /// address that fetches /robots.txt a one-day block.
    ///
    /// The three category policies are forced to Blocked while this is on
    /// and cannot be edited, but their stored values are untouched — turn
    /// this off and they come back. Let's Encrypt is the one bot still
    /// allowed, because blocking it breaks certificate renewal in a way
    /// that only surfaces two months later.
    SetHumansOnly {
        /// Whether humans-only mode is on
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Block the user agents of browsers too old for anyone to still run.
    ///
    /// Opera 5 to 12, Firefox 1 to 9, Chrome 1 to 39, Internet Explorer 2
    /// to 9, feature phones (NetFront, UP.Browser, J2ME, Symbian,
    /// BlackBerry OS) and the like: the strings scanners rotate through to
    /// look like people, which no bot list can carry because none of them
    /// is a bot's name. One switch for every site, off by default, because
    /// a few are still a person somewhere (Opera Mini sends `Opera/9.80`).
    /// Humans only does not turn it on.
    SetOldBrowsers {
        /// Whether old browser agents are blocked
        #[arg(long, value_name = "true|false", action = clap::ArgAction::Set)]
        enabled: bool,
    },
    /// Print the robots.txt that would be generated now, without writing it
    ShowRobotsTxt,
    /// Set what the web server sends a blocked request.
    ///
    /// These are not interchangeable status codes; each says something
    /// different, and the difference matters most for clients caught by
    /// mistake. "forbidden" (403, the default) is the only one that tells
    /// a wrongly-caught human what happened. "not-found" (404) hides that
    /// anything was blocked. "gone" (410) is the one that asks a
    /// well-behaved crawler to drop the URL permanently — prefer it over
    /// 403 when you're turning away crawlers rather than attackers.
    /// "too-many-requests" (429) tells a polite client to retry later.
    /// "teapot" (418) is RFC 2324's joke — it works, but it is
    /// not IANA-registered and NGINX sends it with an empty body.
    /// "close" (444) sends nothing at all, which is cheapest but
    /// indistinguishable from the server being down. "tarpit" answers 403
    /// but throttles the body to a byte per second, holding the client's
    /// connection open — and one of yours.
    ///
    /// "teapot", "close" and "tarpit" are NGINX's: on Apache each is a
    /// 403.
    ///
    /// Host-wide, and only changes what *would* be written: run
    /// `apply-blocks` afterwards to get the new response into the site
    /// configs. Until then every applied site shows as STALE.
    SetBlockResponse {
        /// What a blocked request gets back
        #[arg(long)]
        response: BlockResponseArg,
    },
    /// Remember where this host's logs actually are.
    ///
    /// The companion to `set-web-server`, for the other half of a
    /// containerised web server. A container that
    /// bind-mounts its log directory writes the access log somewhere that
    /// is not /var/log/nginx/access.log (or /var/log/apache2/access.log) on
    /// the host, and `--access-log` on a
    /// single command cannot reach the two things that actually run the
    /// detectors: `stop-bots tick` and the TUI take no arguments for it, so
    /// the schedule reads the default and finds nothing.
    ///
    /// A path given here is used whenever no flag overrides it. Pass an
    /// empty string to clear one. Give neither flag to print what is
    /// stored.
    SetLogPaths {
        /// The web server's access log every web-side detector reads.
        #[arg(long)]
        access_log: Option<String>,
        /// The SSH authentication log, feeding the SSH scanner detector
        /// and the anti-lockout window.
        #[arg(long)]
        ssh_log: Option<String>,
    },
    /// Set the commands used to test and reload NGINX, and its config root.
    ///
    /// NGINX only. `set-web-server` takes the same flags for either
    /// server, Apache included.
    ///
    /// Defaults are `nginx -t` and `systemctl reload nginx`, which is what
    /// a normal host install needs. Change them when NGINX is not a
    /// service on this host — the case that motivated this is NGINX in a
    /// container with its config on a bind mount, where the files are ours
    /// to edit but there is no unit to reload:
    ///
    ///   --test "docker exec web nginx -t"
    ///   --reload "docker exec web nginx -s reload"
    ///
    /// The command is split into words and run directly. It is never
    /// handed to a shell, so `;`, `|`, `&&`, globs and `$VAR` are ordinary
    /// characters in an argument rather than syntax. Quote an argument
    /// that genuinely contains a space.
    ///
    /// Pass no flag to print the commands currently in effect.
    #[command(hide = true)]
    SetNginxCommands {
        /// The config check. Must exit non-zero on a bad config.
        #[arg(long)]
        test: Option<String>,
        /// The reload.
        #[arg(long)]
        reload: Option<String>,
        /// Where this host's site configs live, when that is not
        /// /etc/nginx — an NGINX in a container with its config on a bind
        /// mount being the case this exists for. Stored, so it no longer
        /// has to be repeated on scan-sites, apply-blocks, batch and tui,
        /// where forgetting it scanned an empty /etc/nginx and reported
        /// success.
        #[arg(long)]
        root: Option<PathBuf>,
        /// Restore all three to their defaults.
        #[arg(long, conflicts_with_all = ["test", "reload", "root"])]
        reset: bool,
    },
    /// Choose the web server whose sites this host protects.
    ///
    /// `nginx` is the default, and what every host was before there was a
    /// choice. `apache` reads `<VirtualHost>` sections under /etc/apache2,
    /// blocks with mod_rewrite (`a2enmod rewrite` if it is off), and tests
    /// and reloads with `apache2ctl configtest` and `systemctl reload
    /// apache2`. Stored in the host settings, so every command and the TUI
    /// follow it.
    ///
    /// Also takes the server's own commands and config root, for a server
    /// that is not where a stock install puts it. On RHEL and its relatives, whose Apache
    /// reads conf.d and logs to /var/log/httpd:
    ///
    ///   set-web-server apache --root /etc/httpd --test "apachectl configtest" --reload "systemctl reload httpd"
    ///
    ///   set-log-paths --access-log /var/log/httpd/access_log
    ///
    /// Refused while the web server chosen now still has stop-bots in its
    /// config: take that out first with `uninstall web-server`.
    ///
    /// Pass no server to print what is in effect.
    SetWebServer {
        /// `nginx` or `apache`.
        #[arg(value_parser = parse_web_server)]
        server: Option<webserver::WebServer>,
        /// The config check. Must exit non-zero on a bad config.
        #[arg(long, requires = "server")]
        test: Option<String>,
        /// The reload.
        #[arg(long, requires = "server")]
        reload: Option<String>,
        /// Where this host's site configs live, when that is not where a
        /// stock install puts them.
        #[arg(long, requires = "server")]
        root: Option<PathBuf>,
        /// Restore the server's commands and root to their defaults.
        #[arg(long, requires = "server", conflicts_with_all = ["test", "reload", "root"])]
        reset: bool,
    },
    /// Report whether this host is actually protected.
    ///
    /// Every other check in this tool compares what it would generate
    /// against what is on disk. This one looks at the kernel, the units
    /// and the filesystem — the gap that let a host run for three weeks
    /// with 48,860 generated rules and an empty ruleset.
    ///
    /// Exits 1 if anything is CRITICAL and 0 otherwise, so it is usable
    /// from a monitoring check. `--quiet` prints only what needs
    /// attention, which is the form to put in cron.
    Status {
        /// Read this SSH log instead of auto-detecting one
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Print only checks that need attention
        #[arg(long)]
        quiet: bool,
        /// Use the last probe the internal cron took instead of looking at
        /// the host now. Cheap, and what the dashboards show.
        #[arg(long)]
        cached: bool,
        /// Print every check as one JSON object instead of text; the exit
        /// status is the same. Its field names are part of the stable
        /// contract from 1.0: fields may be added, never renamed or removed
        #[arg(long, conflicts_with = "quiet")]
        json: bool,
    },
    /// One unattended pass over everything, for a real cron entry.
    ///
    /// Refreshes every list, scans the logs, writes the web server's
    /// blocking rules and the firewall script — and, with --apply, puts both into
    /// effect.
    ///
    /// Without --apply nothing is enforced: the config and the script are
    /// written and left alone, which is inert (config does nothing until a
    /// reload, a script does nothing until it is run). That is this
    /// project's default everywhere else and stays the default here.
    ///
    /// With --apply, the SSH lockout guard refuses — and refusing means
    /// nothing is applied — if the rules would block a currently-connected
    /// client, *or* if no SSH log could be read at all so the check could
    /// not run. That is the same line every other apply draws. Pass
    /// --ssh-log if the log isn't where this expects, or --force if you
    /// know what you're doing.
    ///
    /// The script is written to /etc/stop-bots/firewall.next.nft (or
    /// .next.sh) and copied to firewall.nft, the file the boot unit loads,
    /// only once it has been applied. --dry-run prints what would change
    /// and changes nothing.
    ///
    /// Refreshes bot lists and crawler IP ranges in full, and reputation
    /// feeds and country ranges only where they are switched on or
    /// selected. Runs every detector that is switched on, with its stored
    /// TTL and threshold (`list-detectors`). One step's failure never stops
    /// the others; the exit status is non-zero if any of them failed, which
    /// is what makes cron mail you.
    Batch {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Reload the web server and run the generated firewall script, rather than
        /// only writing both
        #[arg(long)]
        apply: bool,
        /// The applied firewall script: what an apply replaces, and what the
        /// boot unit loads. The script is written beside it as
        /// <name>.next.<ext>. Defaults to /etc/stop-bots/firewall.nft, or
        /// firewall.sh for iptables — which generates a shell script, not an
        /// nftables one
        #[arg(long)]
        out: Option<PathBuf>,
        /// Which firewall to generate for. Defaults to whichever backend
        /// this host is set to (`set-firewall-backend`) — a crontab that
        /// silently disagreed with it used to leave two scripts on disk, in
        /// two syntaxes, at two paths, one of them stale.
        #[arg(long)]
        backend: Option<FirewallBackend>,
        /// Read this SSH log file instead of auto-detecting one. Worth
        /// setting explicitly under cron: on a journald-only host,
        /// `journalctl` can come back empty, which is the case --apply
        /// refuses on
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, help = ACCESS_LOG_HELP)]
        access_log: Option<PathBuf>,
        /// Apply even if the lockout guard objects, or could not run
        #[arg(long)]
        force: bool,
        /// Skip every step that downloads something — for a host with no
        /// outbound access, or a second, more frequent cron entry that
        /// only wants the log scan and the apply (bot lists change weekly;
        /// an access log changes every second)
        #[arg(long)]
        no_fetch: bool,
        /// Print a line per step, not just the failures. With --dry-run,
        /// also print the diffs --diff prints
        #[arg(long, short)]
        verbose: bool,
        /// Print what the web server and firewall steps would change — the
        /// files, the rules added and removed against the applied script,
        /// the lockout check's verdict — and change nothing: nothing is
        /// downloaded, scanned, written, applied or recorded. The one
        /// exception is the bot list built into this binary, which is
        /// stored first, as every other command that renders web server
        /// config does
        #[arg(long)]
        dry_run: bool,
        /// With --dry-run, also print a unified diff of every file that
        /// would change, the firewall script included
        #[arg(long, requires = "dry_run")]
        diff: bool,
        #[arg(long, help = NO_CONFIRM_HELP)]
        no_confirm: bool,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
    /// Keep this host protected with nobody at a terminal.
    ///
    /// `install cron` writes /etc/cron.d/stop-bots, which runs `stop-bots
    /// tick` once a minute: the detectors each minute and the lists weekly,
    /// the same schedule the TUI runs while it is open. It writes what the
    /// detectors find, and applies it only as far as `set-auto-apply` and
    /// `set-auto-apply-firewall` allow; both are off until you turn them on.
    ///
    /// `install firewall` writes a systemd unit that loads the applied
    /// firewall script at boot.
    ///
    /// Nothing is written until every check has passed, a file you have
    /// edited is left alone rather than replaced, and --dry-run prints the
    /// whole plan without touching anything. Start there.
    Install {
        /// What to install: `cron`, the schedule, or `firewall`, the unit
        /// that loads the applied firewall script at boot.
        #[arg(value_enum)]
        target: InstallTarget,
        /// Print every step and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Replace a file even if it has been edited since stop-bots wrote
        /// it. An unedited one, from any version, is replaced without this.
        #[arg(long)]
        force: bool,
        /// The stop-bots binary the cron file runs. Defaults to the one
        /// running this command, which is refused if it sits in a build
        /// directory — a cron file pointing into target/debug works until
        /// the next `cargo clean`.
        #[arg(long)]
        binary: Option<PathBuf>,
        /// Install into this prefix instead of `/`. For inspecting the
        /// result without root; a file written under a prefix is one that
        /// cron and systemd never see, so this runs no `systemctl`.
        #[arg(long)]
        prefix: Option<PathBuf>,
    },
    /// Remove stop-bots from this host and put it back as it was.
    ///
    /// Stops and removes every unit it installed, deletes the live nft table or
    /// iptables chain, takes the injected blocks out of every site of the
    /// web server the host settings choose (tested with `nginx -t` or
    /// `apache2ctl configtest`, put back if that fails, then reloaded), and
    /// deletes the generated web server files and firewall scripts. Every
    /// step is reported, a failed one does not stop the rest, and any
    /// failure makes the exit status non-zero.
    ///
    /// The database is kept, with every setting and rule, and so is the
    /// `stop-bots` user that owns it, unless --purge is given; the output
    /// says where it is. Needs root, except with
    /// --prefix. Run it with --dry-run first.
    Uninstall {
        /// What to remove: `nginx` (also spelled `web-server`, and on an
        /// Apache host it is Apache's blocks it removes), `firewall`, `cron`,
        /// or `all` (the default), which is all three plus /etc/stop-bots
        /// itself.
        #[arg(value_enum, default_value = "all")]
        target: UninstallTarget,
        /// Print every step and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also delete the database and the copies upgrades kept of it.
        /// Only with `all`.
        #[arg(long)]
        purge: bool,
        /// Remove from this prefix instead of `/`, as `install --prefix`
        /// wrote it. Nothing outside it is touched, and no systemctl, nft,
        /// iptables or web server test or reload is run.
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
    },
    /// Write the man pages and shell completions for packaging
    ///
    /// Hidden: the release pipeline runs it, and the `.deb` ships what it
    /// writes. Not part of the command line people use.
    #[command(hide = true)]
    GenerateDocs {
        /// The directory to write `man/` and `completions/` into
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
    },
    /// Run whatever is due on the schedule, once, and exit.
    ///
    /// What `install cron` runs every minute: the jobs the TUI's Dashboard
    /// lists under Scheduled tasks, each only when it is due, so a minute
    /// with nothing due costs one database read. It applies to the web
    /// server and the firewall only what `set-auto-apply` and
    /// `set-auto-apply-firewall` allow. Prints nothing unless a job could
    /// not be recorded or --verbose is given, so cron mails only trouble.
    /// A run while another is still going leaves at once.
    Tick {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Read this SSH log file instead of the stored one or the search
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        /// Print what each job that ran did
        #[arg(long, short)]
        verbose: bool,
    },
    /// Start the TUI (also the default when run with no subcommand)
    Tui {
        #[arg(long, help = ROOT_HELP)]
        root: Option<PathBuf>,
        /// Skip reloading the web server after its screen applies blocking
        /// rules (e.g. for tests driving the TUI end to end against a
        /// throwaway fixture root, where there's no real server to reload)
        #[arg(long)]
        no_reload: bool,
        /// Read this SSH log file instead of auto-detecting one — the same
        /// override every SSH-reading CLI subcommand already takes, and for
        /// the same two audiences: a host with a non-standard log location,
        /// and tests, where auto-detection would otherwise shell out to
        /// `journalctl` on every refresh of the Firewall screen
        #[arg(long)]
        ssh_log: Option<PathBuf>,
        #[arg(long, value_name = "SECS", default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..), help = CONFIRM_TIMEOUT_HELP)]
        confirm_timeout: u64,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum InstallTarget {
    /// /etc/cron.d/stop-bots, which runs `stop-bots tick` every minute.
    Cron,
    /// A systemd unit that re-applies the rendered firewall script at
    /// boot. Not `nftables.service`: that loads /etc/nftables.conf, which
    /// is a different file, and on a stock Debian or Ubuntu it flushes
    /// every other table on the host first.
    Firewall,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UninstallTarget {
    /// The blocks in every site, the generated conf.d (or Apache's
    /// conf-enabled) files and /etc/stop-bots/nginx (or apache), for the
    /// web server the host settings choose.
    #[value(alias = "web-server")]
    Nginx,
    /// The live nft table or iptables chain, the boot unit and the
    /// firewall scripts.
    Firewall,
    /// /etc/cron.d/stop-bots.
    Cron,
    /// All of the above, and /etc/stop-bots once it is empty.
    All,
}

impl From<UninstallTarget> for stop_bots::uninstall::Target {
    fn from(target: UninstallTarget) -> Self {
        match target {
            UninstallTarget::Nginx => Self::Nginx,
            UninstallTarget::Firewall => Self::Firewall,
            UninstallTarget::Cron => Self::Cron,
            UninstallTarget::All => Self::All,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum FirewallBackend {
    Iptables,
    Nftables,
}

#[derive(Clone, Copy, ValueEnum)]
enum GeoModeArg {
    Blocklist,
    Allowlist,
}

impl From<GeoModeArg> for stop_bots::db::GeoMode {
    fn from(arg: GeoModeArg) -> Self {
        match arg {
            GeoModeArg::Blocklist => stop_bots::db::GeoMode::Blocklist,
            GeoModeArg::Allowlist => stop_bots::db::GeoMode::Allowlist,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CategoryArg {
    /// Vulnerability and SEO scanners
    Scanner,
    /// Search-engine crawlers
    Search,
    /// AI crawlers and assistants
    Ai,
}

impl From<CategoryArg> for stop_bots::db::Category {
    fn from(arg: CategoryArg) -> Self {
        use stop_bots::db::Category as C;
        match arg {
            CategoryArg::Scanner => C::Scanner,
            CategoryArg::Search => C::Search,
            CategoryArg::Ai => C::Ai,
        }
    }
}

/// `allowed`, `blocked`, or `default` — "follow whatever is above me",
/// which is the category for a bot and the host-wide policy for a site
/// override.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PolicyArg {
    Allowed,
    Blocked,
    /// Follow the category (for a bot) or the host-wide policy (for a
    /// site override)
    Default,
}

impl PolicyArg {
    /// `None` for `default`, which every override API spells as "no
    /// override".
    fn policy(self) -> Option<stop_bots::db::Policy> {
        match self {
            PolicyArg::Allowed => Some(stop_bots::db::Policy::Allowed),
            PolicyArg::Blocked => Some(stop_bots::db::Policy::Blocked),
            PolicyArg::Default => None,
        }
    }
}

/// A detector as the command line names it.
///
/// The stored ids (`block_scanners`, ...) are settings keys and cron-job
/// ids that can never change; these are the names a person types, and
/// the stored id is accepted too, as a hidden alias.
#[derive(Clone, Copy)]
struct DetectorArg(stop_bots::protection::Detector);

impl DetectorArg {
    const ALL: [DetectorArg; stop_bots::protection::Detector::ALL.len()] = {
        let all = stop_bots::protection::Detector::ALL;
        let mut out = [DetectorArg(all[0]); stop_bots::protection::Detector::ALL.len()];
        let mut i = 0;
        while i < all.len() {
            out[i] = DetectorArg(all[i]);
            i += 1;
        }
        out
    };

    /// The name `set-detector` and `--source` both take — one list, in
    /// `blocks::detector_name`, so the two can never disagree.
    fn name(self) -> &'static str {
        stop_bots::blocks::detector_name(self.0)
    }
}

impl ValueEnum for DetectorArg {
    fn value_variants<'a>() -> &'a [Self] {
        &Self::ALL
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(
            clap::builder::PossibleValue::new(self.name())
                .help(self.0.spec().label)
                .alias(self.0.id()),
        )
    }
}

/// Named rather than numeric (`--response forbidden`, not `--response
/// 403`): "444" means nothing without knowing NGINX's non-standard codes,
/// and a bare number invites passing an arbitrary one this tool doesn't
/// support.
#[derive(Clone, Copy, ValueEnum)]
enum BlockResponseArg {
    /// 403 — says the block was deliberate
    Forbidden,
    /// 404 — hides that anything was blocked
    NotFound,
    /// 410 — asks well-behaved crawlers to drop the URL for good
    Gone,
    /// 429 — tells a polite client to back off and retry
    TooManyRequests,
    /// 418 — a joke (RFC 2324); unregistered, and sends an empty body
    Teapot,
    /// 444 — close without replying at all
    Close,
    /// A 403 whose body is throttled to one byte per second
    Tarpit,
}

impl From<BlockResponseArg> for stop_bots::db::BlockResponse {
    fn from(arg: BlockResponseArg) -> Self {
        use stop_bots::db::BlockResponse as R;
        match arg {
            BlockResponseArg::Forbidden => R::Forbidden,
            BlockResponseArg::NotFound => R::NotFound,
            BlockResponseArg::Gone => R::Gone,
            BlockResponseArg::TooManyRequests => R::TooManyRequests,
            BlockResponseArg::Teapot => R::Teapot,
            BlockResponseArg::Close => R::Close,
            BlockResponseArg::Tarpit => R::Tarpit,
        }
    }
}

/// Runs the command, and prints its error the way returning it from
/// `main` would (`Error: ` and anyhow's chain, exit status 1), except
/// through [`stop_bots::present::terminal_safe_text`]. An error quotes
/// what it failed on: a site's server name, a path, a value read from the
/// database or a log, any of which the unprivileged console or a client
/// could have chosen.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            say_err!("Error: {err:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Spellings of the command line that still work but are on their way
/// out: the old verb (and, for a few, a flag that used to change what it
/// did), and what it is now. Each is rewritten to the new spelling before
/// parsing, with a warning on stderr, so the old one cannot drift from the
/// new one. They go in 2.0.0 (see "Versioning" in `RELEASING.md`).
///
/// `(old verb, flag that selects this row or "", new verb, words inserted
/// after it)`.
const DEPRECATED: &[(&str, &str, &str, &[&str])] = &[
    ("block-ssh-scanners", "", "run-detector", &["ssh-scanners"]),
    ("block-scanners", "", "run-detector", &["ssh-scanners"]),
    ("block-web-scanners", "", "run-detector", &["web-scanners"]),
    (
        "block-spoofed-crawlers",
        "",
        "run-detector",
        &["spoofed-crawlers"],
    ),
    ("block-probe-paths", "", "run-detector", &["probe-paths"]),
    ("block-honeypot", "", "run-detector", &["honeypot"]),
    ("trust", "--remove", "remove-trusted", &[]),
    ("trust", "", "add-trusted", &[]),
    ("exempt-path", "--remove", "remove-exempt-path", &[]),
    ("exempt-path", "", "add-exempt-path", &[]),
    ("update-ip-ranges", "", "update-crawler-ranges", &[]),
    (
        "update-reputation-source",
        "",
        "update-reputation-sources",
        &[],
    ),
];

/// `args` with a deprecated spelling (see [`DEPRECATED`]) rewritten to the
/// current one, and the warning to print, if there was one.
fn undeprecate(mut args: Vec<std::ffi::OsString>) -> (Vec<std::ffi::OsString>, Option<String>) {
    // The verb is the first word that is neither a flag nor the value of
    // the one global flag that takes a value.
    let mut at = None;
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].to_string_lossy();
        if arg == "--db" {
            i += 2;
            continue;
        }
        if !arg.starts_with('-') {
            at = Some(i);
            break;
        }
        i += 1;
    }
    let Some(at) = at else {
        return (args, None);
    };
    let verb = args[at].to_string_lossy().into_owned();
    let row = DEPRECATED.iter().find(|(old, flag, _, _)| {
        *old == verb && (flag.is_empty() || args[at + 1..].iter().any(|a| a == *flag))
    });
    let Some((old, flag, new, insert)) = row else {
        return (args, None);
    };
    if !flag.is_empty() {
        args.retain(|a| a != *flag);
    }
    let replacement: Vec<std::ffi::OsString> = std::iter::once(new.into())
        .chain(insert.iter().map(Into::into))
        .collect();
    args.splice(at..=at, replacement);
    let was = if flag.is_empty() {
        (*old).to_string()
    } else {
        format!("{old} {flag}")
    };
    let now = std::iter::once(*new)
        .chain(insert.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    (args, Some(deprecation(&was, &now)))
}

/// The one line a deprecated spelling prints.
fn deprecation(was: &str, now: &str) -> String {
    format!("warning: `{was}` is deprecated, use `{now}`; it will be removed in 2.0.0")
}

/// Prints [`deprecation`] for a spelling that is still its own command.
fn deprecated(was: &str, now: &str) {
    say_err!("{}", deprecation(was, now));
}

async fn run() -> Result<()> {
    let (args, warning) = undeprecate(std::env::args_os().collect());
    if let Some(warning) = warning {
        say_err!("{warning}");
    }
    let cli = Cli::parse_from(args);
    // A one-shot command's output is often piped into something that stops
    // reading early (`| head`). Rust ignores SIGPIPE, so the next write is
    // an error, and `say!` (`println!` underneath) turns that into a panic.
    // Dying quietly, the default, is what every other command-line tool
    // does. Not for the TUI: it writes to a terminal, where a peer going
    // away is an error to handle, not the end of the process.
    // Nothing a one-shot command runs writes to a child's stdin, which is
    // the other place the signal could come from.
    if !matches!(cli.command, None | Some(Command::Tui { .. })) {
        // SAFETY: called before any thread this program starts writes to a
        // pipe, and SIG_DFL is async-signal-safe to install.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }
    // Moved into whichever arm runs; only one does.
    let db = cli.db;

    match cli.command {
        // No flags to pass, so the stored root is the only way this form
        // can be right on a host whose config is not in /etc/nginx.
        None => run_tui(db, None, false, None, stop_bots::revert::DEFAULT_TIMEOUT).await,
        Some(Command::Tui {
            root,
            no_reload,
            ssh_log,
            confirm_timeout,
        }) => {
            let timeout = std::time::Duration::from_secs(confirm_timeout);
            run_tui(db, root, no_reload, ssh_log, timeout).await
        }
        Some(Command::Install {
            target,
            dry_run,
            force,
            binary,
            prefix,
        }) => match target {
            InstallTarget::Cron => run_install_cron(db, binary, prefix, dry_run, force),
            InstallTarget::Firewall => run_install_firewall(binary, prefix, dry_run, force),
        },
        Some(Command::Tick {
            root,
            ssh_log,
            verbose,
        }) => run_tick(db, root, ssh_log, verbose).await,
        Some(Command::Uninstall {
            target,
            dry_run,
            purge,
            prefix,
            root,
        }) => run_uninstall(db, target, dry_run, purge, prefix, root),
        Some(Command::Status {
            ssh_log,
            quiet,
            cached,
            json,
        }) => run_status(db, ssh_log, quiet, cached, json),
        Some(Command::Batch {
            root,
            apply,
            out,
            backend,
            ssh_log,
            access_log,
            force,
            no_fetch,
            verbose,
            dry_run,
            diff,
            no_confirm,
            confirm_timeout,
        }) => {
            let request = BatchRequest {
                root,
                out,
                backend,
                apply,
                ssh_log,
                access_log,
                force,
                no_fetch,
                confirm: confirm_with(apply && !dry_run, no_confirm, confirm_timeout),
            };
            if dry_run {
                preview_batch(db, request, diff || verbose)
            } else {
                run_batch(db, request, verbose).await
            }
        }
        Some(Command::ScanSites { root }) => scan_sites(root.as_deref(), db),
        Some(Command::UpdateBotLists { source_id, source }) => {
            update_bot_lists(db, source_id, source).await
        }
        Some(Command::ApplyBlocks {
            root,
            no_reload,
            dry_run,
            diff,
        }) => {
            if dry_run {
                preview_apply_blocks(root.as_deref(), db, diff)
            } else {
                apply_blocks(root.as_deref(), db, no_reload)
            }
        }
        Some(Command::AddFirewallRule {
            address,
            port,
            action,
        }) => add_firewall_rule(db, address, port, &action),
        Some(Command::ListFirewallRules { source, json }) => list_firewall_rules(db, source, json),
        Some(Command::RemoveFirewallRule {
            id,
            source,
            dry_run,
        }) => remove_firewall_rule(db, id, source, dry_run),
        Some(Command::SetFirewallRule { id, enabled }) => set_firewall_rule(db, id, enabled),
        Some(Command::RenderFirewall {
            backend,
            out,
            apply,
            force,
            ssh_log,
            no_confirm,
            confirm_timeout,
        }) => render_firewall(
            db,
            RenderRequest {
                backend,
                out,
                apply,
                force,
                ssh_log,
                confirm: confirm_with(apply, no_confirm, confirm_timeout),
            },
        ),
        Some(Command::RevertFirewall {
            backend,
            out,
            token,
            after,
        }) => revert_firewall(db, backend, out, token, after),
        Some(Command::SetFirewallBackend { backend }) => set_firewall_backend(db, backend),
        Some(Command::RunDetector {
            detector,
            threshold,
            ttl_days,
            ssh_log,
            access_log,
            dry_run,
        }) => run_detector(
            db, detector.0, threshold, ttl_days, ssh_log, access_log, dry_run,
        ),
        Some(Command::SetProbePaths { paths }) => set_probe_paths(db, paths),
        Some(Command::ListProbePaths { json }) => list_probe_paths(db, json),
        Some(Command::SetHoneypotPath { path }) => set_honeypot_path(db, path),
        Some(Command::ListDetectors { json }) => list_detectors(db, json),
        Some(Command::SetDetector {
            detector,
            enabled,
            ttl_days,
            threshold,
            window_hours,
            app_aware,
        }) => set_detector(
            db,
            detector,
            DetectorChanges {
                enabled,
                ttl_days,
                threshold,
                window_hours,
                app_aware,
            },
        ),
        Some(Command::SetRepeatOffenders { enabled }) => set_repeat_offenders(db, enabled),
        Some(Command::SetSubnetEscalation { enabled, min }) => {
            set_subnet_escalation(db, enabled, min)
        }
        Some(Command::RecordAccessStats { access_log }) => record_access_stats(db, access_log),
        Some(Command::ListAccessStats { json }) => list_access_stats(db, json),
        Some(Command::Maintain { force_compact }) => maintain(db, force_compact),
        Some(Command::UpdateCrawlerRanges { source_id, source }) => {
            update_crawler_ranges(db, source_id, source).await
        }
        Some(Command::UpdateReputationSources { source_id, source }) => {
            update_reputation_sources(db, source_id, source).await
        }
        Some(Command::SetReputationSource { source_id, enabled }) => {
            set_reputation_source(db, source_id, enabled)
        }
        Some(Command::ListReputationSources { json }) => list_reputation_sources(db, json),
        Some(Command::UpdateCountryRanges { country, source }) => {
            update_country_ranges(db, country, source).await
        }
        Some(Command::SetGeoMode { mode }) => set_geo_mode(db, mode),
        Some(Command::AddCountry { country }) => set_country_selected(db, country, true),
        Some(Command::RemoveCountry { country }) => set_country_selected(db, country, false),
        Some(Command::ListSelectedCountries { json }) => list_selected_countries(db, json),
        Some(Command::AddHostingAsn { asn }) => add_hosting_asn(db, asn),
        Some(Command::RemoveHostingAsn { asn }) => remove_hosting_asn(db, asn),
        Some(Command::ListHostingAsns { json }) => list_hosting_asns(db, json),
        Some(Command::UpdateHostingAsns { asn, source }) => {
            update_hosting_asns(db, asn, source).await
        }
        Some(Command::SetCategory {
            category,
            policy,
            site,
        }) => set_category(db, category, policy, site),
        Some(Command::ListCategories { site, json }) => list_categories(db, site, json),
        Some(Command::SetBot { bot, policy, site }) => set_bot(db, bot, policy, site),
        Some(Command::ListBots { search, json }) => list_bots(db, search, json),
        Some(Command::SetLogPaths {
            access_log,
            ssh_log,
        }) => run_set_log_paths(db, access_log, ssh_log),
        Some(Command::SetNginxCommands {
            test,
            reload,
            root,
            reset,
        }) => {
            deprecated("set-nginx-commands", "set-web-server nginx");
            set_nginx_commands(db, test, reload, root, reset)
        }
        Some(Command::SetWebServer {
            server,
            test,
            reload,
            root,
            reset,
        }) => set_web_server(
            db,
            server,
            ServerSettings {
                test,
                reload,
                root,
                reset,
            },
        ),
        Some(Command::SetBlockResponse { response }) => set_block_response(db, response),
        Some(Command::SetRateLimit {
            enabled,
            rps,
            burst,
        }) => set_rate_limit(db, enabled, rps, burst),
        Some(Command::SetSiteRule {
            site,
            rule,
            enabled,
        }) => set_site_rule(db, site, rule, enabled),
        Some(Command::AddExemptPath {
            site,
            path,
            user_agent,
        }) => exempt_path(db, site, path, user_agent, false),
        Some(Command::RemoveExemptPath {
            site,
            path,
            user_agent,
        }) => exempt_path(db, site, path, user_agent, true),
        Some(Command::AddTrusted {
            address,
            user_agent,
        }) => trust(db, address, user_agent, false),
        Some(Command::RemoveTrusted {
            address,
            user_agent,
        }) => trust(db, address, user_agent, true),
        Some(Command::ListTurnedAway { access_log, json }) => {
            list_turned_away(db, access_log, json)
        }
        Some(Command::ListTrusted { json }) => list_trusted(db, json),
        Some(Command::SetRobotsTxt { enabled }) => set_robots_txt(db, enabled),
        Some(Command::SetAutoApply { enabled }) => set_auto_apply(db, enabled),
        Some(Command::SetAutoApplyFirewall { enabled }) => set_auto_apply_firewall(db, enabled),
        Some(Command::SetCloudPort80 { enabled }) => set_cloud_port_80(db, enabled),
        Some(Command::SetSshLockoutCheck { enabled }) => set_ssh_lockout_check(db, enabled),
        Some(Command::SetHumansOnly { enabled }) => set_humans_only(db, enabled),
        Some(Command::SetOldBrowsers { enabled }) => set_old_browsers(db, enabled),
        Some(Command::ShowRobotsTxt) => show_robots_txt(db),
        Some(Command::GenerateDocs { out }) => {
            use clap::CommandFactory;
            for path in stop_bots::docs::generate(Cli::command(), &out)? {
                say!("{}", path.display());
            }
            Ok(())
        }
    }
}

/// Resolves and opens the database. An explicit `--db` is always honored
/// as-is, even if opening it fails — silently substituting a path the user
/// asked for would be worse than just erroring. Without one, tries the
/// system location first and falls back to a per-user location if that
/// isn't writable: `/var/lib` typically needs root, which actually applying
/// nginx/firewall changes needs anyway, but just exploring with `cargo run`
/// or the TUI shouldn't require it.
fn open_db(explicit: Option<PathBuf>) -> Result<Db> {
    let db = match explicit {
        Some(path) => Db::open(path)?,
        None => open_default_db()?,
    };
    migrate_host_settings(&db)?;
    Ok(db)
}

/// Moves the host settings out of the database into their own file, the
/// first time a root process opens one (see [`stop_bots::hostconf`]). A
/// no-op for anyone else, and once the file exists.
fn migrate_host_settings(db: &Db) -> Result<()> {
    let path = stop_bots::hostconf::path();
    let migrated = stop_bots::hostconf::migrate(db, &path)?;
    if let Some(note) = migrated.note(&path) {
        say_err!("{note}");
    }
    Ok(())
}

/// The host settings: the NGINX commands and root, and the logs.
fn host_settings() -> Result<stop_bots::hostconf::HostConf> {
    stop_bots::hostconf::HostConf::load()
}

/// How the host's web server is named in what a command prints — "NGINX"
/// or "Apache" — for a command with no host settings of its own at hand.
/// A `host.conf` that cannot be read is NGINX here, as it is everywhere
/// that asks [`webserver::WebServer::configured`]: a sentence is no place
/// to fail a command that has already done its work.
fn server_label() -> &'static str {
    webserver::WebServer::configured().label()
}

fn open_default_db() -> Result<Db> {
    open_or_fallback(Path::new(DEFAULT_DB_PATH), user_db_path)
}

/// Tries to create `primary`'s parent directory and open it as the
/// database; only if that directory can't even be created does it fall
/// back to whatever `fallback` resolves to (printing a note about which
/// path was used). `fallback` is a closure, not an already-resolved path,
/// so resolving it (which can itself fail, e.g. if neither `XDG_DATA_HOME`
/// nor `HOME` is set) never gets in the way of the common case where
/// `primary` just works — important for e.g. a root-run container with a
/// minimal environment, where `/var/lib` is perfectly writable but `HOME`
/// might not be set at all.
///
/// Deliberately narrow: this does *not* fall back on every kind of
/// failure, e.g. the directory existing but its database file being
/// corrupt, or owned by someone else and unreadable. Falling back in those
/// cases would hand back a fresh, empty database that's easy to mistake for
/// "no data yet" instead of surfacing the real problem — the dev-ergonomics
/// win this exists for is specifically "the system directory doesn't exist
/// and I can't create it", not "something is wrong with the system db".
fn open_or_fallback(primary: &Path, fallback: impl FnOnce() -> Result<PathBuf>) -> Result<Db> {
    let parent = primary
        .parent()
        .with_context(|| format!("{} has no parent directory", primary.display()))?;
    // 0700 if this creates it: whichever call makes the directory decides
    // its mode, and this one runs before `Db::open` gets the chance.
    if let Err(dir_err) = stop_bots::db::create_private_dir_all(parent) {
        let fallback = fallback()?;
        say_err!(
            "Note: couldn't create {} ({dir_err}); using {} instead.",
            parent.display(),
            fallback.display()
        );
        return Db::open(&fallback).with_context(|| {
            format!(
                "failed to create {} ({dir_err}) and failed to open the fallback database at {}",
                parent.display(),
                fallback.display()
            )
        });
    }
    Db::open(primary)
}

/// The per-user fallback database location, following the XDG Base
/// Directory spec (`$XDG_DATA_HOME`, or `~/.local/share` if that's unset).
fn user_db_path() -> Result<PathBuf> {
    resolve_user_db_path(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))
}

/// Pure resolution logic for [`user_db_path`], taking the relevant env vars
/// as parameters so it's testable without mutating real process env vars
/// (which would race with other tests in this binary).
fn resolve_user_db_path(
    xdg_data_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let data_home = xdg_data_home
        .map(PathBuf::from)
        .or_else(|| home.map(|home| PathBuf::from(home).join(".local/share")))
        .context(
            "could not determine a per-user data directory: neither XDG_DATA_HOME nor HOME is set",
        )?;
    Ok(data_home.join("stop-bots").join("db.sqlite3"))
}

/// Blanks the screen before the TUI's first frame.
///
/// `ratatui::init` enters the alternate screen, which normally comes up
/// blank — but a terminal that ignores the request (a `TERM` without
/// `smcup`, tmux with `alternate-screen off`) leaves the shell's scrollback
/// where it is. That would be cosmetic if the first frame painted over it,
/// and it doesn't: ratatui diffs each frame against the previous one, and
/// the first is diffed against a buffer that is already blank, so none of
/// the frame's blank cells are transmitted and the old text shows through
/// every gap.
///
/// Deliberately not `Terminal::clear`, which snapshots the cursor position
/// first — a `\x1b[6n` query that blocks until the terminal answers, and
/// errors out after a timeout on any terminal that doesn't. There is no
/// cursor position worth preserving here.
// The TUI's own escape sequence, written where ratatui writes its frames.
#[allow(clippy::disallowed_methods)]
fn clear_screen() -> Result<()> {
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
    )
    .context("failed to clear the terminal")
}

async fn run_tui(
    db_path: Option<PathBuf>,
    root: Option<PathBuf>,
    no_reload: bool,
    ssh_log: Option<PathBuf>,
    confirm_timeout: std::time::Duration,
) -> Result<()> {
    let defaulted = db_path.is_none();
    let db = open_db(db_path)?;
    stop_bots::firewall::seed_backend(&db, stop_bots::firewall::Installed::detect())?;
    let root = webserver::root(&host_settings()?, root.as_deref());
    let notice = stop_bots::db::location_notice(db.path().as_deref(), defaulted);
    let mut app = stop_bots::app::App::new(db, root, !no_reload, ssh_log)?;
    app.db_notice = notice;
    app.confirm_timeout = confirm_timeout;
    let terminal = ratatui::init();
    // Not `?`: bailing here would skip the `restore` below and leave the
    // terminal in raw mode.
    let result = match clear_screen() {
        Ok(()) => app.run(terminal).await,
        Err(err) => Err(err),
    };
    ratatui::restore();
    result
}

/// Runs one batch pass and turns its report into output and an exit
/// status.
///
/// Quiet on success on purpose: this is built to sit in a crontab, and
/// `cron` mails the owner anything a job prints. A nightly run that says
/// nothing is a nightly run nobody has to read. `--verbose` prints every
/// step, which is what a first run by hand wants.
///
/// Failures go to stderr and set a non-zero exit status, so they are
/// visible whichever way the job is wired up.
/// Where `batch` writes its firewall script when not told otherwise.
///
/// Prints the health report, and exits non-zero if anything is critical.
///
/// The exit status is the point: this is meant to go in a monitoring check
/// or a crontab, where nobody reads the output until something is wrong.
fn run_status(
    db_path: Option<PathBuf>,
    ssh_log: Option<PathBuf>,
    quiet: bool,
    cached: bool,
    json: bool,
) -> Result<()> {
    use stop_bots::health::{self, Level};

    let db = open_db(db_path)?;
    let (report, taken_at) = if cached {
        match health::cached_report(&db)? {
            Some((report, at)) => (report, Some(at)),
            None => anyhow::bail!(
                "no health probe has been recorded yet — run `stop-bots status` without \
                 --cached, or `stop-bots install cron` so the schedule takes one"
            ),
        }
    } else {
        // The list built into this binary, stored first, as every command
        // that renders the web server's config stores it: whether a site
        // is applied is judged against what an apply would write, and after
        // an upgrade that includes what this binary added to the list.
        botlist::register_all_sources(&db)?;
        let backend = stop_bots::firewall::stored_backend(&db)?;
        let path = db
            .path()
            .unwrap_or_else(|| PathBuf::from("./stop-bots.sqlite3"));
        let block_status = db.get_block_response()?.status_code();
        let probe = health::probe(
            backend,
            &path,
            ssh_log.as_deref(),
            &host_settings()?,
            block_status,
            stop_bots::scanblock::crawler_claims(&db)?,
        );
        health::store_probe(&db, &probe)?;
        (health::assess(&db, &probe)?, None)
    };

    if json {
        stop_bots::output::print(&stop_bots::output::Status::new(&report, taken_at))?;
        return exit_status(&report);
    }

    let shown: Vec<_> = if quiet {
        report.at_least(Level::Warn)
    } else {
        report.checks.iter().collect()
    };

    let notes = revert_notes(&db)?;
    if quiet && shown.is_empty() && notes.is_empty() {
        return Ok(());
    }

    say!("{}", report.headline());
    for note in notes {
        say!("{note}");
    }
    if let Some(at) = taken_at {
        say!("(from a probe taken {})", stop_bots::present::ago(at));
    }
    say!();

    for check in shown {
        say!("  [{}] {}", check.level.tag(), check.title);
        say!("      {}", check.detail);
        if let Some(fix) = &check.fix {
            say!("      -> {fix}");
        }
    }
    say!();

    exit_status(&report)
}

/// `status`'s exit status, the same with `--json` as without: an error,
/// and so 1, when anything is critical.
fn exit_status(report: &stop_bots::health::Report) -> Result<()> {
    if report.worst() == stop_bots::health::Level::Critical {
        // `bail!` rather than `exit(1)`: it prints the reason, and the
        // reason is the whole value of a non-zero status here.
        anyhow::bail!("this host is not protected the way it is configured to be");
    }
    Ok(())
}

/// What `status` says about confirm-or-revert: an apply waiting to be
/// kept, and a revert in the last day.
fn revert_notes(db: &Db) -> Result<Vec<String>> {
    let backend = stop_bots::firewall::stored_backend(db)?;
    let applied = stop_bots::firewall::default_output_path(backend);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let mut notes = Vec::new();
    if let Some(pending) = stop_bots::revert::waiting(&applied, now) {
        notes.push(format!(
            "A firewall apply is waiting to be kept: the previous rules come back in {} s \
             unless it is (`stop-bots revert-firewall` puts them back now).",
            pending.seconds_left(now)
        ));
    }
    if let Some((at, message)) = stop_bots::revert::last_reverted(&applied) {
        if now - at < 86_400 {
            notes.push(format!("{message}, {}.", stop_bots::present::ago(at)));
        }
    }
    Ok(notes)
}

/// `batch`'s arguments as the command line gives them, before the two
/// that depend on the database have been resolved.
///
/// Separate from [`stop_bots::batch::BatchOptions`] because resolving them
/// needs an open database and parsing does not: the backend falls back to
/// whatever this host is set to, and the output path falls out of
/// whichever backend that turns out to be.
struct BatchRequest {
    root: Option<PathBuf>,
    out: Option<PathBuf>,
    backend: Option<FirewallBackend>,
    apply: bool,
    ssh_log: Option<PathBuf>,
    access_log: Option<PathBuf>,
    force: bool,
    no_fetch: bool,
    /// Confirm-or-revert's timeout, when the firewall apply asks.
    confirm: Option<std::time::Duration>,
}

/// The timeout to confirm an apply in, when this run asks at all: an
/// apply, with a terminal on stdin to answer from, and no `--no-confirm`.
/// Everything else — cron above all — applies as it always did.
fn confirm_with(apply: bool, no_confirm: bool, secs: u64) -> Option<std::time::Duration> {
    use std::io::IsTerminal;
    (apply && !no_confirm && std::io::stdin().is_terminal())
        .then(|| std::time::Duration::from_secs(secs))
}

async fn run_batch(db_path: Option<PathBuf>, request: BatchRequest, verbose: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let host = host_settings()?;
    let request = BatchRequest {
        root: Some(webserver::root(&host, request.root.as_deref())),
        ..request
    };

    let (backend, out) = firewall_target(&db, request.backend, request.out)?;
    let options = stop_bots::batch::BatchOptions {
        root: request.root.expect("resolved above"),
        out,
        backend,
        apply: request.apply,
        ssh_log: request.ssh_log,
        access_log: request.access_log,
        force: request.force,
        no_fetch: request.no_fetch,
        confirm: request.confirm,
        host,
    };

    let report = stop_bots::batch::run(&db, &options).await;

    if verbose {
        say!("{}", report.full());
    } else if report.failures() > 0 {
        say_err!("{}", report.failures_only());
    }

    let failures = report.failures();
    if failures > 0 {
        anyhow::bail!("{failures} of {} step(s) failed", report.steps.len());
    }
    Ok(())
}

fn scan_sites(root: Option<&Path>, db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    let host = host_settings()?;
    let server = host.web_server();
    let root = webserver::root(&host, root);
    let root = root.as_path();
    let sites = server.discover_sites(root)?;
    for site in &sites {
        db.upsert_site(&site.server_name, &site.config_path.to_string_lossy())?;
    }
    say!(
        "Discovered {} site(s) under {}",
        sites.len(),
        root.display()
    );
    // What the detectors will make allowances for, so that it is seen
    // before it matters: see `stop_bots::services`.
    let mut named = std::collections::BTreeSet::new();
    for site in &sites {
        if let Some(service) = server.site_service(&site.config_path, &site.server_name) {
            named.insert((site.server_name.as_str(), service.name()));
        }
    }
    for (name, service) in named {
        say!("  {name} runs {service}: its apps' requests for its own data are not taken for a bot's");
    }
    Ok(())
}

async fn update_bot_lists(
    db_path: Option<PathBuf>,
    source_id: Option<String>,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let kinds = match (source_id, &source) {
        (Some(id), _) => vec![botlist::SourceKind::from_id(&id)
            .with_context(|| format!("unknown bot-list source id: {id}"))?],
        (None, Some(_)) => vec![botlist::SourceKind::WellKnownBots],
        (None, None) => botlist::SourceKind::ALL.to_vec(),
    };
    let mut failed = Vec::new();
    for kind in kinds {
        let stored = match &source {
            Some(path) => std::fs::read_to_string(path)
                .map_err(anyhow::Error::from)
                .and_then(|raw| botlist::store_raw(&db, kind, &raw)),
            None => botlist::update(&db, kind).await,
        };
        match stored {
            Ok((count, skipped)) => {
                say!("Stored {count} bot(s) from {}", kind.name());
                if let Some(note) = botlist::left_out_note(skipped) {
                    say!("It {note}.");
                }
            }
            Err(err) => failed.push(format!("{}: {err:#}", kind.name())),
        }
    }
    each_or_fail(failed)
}

/// The end of an "every source, or one" update: fine if every one was
/// stored, and otherwise an error naming each that was not, after the rest
/// were. One feed that is down must not stop the others being refreshed.
fn each_or_fail(failed: Vec<String>) -> Result<()> {
    if failed.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} could not be updated:\n{}",
        failed.len(),
        failed.join("\n")
    )
}

/// `apply-blocks --dry-run`: the files an apply would change, and with
/// `--diff` how, through the functions the apply uses. Writes nothing.
fn preview_apply_blocks(root: Option<&Path>, db_path: Option<PathBuf>, diff: bool) -> Result<()> {
    let db = open_db(db_path)?;
    botlist::register_all_sources(&db)?;
    let host = host_settings()?;
    let root = webserver::root(&host, root);
    let changes = webserver::preview_all_sites(host.web_server(), &db, &root);
    say!("Dry run: nothing is written or reloaded.");
    let changes = changes.map_err(|err| format!("{err:#}"));
    for line in stop_bots::preview::nginx_lines(host.web_server(), &changes) {
        say!("{line}");
    }
    let changes = changes.map_err(|err| anyhow::anyhow!(err))?;
    if diff {
        say_inline!("{}", stop_bots::preview::nginx_diff(&changes));
    }
    print_skipped_entries(&db, host.web_server())
}

/// Says which stored entries the web server's config leaves out (see
/// `nginx::skipped_entries`, whose checks Apache's render shares), on
/// stderr, one per line. An apply writes everything else, so this is a
/// warning and not a failure.
fn print_skipped_entries(db: &Db, server: webserver::WebServer) -> Result<()> {
    for entry in nginx::skipped_entries(db)? {
        say_err!(
            "warning: left out of the {} config: {}",
            server.label(),
            terminal_safe(&entry.to_string())
        );
    }
    Ok(())
}

/// `batch --dry-run`: what the NGINX and firewall steps would change,
/// against the database as it is — nothing is downloaded or scanned first,
/// because both would write to it.
fn preview_batch(db_path: Option<PathBuf>, request: BatchRequest, diff: bool) -> Result<()> {
    let db = open_db(db_path)?;
    // The run stores this first (see `batch::run`), so a preview without
    // it would show a fresh host an NGINX plane with nothing to change.
    botlist::register_all_sources(&db)?;
    let host = host_settings()?;
    let root = webserver::root(&host, request.root.as_deref());
    let (backend, out) = firewall_target(&db, request.backend, request.out)?;
    let run = stop_bots::firewall::FirewallRun::new(backend, out)
        .apply(request.apply)
        .force(request.force)
        .protect(stop_bots::sshlog::session_client());
    // The flag, else the path `set-log-paths` stored, else the search.
    let source = host.log_paths().ssh(request.ssh_log.as_deref());
    let preview = stop_bots::preview::apply_everything(
        host.web_server(),
        &db,
        &root,
        run,
        stop_bots::firewall::SshLog::Read(&source),
    );

    say!(
        "Dry run: nothing is downloaded, scanned, written, applied or recorded. Against the \
         database as it is, `batch{}` would:",
        if request.apply { " --apply" } else { "" }
    );
    for line in preview.lines() {
        say!("{line}");
    }
    if preview
        .firewall
        .as_ref()
        .is_ok_and(|outcome| matches!(outcome.guard, stop_bots::firewall::Guard::NoLogins { .. }))
    {
        say!("{}.", stop_bots::firewall::NO_LOGINS_CLI_FIX);
    }
    if diff {
        say_inline!("{}", preview.diff());
    }
    Ok(())
}

fn apply_blocks(root: Option<&Path>, db_path: Option<PathBuf>, no_reload: bool) -> Result<()> {
    let db = open_db(db_path)?;
    // The list compiled into this binary, stored as the TUI and the web
    // console store it on start: on a host driven by the CLI alone,
    // nothing else ever would.
    botlist::register_all_sources(&db)?;
    let host = host_settings()?;
    let root = webserver::root(&host, root);
    // Tested, put back if the test fails, and reloaded only when something
    // actually changed on disk.
    let commands = (!no_reload).then(|| host.commands()).transpose()?;
    let outcome =
        webserver::apply_all_sites_and_reload(host.web_server(), &db, &root, commands.as_ref())?;
    say!(
        "Applied blocking rules to {} site(s) across {} file(s), {} file(s) changed",
        outcome.sites,
        outcome.files,
        outcome.changed
    );
    if outcome.reloaded {
        say!("Reloaded {}", host.web_server().label());
    }
    print_skipped_entries(&db, host.web_server())
}

fn add_firewall_rule(
    db_path: Option<PathBuf>,
    address: String,
    port: Option<u16>,
    action: &str,
) -> Result<()> {
    let action = FirewallAction::parse(action)?;
    // The same line `trust` draws at `/0`, and for the same reason: a
    // block of every address with no port is the host off the network,
    // far likelier a typo for a real prefix than a decision. With a port
    // it is an ordinary rule — closing that port to everyone — and stays.
    if action == FirewallAction::Block
        && port.is_none()
        && stop_bots::db::is_every_address(&address)
    {
        anyhow::bail!(
            "refusing to block {}: that is every address, which would take this host off the \
             network. Pass --port to close a single port to everyone.",
            address.trim()
        );
    }
    let db = open_db(db_path)?;
    let id = db.add_firewall_rule(&NewFirewallRule {
        address,
        port,
        action,
        source: RuleSource::Cli,
        evidence: None,
    })?;
    say!("Added firewall rule #{id}");
    Ok(())
}

/// A `--source` value: a source's name, its stored id, or `before-0.1`.
fn source_arg(value: &str) -> Result<SourceFilter, String> {
    SourceFilter::parse(value).ok_or_else(|| {
        let names: Vec<&str> = RuleSource::stored_sources()
            .into_iter()
            .map(RuleSource::name)
            .chain([stop_bots::blocks::LEGACY_NAME])
            .collect();
        format!("unknown source {value:?}; one of: {}", names.join(", "))
    })
}

fn list_firewall_rules(
    db_path: Option<PathBuf>,
    source: Option<SourceFilter>,
    json: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    db.prune_expired_firewall_rules()?;
    let query = stop_bots::db::BlockQuery {
        source,
        search: String::new(),
    };
    let rules = db.blocks_page(&query, 0, usize::MAX >> 1)?;
    if json {
        return stop_bots::output::print(&stop_bots::output::FirewallRules {
            rules: rules.iter().map(Into::into).collect(),
        });
    }
    if rules.is_empty() {
        match source {
            Some(source) => say!("No firewall rules from {}.", source.name()),
            None => say!("No firewall rules stored."),
        }
        return Ok(());
    }
    let now = now_secs();
    let offences = db.repeat_offences(now)?;
    for rule in &rules {
        say!("{}", rule_line(rule, now, &offences));
    }
    Ok(())
}

/// One rule as `list-firewall-rules` prints it: what it does, then where
/// it came from, then the evidence, which is last because it is the one
/// part of unbounded length.
///
/// The address and the evidence go through [`terminal_safe`] here as well
/// as through `say!`: `say!` keeps newlines, and a row written straight
/// into the database has not been through
/// [`stop_bots::blocks::evidence_line`], so a newline in it would forge a
/// second rule underneath.
///
/// A detector's block of an address blocked before says which offence it
/// is, from `offences` ([`Db::repeat_offences`]).
fn rule_line(
    rule: &FirewallRule,
    now: i64,
    offences: &std::collections::HashMap<String, u32>,
) -> String {
    let port = rule.port.map(|p| format!(":{p}")).unwrap_or_default();
    let status = if rule.enabled { "" } else { " (disabled)" };
    let expiry = rule
        .expires_at
        .map(|t| format!(" ({})", format_expiry(t)))
        .unwrap_or_default();
    let added = rule
        .created_at
        .map(|t| format!(", added {} ago", stop_bots::blocks::format_age(t, now)))
        .unwrap_or_default();
    let evidence = rule
        .evidence
        .as_deref()
        .map(|line| format!(": {}", terminal_safe(line)))
        .unwrap_or_default();
    let offence = stop_bots::blocks::offence_note(rule, offences)
        .map(|note| format!(", {note}"))
        .unwrap_or_default();
    format!(
        "#{} {:?} {}{port}{status}{expiry} [{}{added}{offence}]{evidence}",
        rule.id,
        rule.action,
        terminal_safe(&rule.address),
        stop_bots::blocks::source_name(rule.source)
    )
}

/// Renders a firewall rule's `expires_at` as "expires in 5d" for
/// `list-firewall-rules`, rounded the same way as every other screen that
/// shows time left ([`stop_bots::dynamic::format_until`]).
fn format_expiry(expires_at: i64) -> String {
    format!(
        "expires in {}",
        stop_bots::dynamic::format_until(expires_at)
    )
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn remove_firewall_rule(
    db_path: Option<PathBuf>,
    id: Option<i64>,
    source: Option<SourceFilter>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    match (id, source) {
        (Some(id), _) => {
            db.remove_firewall_rule(id)?;
            say!("Removed firewall rule #{id}");
        }
        (None, Some(source)) => {
            let count = db.remove_firewall_rules_from(source, dry_run)?;
            let name = source.name();
            if dry_run {
                say!("Would remove {count} firewall rule(s) from {name} (dry run).");
                return Ok(());
            }
            say!("Removed {count} firewall rule(s) from {name}.");
            if count == 0 {
                return Ok(());
            }
            if matches!(
                source,
                SourceFilter::Source(RuleSource::Detector(_)) | SourceFilter::Legacy
            ) {
                say!(
                    "The detectors leave those addresses alone for as long as each block was \
                     meant to last."
                );
            }
        }
        (None, None) => unreachable!("clap requires --id or --source"),
    }
    say!("Run `stop-bots render-firewall` and apply the script to put it in effect.");
    Ok(())
}

fn set_firewall_rule(db_path: Option<PathBuf>, id: i64, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_firewall_rule_enabled(id, enabled)?;
    say!(
        "Firewall rule #{id} is now {}.",
        if enabled { "enabled" } else { "disabled" }
    );
    say!("Run `stop-bots render-firewall` and apply the script to put it in effect.");
    Ok(())
}

fn set_firewall_backend(db_path: Option<PathBuf>, backend: FirewallBackend) -> Result<()> {
    let db = open_db(db_path)?;
    let backend: stop_bots::firewall::FirewallBackend = backend.into();
    stop_bots::firewall::store_backend(&db, backend)?;
    say!(
        "Firewall backend set to {}. Scripts go to {} unless told otherwise.",
        backend.stored(),
        stop_bots::firewall::default_output_path(backend).display()
    );
    Ok(())
}

async fn update_crawler_ranges(
    db_path: Option<PathBuf>,
    source_id: Option<String>,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let kinds = match source_id {
        Some(id) => vec![ipranges::IpRangeSourceKind::from_id(&id)
            .with_context(|| format!("unknown crawler source id: {id}"))?],
        None => ipranges::IpRangeSourceKind::ALL.to_vec(),
    };
    let mut failed = Vec::new();
    for kind in kinds {
        let stored = match &source {
            Some(path) => read_source_file(path)
                .and_then(|raw| kind.parse(&raw))
                .and_then(|ranges| ipranges::store(&db, kind, &ranges)),
            None => ipranges::update(&db, kind).await,
        };
        match stored {
            Ok(count) => say!("Stored {count} CIDR range(s) from {}", kind.name()),
            Err(err) => failed.push(format!("{}: {err:#}", kind.name())),
        }
    }
    each_or_fail(failed)
}

async fn update_country_ranges(
    db_path: Option<PathBuf>,
    country: Option<String>,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let countries = match country {
        Some(country) => vec![country],
        None => {
            let selected = db.list_selected_countries()?;
            if selected.is_empty() {
                say!("No country is selected, so there is nothing to update (`add-country`).");
            }
            selected
        }
    };
    let mut failed = Vec::new();
    for country in countries {
        let stored = match &source {
            Some(path) => {
                read_source_file(path).and_then(|raw| ipranges::store_country(&db, &country, &raw))
            }
            None => ipranges::update_country(&db, &country).await,
        };
        match stored {
            Ok(count) => say!("Stored {count} CIDR range(s) for country {country}"),
            Err(err) => failed.push(format!("{country}: {err:#}")),
        }
    }
    each_or_fail(failed)
}

/// Reads a `--source` override, saying which file failed rather than
/// leaving a bare "No such file or directory" to be matched against three
/// possible paths on the command line.
fn read_source_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn set_geo_mode(db_path: Option<PathBuf>, mode: GeoModeArg) -> Result<()> {
    let db = open_db(db_path)?;
    let mode: stop_bots::db::GeoMode = mode.into();
    db.set_geo_mode(mode)?;
    say!("Geo mode set to {mode:?}");
    // What the countries already on the list now mean: switching keeps
    // the list, so the ones that were blocked become the only ones allowed.
    let countries = db.list_selected_countries()?.join(" ").to_uppercase();
    say!(
        "{}",
        match (mode, countries.is_empty()) {
            (stop_bots::db::GeoMode::Blocklist, true) =>
                "No country is selected, so none is blocked.".to_string(),
            (stop_bots::db::GeoMode::Blocklist, false) =>
                format!("Blocked: {countries}. Every other country is allowed."),
            (stop_bots::db::GeoMode::Allowlist, true) =>
                "WARNING: no country is selected, so every address is blocked except trusted \
                 addresses, SSH logins from the last week and private networks. Add the countries \
                 you allow with `add-country`, or trust your address with `add-trusted --address`."
                    .to_string(),
            (stop_bots::db::GeoMode::Allowlist, false) => format!(
                "Allowed: {countries}. Every other country is blocked on every port; make sure the \
                 country you connect from is one of them."
            ),
        }
    );
    say!("Run render-firewall, then apply the script, to enforce it.");
    Ok(())
}

async fn update_reputation_sources(
    db_path: Option<PathBuf>,
    source_id: Option<String>,
    source: Option<PathBuf>,
) -> Result<()> {
    use stop_bots::ipranges::reputation::{self, ReputationSourceKind};

    let db = open_db(db_path)?;
    let kinds = match source_id {
        Some(id) => {
            let Some(kind) = ReputationSourceKind::from_id(&id) else {
                let known: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
                anyhow::bail!("unknown source: {id} (known: {})", known.join(", "));
            };
            vec![kind]
        }
        None => {
            let on: Vec<ReputationSourceKind> = db
                .list_reputation_sources()?
                .into_iter()
                .filter(|s| s.enabled)
                .filter_map(|s| ReputationSourceKind::from_id(&s.id))
                .collect();
            if on.is_empty() {
                say!(
                    "No feed is switched on, so there is nothing to update \
                     (`set-reputation-source`, or name one with --source-id)."
                );
            }
            on
        }
    };
    let mut failed = Vec::new();
    for kind in kinds {
        let stored = match &source {
            Some(path) => read_source_file(path)
                .and_then(|raw| kind.parse(&raw))
                .and_then(|ranges| reputation::store(&db, kind, &ranges)),
            None => reputation::update(&db, kind).await,
        };
        let count = match stored {
            Ok(count) => count,
            Err(err) => {
                failed.push(format!("{}: {err:#}", kind.name()));
                continue;
            }
        };
        say!("Stored {count} range(s) for {}", kind.name());
        // Fetching and enabling are separate on purpose; say so, or a fetch
        // that appears to succeed but changes nothing reads as a bug.
        let enabled = db
            .list_reputation_sources()?
            .into_iter()
            .any(|s| s.id == kind.id() && s.enabled);
        if !enabled {
            say!(
                "This feed is currently OFF — run `stop-bots set-reputation-source --source-id {} \
                 --enabled true` to apply it.",
                kind.id()
            );
        }
    }
    each_or_fail(failed)
}

fn set_reputation_source(db_path: Option<PathBuf>, source_id: String, enabled: bool) -> Result<()> {
    use stop_bots::ipranges::reputation::ReputationSourceKind;

    let db = open_db(db_path)?;
    let Some(kind) = ReputationSourceKind::from_id(&source_id) else {
        let known: Vec<&str> = ReputationSourceKind::ALL.iter().map(|k| k.id()).collect();
        anyhow::bail!("unknown source: {source_id} (known: {})", known.join(", "));
    };
    db.register_reputation_source(&kind.as_source())?;
    db.set_reputation_source_enabled(kind.id(), enabled)?;
    say!(
        "{} is now {}",
        kind.name(),
        if enabled { "ON" } else { "OFF" }
    );
    if enabled {
        if let Some(warning) = kind.warning() {
            say!("Warning: {warning}.");
        }
        if kind == ReputationSourceKind::Aws {
            say!("{}", cloud_port_80_line(db.get_cloud_port_80_open()?));
        }
        let count = db
            .list_reputation_sources()?
            .into_iter()
            .find(|s| s.id == kind.id())
            .map(|s| s.range_count)
            .unwrap_or(0);
        if count == 0 {
            say!(
                "No ranges stored yet — run `stop-bots update-reputation-sources --source-id {}` \
                 first, or this does nothing.",
                kind.id()
            );
        }
        say!("Run render-firewall, then apply the script, to enforce it.");
    }
    Ok(())
}

fn list_reputation_sources(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    use stop_bots::ipranges::reputation::{self, ReputationSourceKind};

    let db = open_db(db_path)?;
    reputation::register_all_reputation_sources(&db)?;
    let sources = db.list_reputation_sources()?;
    if json {
        let sources = sources
            .into_iter()
            .map(|source| stop_bots::output::ReputationSourceRow {
                warning: ReputationSourceKind::from_id(&source.id).and_then(|k| k.warning()),
                id: source.id,
                name: source.name,
                url: source.url,
                enabled: source.enabled,
                last_fetched_at: source.last_fetched_at,
                range_count: source.range_count,
            })
            .collect();
        return stop_bots::output::print(&stop_bots::output::ReputationSources { sources });
    }
    for source in sources {
        let state = if source.enabled { "ON " } else { "OFF" };
        let fetched = match source.last_fetched_at {
            Some(_) => format!("{} range(s)", source.range_count),
            None => "never fetched".to_string(),
        };
        let note = ReputationSourceKind::from_id(&source.id)
            .and_then(|k| k.warning())
            .map(|w| format!("  [{w}]"))
            .unwrap_or_default();
        say!(
            "[{state}] {:<22} {fetched}{note}",
            terminal_safe(&source.id)
        );
    }
    Ok(())
}

fn set_rate_limit(
    db_path: Option<PathBuf>,
    enabled: bool,
    rps: Option<i64>,
    burst: Option<i64>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let server = host_settings()?.web_server();
    // Refused rather than stored where nothing would write it: a limit
    // that reads as on and limits nothing is worse than none.
    if let Some(why) = server.without_rate_limiting().filter(|_| enabled) {
        anyhow::bail!("{why}");
    }
    // Parameters are stored even when disabling, so `--enabled false
    // --rps 5` then `--enabled true` uses 5 rather than silently
    // reverting to the default.
    if let Some(rps) = rps {
        db.set_rate_limit_rps(rps)?;
    }
    if let Some(burst) = burst {
        db.set_rate_limit_burst(burst)?;
    }
    db.set_rate_limit_enabled(enabled)?;
    if enabled {
        say!(
            "Rate limiting on: {} req/s per client, burst {}, then 429.",
            db.get_rate_limit_rps()?,
            db.get_rate_limit_burst()?
        );
    } else {
        say!("Rate limiting off.");
    }
    say!(
        "Run `stop-bots apply-blocks` to write it into the {} config.",
        server.label()
    );
    Ok(())
}

/// Resolves a `server_name` to its `sites` row, failing with the known
/// names rather than a bare "not found" — a typo here is the likeliest
/// mistake, and the fix is usually visible in the list.
fn find_site(db: &stop_bots::db::Db, server_name: &str) -> Result<stop_bots::db::Site> {
    let sites = db.list_sites()?;
    sites
        .iter()
        .find(|s| s.server_name == server_name)
        .cloned()
        .ok_or_else(|| {
            let known: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
            if known.is_empty() {
                anyhow::anyhow!("no sites discovered yet — run `stop-bots scan-sites` first")
            } else {
                anyhow::anyhow!("unknown site: {server_name} (known: {})", known.join(", "))
            }
        })
}

fn set_site_rule(
    db_path: Option<PathBuf>,
    site: String,
    rule: String,
    enabled: bool,
) -> Result<()> {
    use stop_bots::webserver::RequestRule;

    let db = open_db(db_path)?;
    let site = find_site(&db, &site)?;
    // Accept the dashed form the CLI advertises as well as the stored
    // underscore form, so `--rule no-user-agent` works.
    let id = rule.replace('-', "_");
    let Some(rule) = RequestRule::from_id(&id) else {
        let known: Vec<String> = RequestRule::ALL
            .iter()
            .map(|r| r.id().replace('_', "-"))
            .collect();
        anyhow::bail!("unknown rule: {rule} (known: {})", known.join(", "));
    };
    db.set_site_request_rule(site.id, rule.id(), enabled)?;
    say!(
        "{}: {} is now {}",
        site.server_name,
        rule.label(),
        if enabled { "blocked" } else { "allowed" }
    );
    if enabled {
        say!("Note: {}.", rule.caveat());
    }
    say!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

fn exempt_path(
    db_path: Option<PathBuf>,
    site: String,
    path: String,
    user_agent: Option<String>,
    remove: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let site = find_site(&db, &site)?;
    let trimmed = path.trim();
    // Matching is anchored at the start of the request path, so a value
    // without a leading slash could never fire — refused rather than
    // stored and silently ignored, same as the TUI does.
    if !remove && !trimmed.starts_with('/') {
        anyhow::bail!("an exempt path must start with '/' (got {trimmed:?})");
    }
    let name = &site.server_name;
    match (user_agent, remove) {
        (None, true) => {
            db.remove_site_path_exemption(site.id, trimmed)?;
            say!("{name}: {trimmed} is no longer exempt");
        }
        (None, false) => {
            db.add_site_path_exemption(site.id, trimmed)?;
            say!("{name}: {trimmed} is exempt from blocking");
        }
        (Some(user_agent), true) => {
            if !db.remove_site_agent_exemption(site.id, trimmed, &user_agent)? {
                anyhow::bail!("{name}: {trimmed} was not exempt for {user_agent:?}");
            }
            say!("{name}: {trimmed} is no longer exempt for {user_agent:?}");
        }
        (Some(user_agent), false) => {
            let stored = db.add_site_agent_exemption(site.id, trimmed, &user_agent)?;
            say!(
                "{name}: {trimmed} is exempt from blocking for clients whose user agent \
                 contains {stored:?}"
            );
        }
    }
    say!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

fn trust(
    db_path: Option<PathBuf>,
    address: Option<String>,
    user_agent: Option<String>,
    remove: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    match (address, user_agent, remove) {
        (Some(address), _, false) => {
            let stored = db.trust_address(&address)?;
            say!(
                "Trusting {stored}: never blocked by the firewall or {}.",
                server_label()
            );
            say!(
                "Run `stop-bots render-firewall` and apply the script, and `stop-bots \
                 apply-blocks`, to put it in effect."
            );
        }
        (Some(address), _, true) => {
            if !db.untrust_address(&address)? {
                anyhow::bail!("{address} is not trusted (see `stop-bots list-trusted`)");
            }
            say!("No longer trusting {address}.");
            say!(
                "Run `stop-bots render-firewall` and apply the script, and `stop-bots \
                 apply-blocks`, to put it in effect."
            );
        }
        (None, Some(user_agent), false) => {
            let stored = db.trust_user_agent(&user_agent)?;
            say!(
                "Trusting any user agent containing {stored:?}, ignoring case: never blocked \
                 by {}.",
                server_label()
            );
            // Said every time, because it is the part that surprises: the
            // firewall and the detectors still treat this client by its
            // address.
            say!(
                "The detectors and the firewall still judge it by its address — trust that \
                 too with `stop-bots add-trusted --address` if it must never be blocked at all."
            );
            say!("Run `stop-bots apply-blocks` to put it in effect.");
        }
        (None, Some(user_agent), true) => {
            if !db.untrust_user_agent(&user_agent)? {
                anyhow::bail!("{user_agent:?} is not trusted (see `stop-bots list-trusted`)");
            }
            say!("No longer trusting {user_agent:?}.");
            say!("Run `stop-bots apply-blocks` to put it in effect.");
        }
        // clap requires one of the two.
        (None, None, _) => unreachable!("clap requires --address or --user-agent"),
    }
    Ok(())
}

fn list_turned_away(
    db_path: Option<PathBuf>,
    access_log: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let response = db.get_block_response()?;
    let log_text = read_access_log(&db, access_log.as_deref())?;
    let turned_away =
        stop_bots::accesslog::turned_away_user_agents(&log_text, response.status_code());

    if json {
        return stop_bots::output::print(&stop_bots::output::TurnedAway {
            block_status: response.status_code(),
            user_agents: turned_away
                .into_iter()
                .map(|entry| stop_bots::output::TurnedAwayRow {
                    user_agent: entry.user_agent,
                    refused: entry.refused,
                    served: entry.served,
                })
                .collect(),
        });
    }

    if turned_away.is_empty() {
        say!("Nothing in this log was turned away.");
        return Ok(());
    }

    // Said before the table, not after: on a host answering 403 the
    // numbers include the application's own refusals, and a reader who
    // learns that at the bottom has already drawn conclusions.
    say!(
        "Counting responses of {} \u{2014} this host's block response.",
        response.label()
    );
    if response.status_code() != stop_bots::db::BlockResponse::Close.status_code() {
        say!(
            "That code is one an application can send too, so compare the columns: refusals \
             with nothing served is a client being stopped at the door."
        );
    }
    say!();
    say!("{:>8}  {:>8}  USER AGENT", "REFUSED", "SERVED");
    for entry in &turned_away {
        // Client-chosen text on its way to a terminal; see `printable`.
        say!(
            "{:>8}  {:>8}  {}",
            entry.refused,
            entry.served,
            terminal_safe(&entry.user_agent)
        );
    }
    say!();
    say!("Allow one with: stop-bots add-trusted --user-agent \"<part of the agent>\"");
    Ok(())
}

fn list_trusted(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    if json {
        return stop_bots::output::print(&stop_bots::output::Trusted {
            addresses: db.list_trusted_addresses()?,
            user_agents: db.list_trusted_user_agents()?,
        });
    }
    let entries = stop_bots::dynamic::trusted_entries(&db)?;
    if entries.is_empty() {
        say!("Nothing is trusted.");
    }
    for entry in entries {
        say!("{:<11} {}", entry.kind(), terminal_safe(entry.value()));
    }
    Ok(())
}

fn set_auto_apply(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_auto_apply(enabled)?;
    say!(
        "Automatic {} applying {}",
        server_label(),
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled {
        // Says where the work happens, because it is not here. Someone who
        // sets this from a shell on a host with no console running has
        // turned on a switch nothing will ever read, and the only sign
        // would be that nothing happens.
        say!(
            "The schedule applies and reloads within the hour \u{2014} it runs from \
             `stop-bots install cron`, or in the TUI while it is open. The firewall script is \
             not covered: apply it yourself, or with `stop-bots batch --apply`."
        );
    }
    Ok(())
}

fn set_humans_only(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_humans_only(enabled)?;
    if enabled {
        say!("Humans only is ON.");
        say!(
            "  \u{2022} Every catalogued bot is blocked, whatever its category. On a host with \
             the usual lists that is over 1,600 patterns, including the several hundred that \
             carry no category at all."
        );
        say!(
            "  \u{2022} Let's Encrypt is the one exception, because blocking it breaks \
             certificate renewal \u{2014} which surfaces as an expired certificate two months \
             later, not as an error now."
        );
        say!(
            "  \u{2022} Any address that fetches /robots.txt is blocked for a day. Note that \
             this catches the crawlers polite enough to ask."
        );
        say!(
            "  \u{2022} The three category policies are forced and cannot be edited until this \
             is off. Their stored values are kept."
        );
        // The screen is named for the server, so the sentence is too.
        let server = server_label();
        say!(
            "\nRun apply-blocks (or the {server} screen's `a`/`A`) to write it into the {server} \
             config."
        );
    } else {
        say!("Humans only is OFF. The stored category policies are back in force.");
    }
    Ok(())
}

fn set_old_browsers(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_block_old_browsers(enabled)?;
    let count = stop_bots::botlist::old_browsers::substrings().len();
    if enabled {
        say!("Old browsers are BLOCKED on every site: {count} user-agent strings.");
    } else {
        say!("Old browsers are allowed again.");
    }
    say!(
        "Run `stop-bots apply-blocks` to write it into the {} config.",
        server_label()
    );
    Ok(())
}

fn set_auto_apply_firewall(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_auto_apply_firewall(enabled)?;
    say!(
        "Automatic firewall applying {}",
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled {
        say!(
            "The schedule will run the script it renders, daily \u{2014} it runs from \
             `stop-bots install cron`, or in the TUI while it is open."
        );
        // The condition that most often stops this doing anything, said
        // up front rather than discovered in a summary line a day later.
        say!(
            "It refuses to apply unless the anti-lockout check ran, which needs a readable \
             SSH log. If the job reports that, point --ssh-log at one."
        );
    }
    Ok(())
}

fn set_cloud_port_80(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_cloud_port_80_open(enabled)?;
    say!("{}", cloud_port_80_line(enabled));
    say!("Run render-firewall, then apply the script, to enforce it.");
    Ok(())
}

fn set_ssh_lockout_check(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_ssh_lockout_check(enabled)?;
    if enabled {
        say!("The SSH lock-out check is on: every firewall apply is checked against SSH logins.");
    } else {
        say!(
            "The SSH lock-out check is off: firewall applies are no longer checked against SSH \
             logins. Addresses that log in over SSH are still let through. \
             `stop-bots status` warns if someone logs in over SSH while it is off."
        );
    }
    Ok(())
}

/// What the cloud-provider feeds do on port 80, said the same way by
/// `set-cloud-port-80` and by `set-reputation-source` turning AWS on.
fn cloud_port_80_line(open: bool) -> &'static str {
    if open {
        "The cloud-provider feeds and hosting providers leave port 80 open, so Let's \
         Encrypt can renew certificates over HTTP (`set-cloud-port-80 --enabled false` \
         closes it)."
    } else {
        "The cloud-provider feeds and hosting providers block port 80 too. Let's Encrypt \
         validates from AWS, so \
         with the AWS feed on, certificates renewed over HTTP stop renewing \
         (`set-cloud-port-80 --enabled true` opens it)."
    }
}

fn set_robots_txt(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_serve_robots_txt(enabled)?;
    say!(
        "robots.txt generation {}",
        if enabled { "enabled" } else { "disabled" }
    );
    if enabled {
        say!(
            "It replaces whatever each site currently serves at /robots.txt. Preview it with \
             `stop-bots show-robots-txt`."
        );
    }
    say!("Run `stop-bots apply-blocks` to write it into the site configs.");
    Ok(())
}

/// "on" or "off", for the listings below.
fn on_off(on: bool) -> &'static str {
    if on {
        "on"
    } else {
        "off"
    }
}

/// One detector's settings as one line: the same wording `list-detectors`
/// and `set-detector` print, so what one shows the other confirms.
fn detector_line(db: &Db, detector: DetectorArg) -> Result<String> {
    let d = detector.0;
    let threshold = match d.threshold(db)? {
        Some(value) => value.to_string(),
        None => "-".to_string(),
    };
    let mut label = d.spec().label.to_string();
    if !d.is_operator_controlled() {
        label.push_str(" (follows set-humans-only)");
    }
    if d.is_new_here(db)? {
        label.push_str(" (new in this release: off until you turn it on)");
    }
    Ok(format!(
        "{:<17} {:<4} {:>5}d {:>9} {:>5}h  {label}",
        detector.name(),
        on_off(d.is_enabled(db)?),
        d.ttl_days(db)?,
        threshold,
        d.window_hours(db)?,
    ))
}

fn list_detectors(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    if json {
        let mut detectors = Vec::new();
        for detector in DetectorArg::ALL {
            let d = detector.0;
            detectors.push(stop_bots::output::DetectorRow {
                name: detector.name(),
                label: d.spec().label,
                enabled: d.is_enabled(&db)?,
                follows_humans_only: !d.is_operator_controlled(),
                ttl_days: d.ttl_days(&db)?,
                threshold: d.threshold(&db)?,
                window_hours: d.window_hours(&db)?,
                new_in_this_release: d.is_new_here(&db)?,
            });
        }
        return stop_bots::output::print(&stop_bots::output::Detectors {
            detectors,
            subnet_escalation: stop_bots::output::SubnetEscalation {
                enabled: stop_bots::protection::subnet_escalation(&db)?.is_some(),
                min: stop_bots::protection::subnet_escalation_min(&db)?,
            },
            repeat_offenders: stop_bots::output::RepeatOffenders {
                enabled: stop_bots::protection::repeat_escalation(&db)?,
                new_in_this_release: stop_bots::protection::repeat_escalation_is_new_here(&db)?,
                max_multiplier: stop_bots::protection::ESCALATION_MAX_MULTIPLIER,
                max_days: stop_bots::protection::ESCALATION_MAX_DAYS,
                memory_days: stop_bots::protection::OFFENCE_MEMORY_DAYS,
            },
        });
    }
    say!(
        "{:<17} {:<4} {:>6} {:>9} {:>6}",
        "DETECTOR",
        "ON",
        "TTL",
        "THRESHOLD",
        "WINDOW"
    );
    for detector in DetectorArg::ALL {
        say!("{}", detector_line(&db, detector)?);
    }
    say!();
    say!(
        "IPv4 /24 escalation: {}, at {} flagged address(es) in one /24.",
        on_off(stop_bots::protection::subnet_escalation(&db)?.is_some()),
        stop_bots::protection::subnet_escalation_min(&db)?
    );
    say!("{}", repeat_offenders_line(&db)?);
    say!(
        "{} `stop-bots list-probe-paths` shows its paths.",
        app_aware_line(&db)?
    );
    say!(
        "The schedule (`stop-bots tick`, or the TUI while it is open) and `batch` run the \
         ones that are on."
    );
    Ok(())
}

/// What `set-detector` was asked to change; `None` leaves each as it is.
struct DetectorChanges {
    enabled: Option<bool>,
    ttl_days: Option<i64>,
    threshold: Option<i64>,
    window_hours: Option<i64>,
    app_aware: Option<bool>,
}

fn set_detector(
    db_path: Option<PathBuf>,
    detector: DetectorArg,
    changes: DetectorChanges,
) -> Result<()> {
    use stop_bots::protection::{MAX_TTL_DAYS, MAX_WINDOW_HOURS};
    let DetectorChanges {
        enabled,
        ttl_days,
        threshold,
        window_hours,
        app_aware,
    } = changes;

    let db = open_db(db_path)?;
    let d = detector.0;
    let name = detector.name();

    // Every refusal before any write, so a bad flag leaves the detector
    // exactly as it was rather than half changed.
    if enabled.is_some() && !d.is_operator_controlled() {
        anyhow::bail!(
            "{name} runs exactly when humans only is on; switch that with `stop-bots \
             set-humans-only`"
        );
    }
    if let Some(days) = ttl_days {
        if !(1..=MAX_TTL_DAYS).contains(&days) {
            anyhow::bail!("a block lasts from 1 to {MAX_TTL_DAYS} days, not {days}");
        }
    }
    if let Some(hours) = window_hours {
        if !(1..=MAX_WINDOW_HOURS).contains(&hours) {
            anyhow::bail!("a detection window is from 1 to {MAX_WINDOW_HOURS} hours, not {hours}");
        }
    }
    if threshold.is_some() && d.threshold_setting().is_none() {
        anyhow::bail!(
            "{name} has no threshold: one matching request is already conclusive (the ones \
             that have one are {})",
            counting_detectors()
        );
    }

    if app_aware.is_some() && d != Detector::ProbePaths {
        anyhow::bail!("--app-aware is a setting of probe-paths only");
    }

    if let Some(value) = threshold {
        d.set_threshold(&db, value)?;
    }
    if let Some(on) = app_aware {
        stop_bots::protection::set_app_probe_paths(&db, on)?;
    }
    if let Some(days) = ttl_days {
        d.set_ttl_days(&db, days)?;
    }
    if let Some(hours) = window_hours {
        d.set_window_hours(&db, hours)?;
    }
    if let Some(on) = enabled {
        d.set_enabled(&db, on)?;
    }

    say!(
        "{:<17} {:<4} {:>6} {:>9} {:>6}",
        "DETECTOR",
        "ON",
        "TTL",
        "THRESHOLD",
        "WINDOW"
    );
    say!("{}", detector_line(&db, detector)?);
    if d == Detector::ProbePaths {
        say!(
            "{} When on, {}; `stop-bots list-probe-paths` shows which, and why.",
            app_aware_line(&db)?,
            stop_bots::protection::app_probe_paths_summary()
        );
    }
    if enabled == Some(false) {
        // The distinction the README draws, said where it bites.
        say!(
            "Blocks it already added stay until they expire; remove one with \
             `stop-bots remove-firewall-rule`."
        );
    }
    Ok(())
}

/// Whether repeat offenders are blocked for longer, as `list-detectors`
/// and `set-repeat-offenders` say it.
fn repeat_offenders_line(db: &Db) -> Result<String> {
    use stop_bots::protection::{
        repeat_escalation, repeat_escalation_is_new_here, repeat_escalation_summary,
    };
    let state = if repeat_escalation_is_new_here(db)? {
        "off (new in this release: `stop-bots set-repeat-offenders --enabled true` turns it on)"
            .to_string()
    } else {
        on_off(repeat_escalation(db)?).to_string()
    };
    Ok(format!(
        "Repeat offenders: {state}. When on, {}.",
        repeat_escalation_summary()
    ))
}

fn set_repeat_offenders(db_path: Option<PathBuf>, enabled: bool) -> Result<()> {
    let db = open_db(db_path)?;
    stop_bots::protection::set_repeat_escalation(&db, enabled)?;
    say!("{}", repeat_offenders_line(&db)?);
    if !enabled {
        say!(
            "Blocks already made stay as long as they were made for; offences are still \
             counted, so turning it back on picks up where it left off."
        );
    }
    Ok(())
}

fn set_subnet_escalation(
    db_path: Option<PathBuf>,
    enabled: Option<bool>,
    min: Option<i64>,
) -> Result<()> {
    let db = open_db(db_path)?;
    stop_bots::protection::set_subnet_escalation(&db, enabled, min)?;
    let on = stop_bots::protection::subnet_escalation(&db)?.is_some();
    say!(
        "IPv4 /24 escalation is {}, at {} flagged address(es) in one /24.",
        on_off(on),
        stop_bots::protection::subnet_escalation_min(&db)?
    );
    if on {
        say!(
            "A detector pass that flags that many addresses in one /24 now blocks all 256 \
             addresses in it."
        );
    }
    Ok(())
}

fn policy_word(policy: stop_bots::db::Policy) -> &'static str {
    match policy {
        stop_bots::db::Policy::Allowed => "allowed",
        stop_bots::db::Policy::Blocked => "blocked",
    }
}

/// The name a category is typed as, which is also how it is printed.
fn category_name(category: CategoryArg) -> &'static str {
    match category {
        CategoryArg::Scanner => "scanner",
        CategoryArg::Search => "search",
        CategoryArg::Ai => "ai",
    }
}

const CATEGORIES: [CategoryArg; 3] = [CategoryArg::Scanner, CategoryArg::Search, CategoryArg::Ai];

/// Said wherever a category or bot policy is set or shown, because it
/// outranks both and nothing else on screen would explain why a stored
/// "allowed" is not in force.
const HUMANS_ONLY_NOTE: &str = "Humans only is on: every catalogued bot but Let's Encrypt is \
blocked whatever is set here. The stored values come back when it is switched off \
(`stop-bots set-humans-only --enabled false`).";

fn set_category(
    db_path: Option<PathBuf>,
    category: CategoryArg,
    policy: PolicyArg,
    site: Option<String>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let name = category_name(category);
    match site {
        None => {
            let Some(policy) = policy.policy() else {
                anyhow::bail!(
                    "the host-wide policy has nothing above it to follow: use allowed or \
                     blocked. `--policy default` removes a site's override, with --site"
                );
            };
            db.set_category_default(category.into(), policy)?;
            say!("Category {name} is now {} host-wide.", policy_word(policy));
        }
        Some(site) => {
            let site = find_site(&db, &site)?;
            db.set_site_category_override(site.id, category.into(), policy.policy())?;
            match policy.policy() {
                Some(policy) => say!(
                    "{}: category {name} is now {}, whatever the host-wide policy says.",
                    site.server_name,
                    policy_word(policy)
                ),
                None => say!(
                    "{}: category {name} follows the host-wide policy again.",
                    site.server_name
                ),
            }
        }
    }
    if db.get_humans_only()? {
        say!("{HUMANS_ONLY_NOTE}");
    }
    say!(
        "Run `stop-bots apply-blocks` to write it into the {} config.",
        server_label()
    );
    Ok(())
}

fn list_categories(db_path: Option<PathBuf>, site: Option<String>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let site = site.map(|name| find_site(&db, &name)).transpose()?;
    if json {
        return stop_bots::output::print(&categories_json(&db, site.as_ref())?);
    }

    match &site {
        None => say!("{:<9} POLICY", "CATEGORY"),
        Some(site) => say!(
            "{:<9} {:<9} {}",
            "CATEGORY",
            "HOST-WIDE",
            terminal_safe(&site.server_name)
        ),
    }
    for category in CATEGORIES {
        let stored = db.get_stored_category_default(category.into())?;
        match &site {
            None => say!("{:<9} {}", category_name(category), policy_word(stored)),
            Some(site) => {
                let over = db
                    .get_site_category_override(site.id, category.into())?
                    .map(policy_word)
                    .unwrap_or("(host-wide)");
                say!(
                    "{:<9} {:<9} {over}",
                    category_name(category),
                    policy_word(stored)
                );
            }
        }
    }

    // Not a category, so not a row of the table: one switch for every
    // site, which no site's override reaches.
    say!();
    say!(
        "Old browsers: {} on every site (set-old-browsers)",
        if db.get_block_old_browsers()? {
            "blocked"
        } else {
            "allowed"
        }
    );

    if let Some(site) = &site {
        let overrides = db.site_bot_overrides(site.id)?;
        if !overrides.is_empty() {
            let bots = db.list_bots()?;
            say!();
            say!("Bot overrides on {}:", terminal_safe(&site.server_name));
            for over in overrides {
                let slug = bots
                    .iter()
                    .find(|b| b.id == over.bot_id)
                    .map(|b| b.slug.as_str())
                    .unwrap_or("(unknown bot)");
                say!("  {:<30} {}", terminal_safe(slug), policy_word(over.policy));
            }
        }
    }
    if db.get_humans_only()? {
        say!();
        say!("{HUMANS_ONLY_NOTE}");
    }
    Ok(())
}

/// What `list-categories --json` prints: the same facts as the text, in
/// the same order.
fn categories_json(
    db: &Db,
    site: Option<&stop_bots::db::Site>,
) -> Result<stop_bots::output::Categories> {
    use stop_bots::output::{
        policy_name, BotOverrideRow, Categories, CategoryRow, SiteCategories, SiteCategoryRow,
    };

    let mut categories = Vec::new();
    for category in CATEGORIES {
        categories.push(CategoryRow {
            category: category_name(category),
            policy: policy_name(db.get_stored_category_default(category.into())?),
        });
    }
    let site = match site {
        None => None,
        Some(site) => {
            let mut site_categories = Vec::new();
            for category in CATEGORIES {
                site_categories.push(SiteCategoryRow {
                    category: category_name(category),
                    policy: db
                        .get_site_category_override(site.id, category.into())?
                        .map(policy_name),
                });
            }
            let bots = db.list_bots()?;
            let bot_overrides = db
                .site_bot_overrides(site.id)?
                .into_iter()
                .map(|over| BotOverrideRow {
                    bot: bots
                        .iter()
                        .find(|b| b.id == over.bot_id)
                        .map_or_else(|| "(unknown bot)".to_string(), |b| b.slug.clone()),
                    policy: policy_name(over.policy),
                })
                .collect();
            Some(SiteCategories {
                server_name: site.server_name.clone(),
                categories: site_categories,
                bot_overrides,
            })
        }
    };
    Ok(Categories {
        categories,
        old_browsers: if db.get_block_old_browsers()? {
            "blocked"
        } else {
            "allowed"
        },
        humans_only: db.get_humans_only()?,
        site,
    })
}

/// Finds a bot by slug, failing with the way to look one up rather than a
/// bare "not found".
fn find_bot(db: &Db, slug: &str) -> Result<stop_bots::db::Bot> {
    db.list_bots()?
        .into_iter()
        .find(|b| b.slug == slug)
        .with_context(|| {
            format!(
                "no bot with slug {slug:?} — find it with `stop-bots list-bots --search <name>`"
            )
        })
}

fn set_bot(
    db_path: Option<PathBuf>,
    slug: String,
    policy: PolicyArg,
    site: Option<String>,
) -> Result<()> {
    use stop_bots::db::BotStatus;

    let db = open_db(db_path)?;
    let bot = find_bot(&db, &slug)?;
    match site {
        None => {
            let status = match policy {
                PolicyArg::Allowed => BotStatus::Allowed,
                PolicyArg::Blocked => BotStatus::Blocked,
                PolicyArg::Default => BotStatus::Default,
            };
            db.set_bot_status(&bot.slug, status)?;
            match policy.policy() {
                Some(policy) => say!("{} is now {} host-wide.", bot.slug, policy_word(policy)),
                None => say!("{} follows its category again.", bot.slug),
            }
        }
        Some(site) => {
            let site = find_site(&db, &site)?;
            db.set_site_bot_override(site.id, bot.id, policy.policy())?;
            match policy.policy() {
                Some(policy) => say!(
                    "{}: {} is now {}, whatever the host-wide setting says.",
                    site.server_name,
                    bot.slug,
                    policy_word(policy)
                ),
                None => say!(
                    "{}: {} follows the host-wide setting again.",
                    site.server_name,
                    bot.slug
                ),
            }
        }
    }
    if db.get_humans_only()? {
        say!("{HUMANS_ONLY_NOTE}");
    }
    say!(
        "Run `stop-bots apply-blocks` to write it into the {} config.",
        server_label()
    );
    Ok(())
}

/// A bot's categories, as `set-category --category` names them.
fn bot_categories(bot: &stop_bots::db::Bot) -> Vec<&'static str> {
    let mut categories = Vec::new();
    if bot.is_scanner {
        categories.push("scanner");
    }
    if bot.is_search_engine {
        categories.push("search");
    }
    if bot.is_ai {
        categories.push("ai");
    }
    categories
}

fn list_bots(db_path: Option<PathBuf>, search: Option<String>, json: bool) -> Result<()> {
    use stop_bots::db::BotStatus;

    let db = open_db(db_path)?;
    let needle = search.as_deref().map(str::to_lowercase);
    let bots: Vec<_> = db
        .list_bots()?
        .into_iter()
        .filter(|b| match &needle {
            Some(n) => b.slug.to_lowercase().contains(n) || b.name.to_lowercase().contains(n),
            None => true,
        })
        .collect();
    if json {
        let bots = bots
            .into_iter()
            .map(|bot| stop_bots::output::BotRow {
                status: match bot.status {
                    BotStatus::Default => "default",
                    BotStatus::Allowed => "allowed",
                    BotStatus::Blocked => "blocked",
                },
                categories: bot_categories(&bot),
                slug: bot.slug,
                name: bot.name,
            })
            .collect();
        return stop_bots::output::print(&stop_bots::output::Bots { bots });
    }
    if bots.is_empty() {
        match &search {
            Some(s) => say!("No bot matches {s:?}."),
            None => say!("No bots stored yet — run `stop-bots update-bot-lists` first."),
        }
        return Ok(());
    }
    say!("{:<9} {:<22} {:<30} NAME", "STATUS", "CATEGORIES", "SLUG");
    for bot in bots {
        let status = match bot.status {
            BotStatus::Default => "category",
            BotStatus::Allowed => "allowed",
            BotStatus::Blocked => "blocked",
        };
        let categories = bot_categories(&bot);
        let categories = if categories.is_empty() {
            "-".to_string()
        } else {
            categories.join(",")
        };
        say!(
            "{status:<9} {categories:<22} {:<30} {}",
            terminal_safe(&bot.slug),
            terminal_safe(&bot.name)
        );
    }
    Ok(())
}

fn show_robots_txt(db_path: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;
    say_inline!("{}", webserver::robots_txt_body(&db)?);
    Ok(())
}

/// Stores the log paths, then prints what every future run will read.
///
/// Printing the resolved state rather than "saved" is the point: the
/// failure this command exists to fix looked exactly like success, so the
/// confirmation has to be the paths themselves.
fn run_set_log_paths(
    db_path: Option<PathBuf>,
    access_log: Option<String>,
    ssh_log: Option<String>,
) -> Result<()> {
    // Opened for the migration only: these settings are the host's now
    // (see `hostconf`), and a database left holding the old rows moves
    // them first, so that what is changed here is what is already there.
    let _db = open_db(db_path)?;
    let path = stop_bots::hostconf::path();
    let mut host = stop_bots::hostconf::HostConf::load_from(&path)?;
    if access_log.is_none() && ssh_log.is_none() {
        say!("Nothing to change. Current settings:");
    } else {
        // An empty value clears one; a path is stored absolute, because
        // the service that reads it does not run where this did.
        let resolve = |raw: &str| -> Result<Option<PathBuf>> {
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(None);
            }
            Ok(Some(std::path::absolute(raw).with_context(|| {
                format!("{raw} is not a path this host can resolve")
            })?))
        };
        if let Some(raw) = &access_log {
            host.access_log = resolve(raw)?;
        }
        if let Some(raw) = &ssh_log {
            host.ssh_log = resolve(raw)?;
        }
        host.save_to(&path)?;
    }

    let paths = host.log_paths();
    match &paths.access {
        Some(path) => say!("  access log: {}", path.display()),
        None => say!(
            "  access log: {} (default — nothing stored)",
            paths.default_access_log()
        ),
    }
    match &paths.ssh {
        Some(path) => say!("  ssh log:    {}", path.display()),
        None => say!("  ssh log:    auto-detected (auth.log, secure, then journalctl)"),
    }
    Ok(())
}

fn run_install_firewall(
    binary: Option<PathBuf>,
    prefix: Option<PathBuf>,
    dry_run: bool,
    force: bool,
) -> Result<()> {
    let binary = match binary {
        Some(path) => path,
        None => std::env::current_exe().context("could not determine the running binary")?,
    };
    // No check of where the binary lives: this unit runs `nft` or `sh` on
    // the script and never runs stop-bots at all, so a binary under /home
    // or /tmp cannot break it. The binary is carried only to name it in
    // the --dry-run hint.
    let layout = match &prefix {
        Some(prefix) => stop_bots::install::Layout::under(prefix, binary),
        None => stop_bots::install::Layout::system(binary),
    };
    let options = stop_bots::install::Options { dry_run, force };

    let steps = stop_bots::install::install_firewall(&layout, &options)?;
    for step in steps.iter() {
        say!("  {step}");
    }
    if dry_run {
        say!("\nDry run — nothing was changed.");
    }
    Ok(())
}

/// `stop-bots install cron`: the schedule, as /etc/cron.d/stop-bots.
fn run_install_cron(
    db: Option<PathBuf>,
    binary: Option<PathBuf>,
    prefix: Option<PathBuf>,
    dry_run: bool,
    force: bool,
) -> Result<()> {
    let binary = match binary {
        Some(binary) => binary,
        None => std::env::current_exe().context("could not determine the running binary")?,
    };
    if stop_bots::install::is_build_artifact(&binary) {
        anyhow::bail!(
            "{} is in a build directory, and the cron file would stop working at the next \
             `cargo clean`. Install the binary first (`install -m 755 {} /usr/local/bin/`), \
             then run `/usr/local/bin/stop-bots install cron`, or pass --binary.",
            binary.display(),
            binary.display()
        );
    }
    let mut layout = match &prefix {
        Some(prefix) => stop_bots::install::Layout::under(prefix, binary),
        None => stop_bots::install::Layout::system(binary),
    };
    if let Some(db) = db {
        layout.db_path = db;
    }
    let options = stop_bots::install::Options { dry_run, force };

    let steps = stop_bots::install::install_cron(&layout, &options)?;
    for step in steps.iter() {
        say!("  {step}");
    }
    if dry_run {
        say!("\nDry run — nothing was changed.");
    }
    Ok(())
}

/// The lock `tick` takes, so that a run cron starts while the last one is
/// still going leaves rather than reading the logs beside it. A file of its
/// own, not the apply lock: an apply waits its turn, a tick need not.
const TICK_LOCK: &str = "/run/stop-bots-tick.lock";

/// `stop-bots tick`: whatever is due on the schedule, once.
async fn run_tick(
    db_path: Option<PathBuf>,
    root: Option<PathBuf>,
    ssh_log: Option<PathBuf>,
    verbose: bool,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    let lock_path = if unsafe { libc::geteuid() } == 0 {
        PathBuf::from(TICK_LOCK)
    } else {
        std::env::temp_dir().join(format!("stop-bots-tick-{}.lock", unsafe {
            libc::geteuid()
        }))
    };
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    // SAFETY: a valid descriptor, owned by `lock` until it drops at the end.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        if verbose {
            say!("Another tick is still running; leaving it to finish.");
        }
        return Ok(());
    }

    let db = open_db(db_path)?;
    let host = stop_bots::hostconf::HostConf::load()?;
    let root = host.root(root.as_deref());
    let settings = stop_bots::cron::TickSettings {
        host: &host,
        root: &root,
        ssh_log,
        firewall_out: None,
    };
    let ran = stop_bots::cron::tick(&db, &settings).await?;
    if verbose {
        if ran.is_empty() {
            say!("Nothing was due.");
        }
        for (job, summary) in ran {
            say!("{}: {}", job.label(), terminal_safe(&summary));
        }
    }
    drop(lock);
    Ok(())
}

/// `stop-bots uninstall`. The work, and the reasoning about its order, is
/// in `stop_bots::uninstall`; this checks the flags and prints the report.
fn run_uninstall(
    db: Option<PathBuf>,
    target: UninstallTarget,
    dry_run: bool,
    purge: bool,
    prefix: Option<PathBuf>,
    root: Option<PathBuf>,
) -> Result<()> {
    use stop_bots::uninstall::{self, Outcome, Plan};

    if purge && target != UninstallTarget::All {
        anyhow::bail!(
            "--purge deletes the database, so it goes only with `all`: whatever `nginx`, \
             `firewall` or `web` leaves installed still reads it"
        );
    }
    // Asked of the uid rather than tried, unlike `install`: a run that got
    // half way on permissions would leave exactly the half-removed host
    // this command exists to avoid.
    if prefix.is_none() && unsafe { libc::geteuid() } != 0 {
        anyhow::bail!(
            "uninstall changes /etc, systemd and the firewall, and needs root. Run it with \
             sudo — `sudo stop-bots uninstall --dry-run` first to see the plan — or pass \
             --prefix to run it against a staged tree."
        );
    }

    let plan = Plan::resolve(prefix.as_deref(), db, root.as_deref())?;
    let report = uninstall::run(&plan, target.into(), &uninstall::Options { dry_run, purge });

    say!(
        "{}",
        if dry_run {
            "Dry run — nothing was changed. Would:"
        } else {
            "Uninstalling:"
        }
    );
    for step in &report.steps {
        match &step.outcome {
            Outcome::Done => say!("  done     {}", step.what),
            Outcome::Planned => say!("  would    {}", step.what),
            Outcome::Skipped(why) => say!("  skipped  {} ({why})", step.what),
            Outcome::Failed(why) => {
                say!("  FAILED   {}", step.what);
                for line in why.lines() {
                    say!("           {line}");
                }
            }
        }
    }
    if !report.kept.is_empty() {
        say!("\nLeft in place:");
        for kept in &report.kept {
            say!("  {kept}");
        }
    }
    let failed = report.failures();
    if failed > 0 {
        anyhow::bail!(
            "{failed} step(s) failed; every other step was done. Fix what is named above \
             and run the same command again: what is already gone is skipped."
        );
    }
    if dry_run {
        say!("\nRe-run without --dry-run to do it.");
    }
    Ok(())
}

fn set_nginx_commands(
    db_path: Option<PathBuf>,
    test: Option<String>,
    reload: Option<String>,
    root: Option<PathBuf>,
    reset: bool,
) -> Result<()> {
    store_server_settings(
        db_path,
        webserver::WebServer::Nginx,
        false,
        ServerSettings {
            test,
            reload,
            root,
            reset,
        },
    )
}

/// What `set-web-server` (and the deprecated `set-nginx-commands`) may change about one
/// server.
struct ServerSettings {
    test: Option<String>,
    reload: Option<String>,
    root: Option<PathBuf>,
    reset: bool,
}

fn parse_web_server(id: &str) -> std::result::Result<webserver::WebServer, String> {
    webserver::WebServer::from_id(id).ok_or_else(|| {
        format!(
            "not a web server stop-bots knows: choose one of {}",
            webserver::WebServer::ALL
                .map(webserver::WebServer::id)
                .join(", ")
        )
    })
}

fn set_web_server(
    db_path: Option<PathBuf>,
    server: Option<webserver::WebServer>,
    settings: ServerSettings,
) -> Result<()> {
    match server {
        Some(server) => store_server_settings(db_path, server, true, settings),
        None => {
            let _db = open_db(db_path)?;
            let host = stop_bots::hostconf::HostConf::load()?;
            say!("Web server:     {}", host.web_server().label());
            print_server_settings(&host)
        }
    }
}

/// Stores `settings` for `server`, and with `choose` makes it the host's
/// web server, then prints what is in effect for it.
fn store_server_settings(
    db_path: Option<PathBuf>,
    server: webserver::WebServer,
    choose: bool,
    settings: ServerSettings,
) -> Result<()> {
    use stop_bots::hostconf::HostConf;

    // Opened for the migration only, as in `set-log-paths`: these are the
    // host's settings now, in `hostconf::path()`, which only root writes.
    let _db = open_db(db_path)?;
    let path = stop_bots::hostconf::path();
    let mut host = HostConf::load_from(&path)?;
    let ServerSettings {
        test,
        reload,
        root,
        reset,
    } = settings;
    let changing = choose || reset || root.is_some() || test.is_some() || reload.is_some();
    if choose {
        // Nothing is switched while the server chosen now still has
        // stop-bots in its config: once the other is chosen, nothing would
        // ever find it there again (see `webserver::leftovers`). Taking it
        // out is `uninstall web-server`'s job, with its `--dry-run`, rather
        // than something a settings command does on the side.
        let current = host.web_server();
        if current != server {
            let current_root = HostConf {
                web_server: Some(current),
                ..host.clone()
            }
            .root(None);
            let left = webserver::leftovers(current, &current_root);
            if !left.is_empty() {
                let listed: Vec<String> = left
                    .iter()
                    .map(|path| format!("  {}", path.display()))
                    .collect();
                anyhow::bail!(
                    "{current} still has stop-bots in its config:\n{}\n\n\
                     Take it out first with `sudo stop-bots uninstall web-server` (it works on \
                     {current}, the web server chosen now; `--dry-run` shows what it would do), \
                     then choose {server} again.",
                    listed.join("\n"),
                    current = current.label(),
                    server = server.id(),
                );
            }
        }
        // NGINX is stored as no choice at all, which it is: the line is
        // left out, and a host that never chose Apache keeps a file the
        // releases before the choice existed can still read.
        host.web_server = (server != webserver::WebServer::Nginx).then_some(server);
    }
    let (test_field, reload_field, root_field) = match server {
        webserver::WebServer::Nginx => (
            &mut host.nginx_test_command,
            &mut host.nginx_reload_command,
            &mut host.nginx_root,
        ),
        webserver::WebServer::Apache => (
            &mut host.apache_test_command,
            &mut host.apache_reload_command,
            &mut host.apache_root,
        ),
    };

    if reset {
        *test_field = None;
        *reload_field = None;
        *root_field = None;
    }
    if let Some(root) = &root {
        // Made absolute, because the service that reads it does not run
        // where this did; not canonicalised, because a symlink an operator
        // chose deliberately is not this command's to resolve.
        *root_field =
            Some(std::path::absolute(root).with_context(|| {
                format!("{} is not a path this host can resolve", root.display())
            })?);
    }
    for (name, value, field) in [
        ("--test", &test, test_field),
        ("--reload", &reload, reload_field),
    ] {
        let Some(value) = value else { continue };
        // Parsed before it is stored, so an unbalanced quote is rejected
        // here rather than at the next reload — which could be a cron run
        // hours later with nobody watching.
        stop_bots::webserver::split_command(value)
            .with_context(|| format!("refusing to store an unusable command for {name}"))?;
        *field = Some(value.clone());
    }
    if changing {
        host.save_to(&path)?;
    }

    if choose {
        say!("Web server:     {}", server.label());
    }
    print_server_settings(&HostConf {
        web_server: Some(server),
        ..host
    })
}

/// The commands and root `host` resolves for its web server.
fn print_server_settings(host: &stop_bots::hostconf::HostConf) -> Result<()> {
    let commands = webserver::ServerCommands::from_host(host)?;
    say!("Test command:   {}", commands.test.join(" "));
    say!("Reload command: {}", commands.reload.join(" "));
    say!("Config root:    {}", host.root(None).display());
    Ok(())
}

fn set_block_response(db_path: Option<PathBuf>, response: BlockResponseArg) -> Result<()> {
    let db = open_db(db_path)?;
    let response: stop_bots::db::BlockResponse = response.into();
    db.set_block_response(response)?;
    say!("Block response set to {}", response.label());
    // Nothing on disk has changed yet, and silently leaving that implicit
    // is exactly how an admin ends up believing 444 is live while every
    // site still returns 403.
    say!("Run `stop-bots apply-blocks` to write it into the site configs.");
    Ok(())
}

fn set_country_selected(db_path: Option<PathBuf>, country: String, selected: bool) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_country_selected(&country, selected)?;
    say!(
        "{} country {country}",
        if selected { "Added" } else { "Removed" }
    );
    Ok(())
}

fn list_selected_countries(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let mode = db.get_geo_mode()?;
    let countries = db.list_selected_countries()?;
    if json {
        return stop_bots::output::print(&stop_bots::output::SelectedCountries {
            geo_mode: stop_bots::output::geo_mode_name(mode),
            countries,
        });
    }
    say!("Geo mode: {mode:?}");
    if countries.is_empty() {
        say!("No countries selected.");
        return Ok(());
    }
    for country in countries {
        say!("{}", terminal_safe(&country));
    }
    Ok(())
}

fn add_hosting_asn(db_path: Option<PathBuf>, asn: u32) -> Result<()> {
    use stop_bots::ipranges::hosting;

    let db = open_db(db_path)?;
    let added = db.add_hosting_asn(asn)?;
    let stored = db.list_hosting_asns()?.into_iter().find(|a| a.asn == asn);
    let description = stored.as_ref().and_then(|a| a.description.clone());
    let label = terminal_safe(&hosting::label(asn, description.as_deref())).into_owned();
    if !added {
        say!("{label} is already blocked.");
        return Ok(());
    }
    say!("{label} is now blocked.");
    say!("Warning: {}.", hosting::warning());
    if let Some(note) = hosting::curated(asn).and_then(|p| p.note) {
        say!("{note}");
    }
    say!("{}", cloud_port_80_line(db.get_cloud_port_80_open()?));
    if stored.is_none_or(|a| a.last_fetched_at.is_none()) {
        say!(
            "No ranges stored yet — run `stop-bots update-hosting-asns` first, or this does \
             nothing."
        );
    }
    say!("Run render-firewall, then apply the script, to enforce it.");
    Ok(())
}

fn remove_hosting_asn(db_path: Option<PathBuf>, asn: u32) -> Result<()> {
    use stop_bots::ipranges::hosting;

    let db = open_db(db_path)?;
    let description = db
        .list_hosting_asns()?
        .into_iter()
        .find(|a| a.asn == asn)
        .and_then(|a| a.description);
    let label = terminal_safe(&hosting::label(asn, description.as_deref())).into_owned();
    if !db.remove_hosting_asn(asn)? {
        say!("{label} was not blocked.");
        return Ok(());
    }
    say!("{label} is no longer blocked, and its ranges are forgotten.");
    say!("Run render-firewall, then apply the script, to enforce it.");
    Ok(())
}

/// Every provider on the built-in list, in its order, then every other
/// selected AS number, by number: what `list-hosting-asns` shows.
fn hosting_asn_rows(db: &Db) -> Result<Vec<stop_bots::output::HostingAsnRow>> {
    use stop_bots::ipranges::hosting::{self, HOSTING_PROVIDERS};

    let selected = db.list_hosting_asns()?;
    let row = |asn: u32| {
        let stored = selected.iter().find(|a| a.asn == asn);
        let description = stored.and_then(|a| a.description.clone());
        stop_bots::output::HostingAsnRow {
            asn,
            name: hosting::display_name(asn, description.as_deref()),
            curated: hosting::curated(asn).is_some(),
            blocked: stored.is_some(),
            last_fetched_at: stored.and_then(|a| a.last_fetched_at),
            range_count: stored.map_or(0, |a| a.range_count),
            note: hosting::curated(asn).and_then(|p| p.note),
            description,
        }
    };
    Ok(HOSTING_PROVIDERS
        .iter()
        .map(|p| p.asn)
        .chain(
            selected
                .iter()
                .map(|a| a.asn)
                .filter(|asn| hosting::curated(*asn).is_none()),
        )
        .map(row)
        .collect())
}

fn list_hosting_asns(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let asns = hosting_asn_rows(&db)?;
    if json {
        return stop_bots::output::print(&stop_bots::output::HostingAsns {
            asns,
            warning: stop_bots::ipranges::hosting::warning(),
        });
    }
    for row in &asns {
        let state = if row.blocked { "ON " } else { "OFF" };
        let ranges = match (row.blocked, row.last_fetched_at) {
            (false, _) => String::new(),
            (true, None) => "not fetched".to_string(),
            (true, Some(_)) => format!("{} range(s)", row.range_count),
        };
        say!(
            "[{state}] {:<9} {:<22} {ranges}",
            format!("AS{}", row.asn),
            terminal_safe(&row.name)
        );
    }
    say!("Blocking one {}.", stop_bots::ipranges::hosting::warning());
    for row in asns.iter().filter(|row| row.note.is_some()) {
        say!("AS{}: {}", row.asn, row.note.unwrap_or_default());
    }
    Ok(())
}

async fn update_hosting_asns(
    db_path: Option<PathBuf>,
    asn: Option<u32>,
    source: Option<PathBuf>,
) -> Result<()> {
    use stop_bots::ipranges::hosting;

    let db = open_db(db_path)?;
    let selected: Vec<u32> = db.list_hosting_asns()?.into_iter().map(|a| a.asn).collect();
    let asns = match asn {
        Some(asn) if !selected.contains(&asn) => anyhow::bail!(
            "AS{asn} is not blocked, so its ranges would not be kept — \
             `stop-bots add-hosting-asn --asn {asn}` first"
        ),
        Some(asn) => vec![asn],
        None => selected,
    };
    if asns.is_empty() {
        say!(
            "No hosting provider is blocked, so there is nothing to update \
             (`add-hosting-asn`; `list-hosting-asns` names them)."
        );
        return Ok(());
    }
    let lines = match &source {
        Some(path) => {
            let raw = std::fs::read(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            hosting::select_lines(&raw, &asns)?
        }
        None => hosting::fetch(&asns)
            .await
            .with_context(|| format!("failed to update from {}", hosting::SOURCE_NAME))?,
    };
    let stored = hosting::store(&db, &asns, &lines)?;
    let names: std::collections::HashMap<u32, Option<String>> = db
        .list_hosting_asns()?
        .into_iter()
        .map(|a| (a.asn, a.description))
        .collect();
    let label = |asn: u32| {
        terminal_safe(&hosting::label(
            asn,
            names.get(&asn).and_then(Option::as_deref),
        ))
        .into_owned()
    };
    for (asn, count) in &stored.stored {
        say!("Stored {count} range(s) for {}", label(*asn));
    }
    let mut failed: Vec<String> = stored
        .missing
        .iter()
        .map(|asn| {
            format!(
                "{}: not in the table — no network announces it; check the number",
                label(*asn)
            )
        })
        .collect();
    failed.extend(
        stored
            .refused
            .iter()
            .map(|(asn, why)| format!("{}: {why}", label(*asn))),
    );
    each_or_fail(failed)
}

/// What `render-firewall` says on stderr about the lockout guard, before
/// the outcome: the warning names every client at risk, and an unreadable
/// log is a note on a write and a refusal on an apply.
fn report_lockout_guard(outcome: &stop_bots::firewall::FirewallOutcome) {
    match &outcome.guard {
        stop_bots::firewall::Guard::LogUnreadable => say_err!(
            "Note: couldn't read any SSH log (tried the stored path, /var/log/auth.log, \
             /var/log/secure and journalctl), so the lockout safety check could not run.{} Run as root, or pass \
             --ssh-log, for this check to work.",
            if outcome.apply == stop_bots::firewall::ApplyStep::NotAsked {
                " The script is written anyway: it is not applied."
            } else {
                ""
            }
        ),
        stop_bots::firewall::Guard::Ran(risks) if !risks.is_empty() => print_lockout_warning(risks),
        stop_bots::firewall::Guard::NoLogins { .. } => say_err!(
            "Note: {}. {}.",
            outcome.guard.describe(),
            stop_bots::firewall::NO_LOGINS_CLI_FIX
        ),
        stop_bots::firewall::Guard::Ran(_) | stop_bots::firewall::Guard::Off => {}
    }
}

fn print_lockout_warning(risks: &[(String, String)]) {
    say_err!(
        "WARNING: these firewall rules would block {} currently-connected SSH client IP address(es):",
        risks.len()
    );
    for (ip, cidr) in risks {
        say_err!("  {ip} (blocked by {cidr})");
    }
    say_err!("Applying them could lock you out of remote access to this machine.");
}

impl From<FirewallBackend> for stop_bots::firewall::FirewallBackend {
    fn from(backend: FirewallBackend) -> Self {
        match backend {
            FirewallBackend::Iptables => stop_bots::firewall::FirewallBackend::Iptables,
            FirewallBackend::Nftables => stop_bots::firewall::FirewallBackend::Nftables,
        }
    }
}

/// Which backend a render is for and where its script goes, for
/// `render-firewall` and `batch` alike.
///
/// An explicit `--backend` wins; without one, the host's own setting does,
/// and the default path follows whichever backend that turned out to be.
/// Both used to be fixed instead: `batch`'s flag carried an `nftables`
/// default, so a host switched to iptables got an nftables
/// script from every cron run — at the *other* path, so both files existed
/// and one was always stale — and `render-firewall` required `--backend`
/// and defaulted `--out` to `.nft` even for iptables, leaving a shell
/// script in a file named for nftables.
fn firewall_target(
    db: &Db,
    backend: Option<FirewallBackend>,
    out: Option<PathBuf>,
) -> Result<(stop_bots::firewall::FirewallBackend, PathBuf)> {
    let backend = match backend {
        Some(backend) => backend.into(),
        None => {
            // A database that has never chosen: whichever this host has.
            stop_bots::firewall::seed_backend(db, stop_bots::firewall::Installed::detect())?;
            stop_bots::firewall::stored_backend(db)?
        }
    };
    let out = out.unwrap_or_else(|| stop_bots::firewall::default_output_path(backend));
    Ok((backend, out))
}

/// `render-firewall`, through the one path every front-end shares (see
/// `firewall::FirewallRun` for the policy).
///
/// Without `--out` the script goes beside the applied one — the file the
/// boot unit loads — and `--apply` is what promotes it. With `--out` alone
/// it goes where the operator said, to read; running it by hand would not
/// survive a reboot, so the hint still points at `--apply`. With both,
/// `--out` names the applied script, as it does for `batch`.
fn render_firewall(db_path: Option<PathBuf>, request: RenderRequest) -> Result<()> {
    use stop_bots::firewall::{ApplyStep, WriteStep};

    let db = open_db(db_path)?;
    let named = if request.apply {
        request.out.clone()
    } else {
        None
    };
    let (backend, applied) = firewall_target(&db, request.backend, named)?;
    let mut run = stop_bots::firewall::FirewallRun::new(backend, applied)
        .apply(request.apply)
        .force(request.force)
        .confirm(request.confirm)
        .protect(stop_bots::sshlog::session_client());
    if let (Some(out), false) = (&request.out, request.apply) {
        run = run.rendered_at(out);
    }
    // The flag, else the path `set-log-paths` stored, else the search.
    let source = host_settings()?.log_paths().ssh(request.ssh_log.as_deref());
    let outcome = stop_bots::firewall::render_and_apply(
        &db,
        run,
        stop_bots::firewall::SshLog::Read(&source),
    )?;

    report_lockout_guard(&outcome);
    let rendered = outcome.rendered_path.display();
    match (&outcome.write, &outcome.apply) {
        (WriteStep::Refused, _) => anyhow::bail!(
            "Refusing to write firewall rules: would block a currently-connected SSH client. \
             Re-run with --force if you're sure."
        ),
        (WriteStep::Failed(err), _) => anyhow::bail!("{err}"),
        // Running this file by hand would enforce it until the next boot
        // and no longer: the boot unit loads the applied script, which only
        // `--apply` replaces. So the hint names the apply, not `nft -f`.
        (WriteStep::Written, ApplyStep::NotAsked) if request.out.is_some() => say!(
            "Wrote {} rule(s) to {rendered}, which nothing loads at boot. Not applied — to \
             apply them, run `stop-bots render-firewall --apply`: it checks for a lockout again, \
             runs the script, and makes it the one loaded at boot ({}).",
            outcome.entries,
            outcome.applied_path.display()
        ),
        (WriteStep::Written, ApplyStep::NotAsked) => say!(
            "Wrote {} rule(s) to {rendered}. Not applied — review it, then run \
             `stop-bots render-firewall --apply`, which checks for a lockout again, runs it, and \
             makes it the script loaded at boot ({}).",
            outcome.entries,
            outcome.applied_path.display()
        ),
        (WriteStep::Written, ApplyStep::Refused) => {
            anyhow::bail!("{}. --force overrides this.", outcome.summary())
        }
        (WriteStep::Written, ApplyStep::AwaitingConfirmation(pending)) => {
            say!("{}.", capitalised(&outcome.summary()));
            let timeout = std::time::Duration::from_secs(pending.timeout_secs().max(1) as u64);
            let answer = stop_bots::revert::ask_on_terminal(timeout);
            settle_on_terminal(&db, &outcome, pending, answer)?;
        }
        _ if outcome.succeeded() => say!("{}", capitalised(&outcome.summary())),
        _ => anyhow::bail!("{}", outcome.summary()),
    }
    Ok(())
}

/// `render-firewall`'s flags, gathered.
struct RenderRequest {
    backend: Option<FirewallBackend>,
    out: Option<PathBuf>,
    apply: bool,
    force: bool,
    ssh_log: Option<PathBuf>,
    confirm: Option<std::time::Duration>,
}

/// Keeps or reverts an apply as the operator answered, says which, and
/// records a kept one as applied. A revert is an error: what was asked
/// for did not stay.
fn settle_on_terminal(
    db: &Db,
    outcome: &stop_bots::firewall::FirewallOutcome,
    pending: &stop_bots::revert::Pending,
    answer: stop_bots::revert::Answer,
) -> Result<()> {
    use stop_bots::revert::Settled;
    let tools = stop_bots::revert::Tools::host();
    match stop_bots::revert::settle(&tools, pending, &outcome.script, answer)? {
        Settled::Kept(message) => {
            db.set_firewall_applied_signature(&outcome.signature)?;
            say!("{message}.");
            Ok(())
        }
        Settled::Reverted(message) => anyhow::bail!("{message}."),
        Settled::Nothing(message) => {
            say!("{message}.");
            Ok(())
        }
    }
}

/// `revert-firewall`: by hand, or as the timer an unconfirmed apply armed
/// (`--token`, and `--after` where there is no systemd to wait for it).
fn revert_firewall(
    db_path: Option<PathBuf>,
    backend: Option<FirewallBackend>,
    out: Option<PathBuf>,
    token: Option<String>,
    after: Option<u64>,
) -> Result<()> {
    use stop_bots::revert::{Settled, Why};
    if let Some(secs) = after {
        std::thread::sleep(std::time::Duration::from_secs(secs));
    }
    // The timer passes both; it must not need the database, which a
    // revert at the wrong moment could find locked or mid-upgrade.
    let (backend, applied) = match (backend, out.clone()) {
        (Some(backend), Some(out)) => (backend.into(), out),
        (backend, out) => firewall_target(&open_db(db_path.clone())?, backend, out)?,
    };
    let why = if token.is_some() {
        Why::NoAnswer
    } else {
        Why::Manual
    };
    let tools = stop_bots::revert::Tools::host();
    let settled = stop_bots::revert::revert(&tools, &applied, backend, token.as_deref(), why)?;
    // Going back by hand loads rules the database did not apply, so it no
    // longer says the current ones are.
    if token.is_none() && matches!(settled, Settled::Reverted(_)) {
        if let Ok(db) = open_db(db_path) {
            let _ = db.set_firewall_applied_signature("");
        }
    }
    say!("{}.", settled.message());
    Ok(())
}

/// `text` with its first letter upper-cased: the shared summaries are
/// written to sit inside other sentences.
fn capitalised(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The detectors that take a threshold, as the command line names them:
/// "a, b and c".
fn counting_detectors() -> String {
    let names: Vec<&str> = DetectorArg::ALL
        .into_iter()
        .filter(|d| d.0.threshold_setting().is_some())
        .map(DetectorArg::name)
        .collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{} and {last}", rest.join(", ")),
        _ => names.join(""),
    }
}

/// `run-detector`: one detector over a whole log, now. The five that had
/// a verb of their own before keep their wording; the rest share one.
fn run_detector(
    db_path: Option<PathBuf>,
    detector: Detector,
    threshold: Option<usize>,
    ttl_days: Option<i64>,
    ssh_log: Option<PathBuf>,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let name = stop_bots::blocks::detector_name(detector);
    if threshold.is_some() && detector.threshold_setting().is_none() {
        anyhow::bail!(
            "{name} has no threshold: one matching request is already conclusive (the ones \
             that have one are {})",
            counting_detectors()
        );
    }
    if detector == Detector::SshScanners && access_log.is_some() {
        anyhow::bail!("ssh-scanners reads the SSH log: give --ssh-log, not --access-log");
    }
    if detector != Detector::SshScanners && ssh_log.is_some() {
        anyhow::bail!("{name} reads the access log: give --access-log, not --ssh-log");
    }
    match detector {
        Detector::SshScanners => block_scanners(db_path, threshold, ttl_days, ssh_log, dry_run),
        Detector::WebScanners => {
            block_web_scanners(db_path, threshold, ttl_days, access_log, dry_run)
        }
        Detector::SpoofedCrawlers => block_spoofed_crawlers(db_path, ttl_days, access_log, dry_run),
        Detector::ProbePaths => block_probe_paths(db_path, ttl_days, access_log, dry_run),
        Detector::Honeypot => block_honeypot(db_path, ttl_days, access_log, dry_run),
        Detector::Injection
        | Detector::RobotsTxt
        | Detector::AssetRatio
        | Detector::RotatingUserAgent
        | Detector::RefererlessCrawl
        | Detector::LoginAttempts
        | Detector::RequestRate
        | Detector::RobotsViolators => {
            let db = open_db(db_path)?;
            let ttl_days = match ttl_days {
                Some(days) => days,
                None => detector.ttl_days(&db)?,
            };
            let log_text = read_access_log(&db, access_log.as_deref())?;
            use stop_bots::scanblock as sb;
            let outcome = match detector {
                Detector::Injection => sb::block_injection(&db, ttl_days, &log_text, dry_run)?,
                Detector::RobotsTxt => sb::block_robots_txt(&db, ttl_days, &log_text, dry_run)?,
                Detector::AssetRatio => {
                    sb::block_asset_ratio(&db, ttl_days, &log_text, threshold, dry_run)?
                }
                Detector::RotatingUserAgent => {
                    sb::block_rotating_ua(&db, ttl_days, &log_text, threshold, dry_run)?
                }
                Detector::LoginAttempts => {
                    sb::block_login_attempts(&db, ttl_days, &log_text, threshold, dry_run)?
                }
                Detector::RequestRate => {
                    sb::block_request_rate(&db, ttl_days, &log_text, threshold, dry_run)?
                }
                Detector::RobotsViolators => {
                    sb::block_robots_violators(&db, ttl_days, &log_text, dry_run)?
                }
                _ => sb::block_refererless(&db, ttl_days, &log_text, threshold, dry_run)?,
            };
            if outcome.candidates == 0 {
                say!("{} found nothing to block.", detector.spec().label);
                return Ok(());
            }
            print_scan_block_outcome(&outcome);
            Ok(())
        }
    }
}

/// Finds scanning IPs in the SSH log and adds a temporary Block rule for
/// each — see [`stop_bots::scanblock::block_ssh_scanners`] for the shared
/// detection/insertion logic (also used by the internal cron's
/// `BlockScanners` job). This CLI wrapper only resolves the log source and
/// reconstructs the on-screen messages from the returned outcome.
fn block_scanners(
    db_path: Option<PathBuf>,
    threshold: Option<usize>,
    ttl_days: Option<i64>,
    ssh_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let (threshold, ttl_days) = detector_defaults(&db, Detector::SshScanners, threshold, ttl_days)?;

    let log_text = read_ssh_log(&db, ssh_log.as_deref())?;

    let outcome =
        stop_bots::scanblock::block_ssh_scanners(&db, threshold, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        say!("No scanning IPs found (threshold: {threshold} failed attempt(s)).");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

/// Finds IPs whose NGINX access-log traffic looks like an automated URL
/// scanner and adds a temporary Block rule for each — see
/// [`stop_bots::scanblock::block_web_scanners`] for the shared
/// detection/exclusion/insertion logic (also used by the internal cron's
/// `BlockWebScanners` job). This CLI wrapper only resolves the log source
/// and reconstructs the on-screen messages from the returned outcome.
fn block_web_scanners(
    db_path: Option<PathBuf>,
    threshold: Option<usize>,
    ttl_days: Option<i64>,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let (threshold, ttl_days) = detector_defaults(&db, Detector::WebScanners, threshold, ttl_days)?;

    let log_text = read_access_log(&db, access_log.as_deref())?;

    let outcome =
        stop_bots::scanblock::block_web_scanners(&db, threshold, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        say!("No scanning IPs found (threshold: {threshold} distinct 404'd path(s)).");
        return Ok(());
    }
    if !outcome.crawler_exclusion_active {
        say!(
            "Warning: no crawler IP ranges fetched yet (run update-crawler-ranges --source-id \
             googlebot/bingbot/gptbot first) — known-crawler exclusion is inactive, so a \
             legitimate search crawler chasing stale links could be flagged below."
        );
    }
    if outcome.skipped_known_crawlers > 0 {
        say!(
            "Skipped {} IP(s) matching known crawler ranges (Googlebot/Bingbot/GPTBot) — never \
             auto-blocked here, even when their 404 behavior looks scan-like.",
            outcome.skipped_known_crawlers
        );
    }
    if outcome.newly_blocked.is_empty() && outcome.already_covered == 0 {
        say!("No scanning IPs left to block after excluding known crawlers.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn block_spoofed_crawlers(
    db_path: Option<PathBuf>,
    ttl_days: Option<i64>,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let ttl_days = match ttl_days {
        Some(days) => days,
        None => Detector::SpoofedCrawlers.ttl_days(&db)?,
    };

    let log_text = read_access_log(&db, access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_spoofed_crawlers(&db, ttl_days, &log_text, dry_run)?;

    // Distinct from "found nothing": with no ranges stored there was
    // nothing to check against, so a clean result here means the detector
    // never ran, not that the log is clean.
    if !outcome.crawler_exclusion_active {
        say!(
            "No crawler IP ranges fetched yet — run `stop-bots update-crawler-ranges --source-id \
             googlebot` (and bingbot/gptbot) first. Nothing was checked."
        );
        return Ok(());
    }
    if outcome.candidates == 0 {
        say!("No forged crawler user agents found.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn block_probe_paths(
    db_path: Option<PathBuf>,
    ttl_days: Option<i64>,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let ttl_days = match ttl_days {
        Some(days) => days,
        None => Detector::ProbePaths.ttl_days(&db)?,
    };

    let log_text = read_access_log(&db, access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_probe_paths(&db, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        say!("No probe-path requests found.");
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn set_probe_paths(db_path: Option<PathBuf>, paths: String) -> Result<()> {
    let db = open_db(db_path)?;
    db.set_text_setting(stop_bots::protection::PROBE_PATHS_EXTRA, &paths)?;
    let accepted = stop_bots::protection::extra_probe_paths(&db)?;
    say!("Extra probe paths set ({} accepted).", accepted.len());
    // Report what was dropped rather than silently ignoring it: finding
    // that out from a detector that never fires, or one that fires on
    // everyone, is much worse.
    let offered = paths
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count();
    if offered > accepted.len() {
        say!(
            "Ignored {} entr(y/ies) that don't start with '/' or name nothing after it — \
             each is looked for at the start of a path segment, and '/' alone is in every \
             request.",
            offered - accepted.len()
        );
    }
    Ok(())
}

fn list_probe_paths(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let extra = stop_bots::protection::extra_probe_paths(&db)?;
    let enabled = stop_bots::protection::app_probe_paths(&db)?;
    let new_here = stop_bots::protection::app_probe_paths_is_new_here(&db)?;
    let probes = stop_bots::logscan::app_probes(&db)?;
    let conditional: Vec<stop_bots::output::ConditionalProbePath> = probes
        .host()
        .iter()
        .map(|(path, verdict)| stop_bots::output::ConditionalProbePath {
            path: format!("/{path}"),
            apps: stop_bots::webapps::apps_serving(path),
            active: enabled && *verdict == stop_bots::webapps::Verdict::Probe,
            reason: verdict.reason().map(str::to_string),
        })
        .collect();
    if json {
        return stop_bots::output::print(&stop_bots::output::ProbePaths {
            built_in: stop_bots::accesslog::DEFAULT_PROBE_PATHS
                .iter()
                .map(ToString::to_string)
                .collect(),
            extra,
            conditional: stop_bots::output::ConditionalProbePaths {
                enabled,
                new_in_this_release: new_here,
                paths: conditional,
            },
        });
    }
    say!("Built-in (always checked):");
    for path in stop_bots::accesslog::DEFAULT_PROBE_PATHS {
        say!("  {path}");
    }
    if extra.is_empty() {
        say!("Extra: none (set with set-probe-paths)");
    } else {
        say!("Extra:");
        for path in &extra {
            say!("  {}", terminal_safe(path));
        }
    }
    say!(
        "{} Each of these is a probe only where no site runs its application:",
        app_aware_line(&db)?
    );
    for path in &conditional {
        let state = match (&path.reason, path.active) {
            (_, true) => "probe on this host".to_string(),
            (None, false) => "would be a probe on this host".to_string(),
            (Some(why), false) => format!("not a probe: {why}"),
        };
        say!(
            "  {:<15} {:<20} {}",
            path.path,
            path.apps.join(", "),
            terminal_safe(&state)
        );
    }
    say!(
        "A request whose log line names its site ($host) is judged by that site alone; \
         one that names none, by every site on the host."
    );
    Ok(())
}

/// Whether app-aware probe paths are on, as `list-probe-paths` and
/// `set-detector probe-paths --app-aware` say it.
fn app_aware_line(db: &Db) -> Result<String> {
    use stop_bots::protection::{app_probe_paths, app_probe_paths_is_new_here};
    let state = if app_probe_paths_is_new_here(db)? {
        "off (new in this release: `stop-bots set-detector probe-paths --app-aware true` \
         turns it on)"
    } else {
        on_off(app_probe_paths(db)?)
    };
    Ok(format!("Probes for absent apps: {state}."))
}

fn block_honeypot(
    db_path: Option<PathBuf>,
    ttl_days: Option<i64>,
    access_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let ttl_days = match ttl_days {
        Some(days) => days,
        None => Detector::Honeypot.ttl_days(&db)?,
    };

    let log_text = read_access_log(&db, access_log.as_deref())?;

    let outcome = stop_bots::scanblock::block_honeypot(&db, ttl_days, &log_text, dry_run)?;
    if outcome.candidates == 0 {
        say!(
            "Nothing fetched the honeypot path ({}).",
            stop_bots::protection::honeypot_path(&db)?
        );
        return Ok(());
    }
    print_scan_block_outcome(&outcome);
    Ok(())
}

fn set_honeypot_path(db_path: Option<PathBuf>, path: String) -> Result<()> {
    let db = open_db(db_path)?;
    // Rejected loudly rather than stored and silently ignored — see
    // `validate_honeypot_path` for what each refusal protects.
    let trimmed = &stop_bots::protection::validate_honeypot_path(&path)?;
    db.set_text_setting(stop_bots::protection::HONEYPOT_PATH, trimmed)?;
    say!("Honeypot path set to {trimmed}");
    say!(
        "It only catches anything once it's published — enable robots.txt generation, or add a \
         Disallow line for it yourself."
    );
    Ok(())
}

/// A detector subcommand's threshold and TTL: the flag if one was given,
/// else what is stored — the values the internal cron and `batch` use, so
/// running a detector by hand behaves like the scheduled pass unless told
/// otherwise.
fn detector_defaults(
    db: &Db,
    detector: Detector,
    threshold: Option<usize>,
    ttl_days: Option<i64>,
) -> Result<(usize, i64)> {
    let threshold = match threshold {
        Some(value) => value,
        None => detector
            .threshold(db)?
            .context("this detector has no threshold")?,
    };
    let ttl_days = match ttl_days {
        Some(days) => days,
        None => detector.ttl_days(db)?,
    };
    Ok((threshold, ttl_days))
}

/// Reads the NGINX access log for a detector subcommand: `--access-log` if
/// given, the conventional path otherwise.
///
/// Every access-log detector needs exactly this, including the same failure
/// message — the two likely causes are a non-standard path and not being
/// root, and naming both is what turns "couldn't read the log" from a dead
/// end into something actionable. Shared so a sixth detector can't quietly
/// ship a seventh wording of it.
fn read_access_log(db: &Db, access_log: Option<&Path>) -> Result<String> {
    // Through `LogPaths`, so a CLI run reads the same file the TUI and the
    // schedule do. Before this, `set-log-paths` could be set and a
    // detector invoked by hand would still go to the default -- two answers
    // to one question, which is the shape of bug this whole type removes.
    let _ = db;
    let host = host_settings().unwrap_or_default();
    let server = host.web_server().label();
    let paths = host.log_paths();
    match paths.access_source(access_log) {
        accesslog::LogSource::Found(text) => Ok(text),
        // Name the path that was actually tried, not the one the reader
        // might assume -- and say where a stored one came from, since an
        // operator who set it and still sees this needs to know it was used.
        accesslog::LogSource::Unavailable => {
            let tried = paths.access_description(access_log);
            match (access_log, &paths.access) {
                (Some(_), _) => anyhow::bail!(
                    "couldn't read the {server} access log at {tried} — pass a different \
                     --access-log, or run as root, for this to work"
                ),
                (None, Some(_)) => anyhow::bail!(
                    "couldn't read the {server} access log at {tried}, the path stored by \
                     `set-log-paths` — check it exists, or run as root"
                ),
                (None, None) => anyhow::bail!(
                    "couldn't read the {server} access log (tried {tried}) — set one with \
                     `stop-bots set-log-paths --access-log <path>`, pass --access-log, \
                     or run as root"
                ),
            }
        }
    }
}

/// The SSH-log counterpart of [`read_access_log`]. Separate rather than
/// generic over the two `LogSource` types: they are distinct enums with
/// distinct fallback chains, and the error text has to name the right
/// paths and the right flag to be worth printing at all.
fn read_ssh_log(db: &Db, ssh_log: Option<&Path>) -> Result<String> {
    // Through `LogPaths`, like `read_access_log`: a stored path is read
    // when no flag names one. The journal is read back a week, not whole.
    let _ = db;
    let paths = host_settings().unwrap_or_default().log_paths();
    let named = ssh_log.or(paths.ssh.as_deref());
    match paths.ssh(ssh_log).read(sshlog::recent_since()) {
        sshlog::LogSource::Found(text) => Ok(text),
        // Two different failures, and saying the wrong one costs real time.
        // An explicit path is read and nothing else is tried, so claiming a
        // search happened sends the reader looking for a bug in the
        // fallback chain instead of at the path they passed — which is
        // exactly how a service pinned to a missing auth.log stayed
        // invisible on a journald-only host.
        sshlog::LogSource::Unavailable => match named {
            Some(path) => anyhow::bail!(
                "couldn't read the SSH log at {} — that path was given explicitly (by \
                 --ssh-log or `set-log-paths`), so /var/log/secure and journalctl were not \
                 tried. Point it somewhere readable, or run as root.",
                path.display()
            ),
            None => anyhow::bail!(
                "couldn't read any SSH log (tried /var/log/auth.log, /var/log/secure, \
                 journalctl) — pass --ssh-log, or run as root, for this to work"
            ),
        },
    }
}

/// Prints the per-IP and summary lines shared by [`block_scanners`] and
/// [`block_web_scanners`], reconstructing the wording each used to print
/// directly (back when the detection/insertion logic itself lived here)
/// from the [`stop_bots::scanblock::ScanBlockOutcome`] it now gets handed.
fn print_scan_block_outcome(outcome: &stop_bots::scanblock::ScanBlockOutcome) {
    for ip in &outcome.newly_blocked {
        let (days, offence) = match outcome.repeat_offenders.iter().find(|r| &r.address == ip) {
            Some(r) => (
                r.ttl_days,
                format!(
                    ", its {} offence",
                    stop_bots::protection::ordinal(r.offence)
                ),
            ),
            None => (outcome.ttl_days, String::new()),
        };
        if outcome.dry_run {
            say!("Would block {ip} for {days} day(s){offence} (dry run)");
        } else {
            say!("Added block rule for {ip}, expiring in {days} day(s){offence}");
        }
    }
    if outcome.skipped_unblocked > 0 {
        say!(
            "Left {} alone: unblocked by hand recently (trust an address to exempt it for good).",
            outcome.skipped_unblocked
        );
    }
    if outcome.newly_blocked.is_empty() {
        say!(
            "Found {} {}(s), all already covered by an existing firewall rule.",
            outcome.already_covered,
            outcome.kind.noun()
        );
    } else if outcome.dry_run {
        say!(
            "Would add {} new block rule(s), expiring after {} day(s) unless a repeat offender's \
             is longer. Re-run without --dry-run to apply.",
            outcome.newly_blocked.len(),
            outcome.ttl_days
        );
    } else if !outcome.repeat_offenders.is_empty() {
        say!(
            "Added {} new block rule(s), expiring after {} day(s), or longer for the {} \
             repeat offender(s). Not applied automatically — run render-firewall, then apply \
             the generated script, to actually enforce them.",
            outcome.newly_blocked.len(),
            outcome.ttl_days,
            outcome.repeat_offenders.len()
        );
    } else {
        say!(
            "Added {} new block rule(s), each expiring after {} day(s). Not applied \
             automatically — run render-firewall, then apply the generated script, to actually \
             enforce them (and again after they expire, to actually lift the block).",
            outcome.newly_blocked.len(),
            outcome.ttl_days
        );
    }
}

/// Reads what was appended to the NGINX access log since the last read and
/// records successful-request user-agent counts: one pass of
/// [`stop_bots::logscan`], the same the internal cron's `RecordAccessStats`
/// job makes. This CLI wrapper only prints the outcome's summary.
fn record_access_stats(db_path: Option<PathBuf>, access_log: Option<PathBuf>) -> Result<()> {
    let db = open_db(db_path)?;

    // The same pass the internal cron makes, from the same cursor, keyed by
    // the path actually read: what the schedule already tallied is not
    // tallied again, and what this reads the detectors see too.
    let host = host_settings()?;
    let flags = stop_bots::logscan::Flags {
        ssh_log: None,
        access_log,
        stored: host.log_paths(),
    };
    let applied =
        stop_bots::logscan::run(&db, &[stop_bots::cron::CronJob::RecordAccessStats], &flags)?;
    if let stop_bots::logscan::Availability::Unavailable(tried) = &applied.access {
        anyhow::bail!(
            "couldn't read the {} access log at {tried} — pass --access-log, set one with \
             `stop-bots set-log-paths --access-log <path>`, or run as root",
            host.web_server().label()
        );
    }
    say!("{}", applied.stats.summary());
    Ok(())
}

/// Lists every recorded user agent's accumulated hit count, most-seen
/// first (see [`stop_bots::db::Db::list_user_agent_stats`]).
fn list_access_stats(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open_db(db_path)?;
    let stats = db.list_user_agent_stats()?;
    if json {
        let user_agents = stats
            .into_iter()
            .map(|stat| stop_bots::output::AccessStatRow {
                user_agent: stat.user_agent,
                hit_count: stat.hit_count,
                last_seen_at: stat.last_seen_at,
            })
            .collect();
        return stop_bots::output::print(&stop_bots::output::AccessStats { user_agents });
    }
    if stats.is_empty() {
        say!("No user-agent stats recorded yet — run record-access-stats first.");
        return Ok(());
    }
    for stat in stats {
        say!("{:>8}  {}", stat.hit_count, terminal_safe(&stat.user_agent));
    }
    Ok(())
}

/// Runs the maintenance the internal cron runs daily, right now, and
/// prints what it did.
///
/// Prints the before/after sizes rather than only the summary line the
/// Dashboard shows: someone reaching for this has just looked at `du` and
/// wants the same number to have moved.
fn maintain(db_path: Option<PathBuf>, force_compact: bool) -> Result<()> {
    let db = open_db(db_path)?;

    let before = db.size_on_disk()?;
    if let Some(size) = before {
        say!(
            "Database is {} ({} reclaimable).",
            stop_bots::health::human_bytes(size.bytes),
            stop_bots::health::human_bytes(size.free_bytes)
        );
    }

    let summary = stop_bots::cron::maintenance(&db);
    say!("{summary}");

    // `cron::maintenance` compacts only when the slack is worth the
    // rewrite. `--force-compact` is for the case its thresholds are wrong
    // for this host — most usefully right after an upgrade that freed a
    // lot at once, where waiting for the next scheduled run would leave
    // the file at its old size for a day.
    if force_compact {
        let reclaimed = db.vacuum()?;
        say!(
            "Compacted anyway: reclaimed {}.",
            stop_bots::health::human_bytes(reclaimed)
        );
    }

    if let (Some(before), Ok(Some(after))) = (before, db.size_on_disk()) {
        if after.bytes < before.bytes {
            say!(
                "Now {} — down from {}.",
                stop_bots::health::human_bytes(after.bytes),
                stop_bots::health::human_bytes(before.bytes)
            );
        }
    }
    // Recording the run last means an interrupted maintenance leaves the
    // job due rather than looking done.
    stop_bots::cron::record_run(&db, stop_bots::cron::CronJob::Maintenance, &summary);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- `--help` ----
    //
    // Doc comments on `Command` used to slide onto the wrong variant: a
    // variant with no comment of its own silently took the next one's, so
    // `web --help` described the block response and `status` described
    // `batch`. Nothing failed, because every string was well-formed. These
    // walk the whole command tree instead of spot-checking a few verbs.

    use clap::CommandFactory;

    /// Every subcommand, by name, with its clap definition.
    fn subcommands() -> Vec<clap::Command> {
        Cli::command()
            .get_subcommands()
            .filter(|c| c.get_name() != "help")
            .cloned()
            .collect()
    }

    /// `ApplyBlocks` for `apply-blocks`: how a variant name leaks into
    /// help text written by someone looking at the enum.
    fn variant_name(command: &str) -> String {
        command
            .split('-')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => first.to_uppercase().chain(chars).collect(),
                    None => String::new(),
                }
            })
            .collect()
    }

    /// All the text `stop-bots <command> --help` prints that we wrote.
    fn help_texts(command: &clap::Command) -> Vec<(String, String)> {
        let name = command.get_name().to_string();
        let mut texts = Vec::new();
        for text in [command.get_about(), command.get_long_about()]
            .into_iter()
            .flatten()
        {
            texts.push((name.clone(), text.to_string()));
        }
        for arg in command.get_arguments() {
            for text in [arg.get_help(), arg.get_long_help()].into_iter().flatten() {
                texts.push((format!("{name} --{}", arg.get_id()), text.to_string()));
            }
        }
        texts
    }

    /// The `.deb` ships a man page per verb. One missing is a verb
    /// `man` knows nothing about; the packaging verb itself is hidden
    /// from both `--help` and the pages.
    #[test]
    fn every_visible_verb_gets_a_man_page_and_generate_docs_is_not_one() {
        let dir = tempfile::tempdir().unwrap();
        stop_bots::docs::generate(Cli::command(), dir.path()).unwrap();

        let page = |name: &str| dir.path().join(format!("man/{name}.1"));
        assert!(page("stop-bots").is_file());
        for command in subcommands().iter().filter(|c| !c.is_hide_set()) {
            let name = format!("stop-bots-{}", command.get_name());
            assert!(page(&name).is_file(), "no man page for `{name}`");
        }
        assert!(!page("stop-bots-generate-docs").exists());
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("generate-docs"), "{help}");
    }

    #[test]
    fn every_subcommand_has_a_description() {
        for command in subcommands() {
            let about = command
                .get_about()
                .map(|a| a.to_string())
                .unwrap_or_default();
            assert!(
                !about.trim().is_empty(),
                "`{}` has no description",
                command.get_name()
            );
        }
    }

    /// Two commands saying the same thing is how a misplaced doc comment
    /// shows up: one variant lost its text and inherited its neighbour's.
    #[test]
    fn no_two_subcommands_share_a_description() {
        let mut seen: std::collections::HashMap<String, String> = Default::default();
        for command in subcommands() {
            let about = command
                .get_about()
                .map(|a| a.to_string())
                .unwrap_or_default();
            if let Some(other) = seen.insert(about.clone(), command.get_name().to_string()) {
                panic!("`{}` and `{other}` both say {about:?}", command.get_name());
            }
        }
    }

    /// `batch` used to open "selected. One step's failure..." — the tail
    /// of a sentence whose start had been cut off onto `status`.
    #[test]
    fn every_description_starts_a_sentence() {
        for command in subcommands() {
            let about = command
                .get_about()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let first = about.chars().next().unwrap_or(' ');
            assert!(
                first.is_uppercase(),
                "`{}` starts mid-sentence: {about:?}",
                command.get_name()
            );
        }
    }

    #[test]
    fn every_flag_says_what_it_does() {
        for command in subcommands() {
            for arg in command.get_arguments() {
                let id = arg.get_id().as_str();
                if id == "help" || id == "version" {
                    continue;
                }
                let help = arg.get_help().map(|h| h.to_string()).unwrap_or_default();
                assert!(
                    !help.trim().is_empty(),
                    "`{} --{id}` has no help",
                    command.get_name()
                );
            }
        }
    }

    /// A reader types `apply-blocks`; `ApplyBlocks`, a table name or a
    /// Rust path means nothing to them and goes stale on a rename.
    #[test]
    fn help_text_names_commands_as_they_are_typed() {
        let variants: Vec<String> = subcommands()
            .iter()
            .map(|c| c.get_name())
            .filter(|name| name.contains('-'))
            .map(variant_name)
            .collect();
        let internal = ["stop_bots::", "firewall_rules", "user_agent_stats"];
        for command in subcommands() {
            for (place, text) in help_texts(&command) {
                for word in internal
                    .iter()
                    .copied()
                    .chain(variants.iter().map(String::as_str))
                {
                    assert!(!text.contains(word), "`{place}` says {word:?}:\n{text}");
                }
            }
        }
    }

    /// `run-detector probe-paths` printed its opening sentence twice, because the
    /// summary was repeated as the first paragraph of the long text.
    #[test]
    fn no_paragraph_of_a_command_s_help_is_repeated() {
        for command in subcommands() {
            let long = command
                .get_long_about()
                .map(|a| a.to_string())
                .unwrap_or_default();
            let mut paragraphs: Vec<String> = long
                .split("\n\n")
                .map(|p| p.split_whitespace().collect::<Vec<_>>().join(" "))
                .filter(|p| !p.is_empty())
                .collect();
            let count = paragraphs.len();
            paragraphs.sort();
            paragraphs.dedup();
            assert_eq!(
                paragraphs.len(),
                count,
                "`{}` repeats a paragraph:\n{long}",
                command.get_name()
            );
        }
    }

    /// clap's own consistency checks — duplicate ids, a global flag
    /// shadowed by a subcommand's own, conflicts naming missing args — run
    /// only when asked, and a debug build panics on them at startup.
    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    /// A script reads `status` and every `list-*` the same way, so one
    /// added later without `--json` fails here rather than in a script.
    #[test]
    fn status_and_every_list_command_take_json() {
        let listing: Vec<clap::Command> = subcommands()
            .into_iter()
            .filter(|c| c.get_name() == "status" || c.get_name().starts_with("list-"))
            .collect();
        assert!(listing.len() >= 11, "too few found: {}", listing.len());
        for command in listing {
            let json = command
                .get_arguments()
                .find(|arg| arg.get_id() == "json")
                .unwrap_or_else(|| panic!("`{}` has no --json", command.get_name()));
            let help = json.get_help().map(|h| h.to_string()).unwrap_or_default();
            assert!(
                help.contains("stable contract from 1.0"),
                "`{} --json` does not say its fields are a contract: {help:?}",
                command.get_name()
            );
        }
    }

    /// `--db` is global: accepted before or after the subcommand.
    #[test]
    fn db_is_accepted_before_and_after_the_subcommand() {
        for args in [
            &["stop-bots", "--db", "/tmp/x.db", "list-trusted"][..],
            &["stop-bots", "list-trusted", "--db", "/tmp/x.db"][..],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(cli.db.as_deref(), Some(Path::new("/tmp/x.db")), "{args:?}");
        }
    }

    fn args(words: &[&str]) -> Vec<std::ffi::OsString> {
        words.iter().map(Into::into).collect()
    }

    /// Every deprecated spelling still parses, as the command it became,
    /// and says so on stderr; none is advertised in `--help`.
    #[test]
    fn every_deprecated_spelling_is_rewritten_to_its_replacement_and_warns() {
        let help = Cli::command().render_help().to_string();
        for (old, flag, new, insert) in DEPRECATED {
            let mut given = vec!["stop-bots", old];
            if !flag.is_empty() {
                given.push(flag);
            }
            let (rewritten, warning) = undeprecate(args(&given));
            let mut expected = vec!["stop-bots", new];
            expected.extend(insert.iter());
            assert_eq!(rewritten, args(&expected), "{given:?}");
            let warning = warning.unwrap_or_default();
            assert!(
                warning.contains("deprecated") && warning.contains(new),
                "{given:?} warned: {warning:?}"
            );
            assert!(
                !help.contains(&format!("  {old} ")),
                "{old} is still advertised:\n{help}"
            );
        }
    }

    #[test]
    fn a_deprecated_spelling_keeps_its_flags_and_a_global_db_before_it() {
        let (rewritten, warning) = undeprecate(args(&[
            "stop-bots",
            "--db",
            "/tmp/x.db",
            "trust",
            "--remove",
            "--address",
            "203.0.113.7",
        ]));
        assert_eq!(
            rewritten,
            args(&[
                "stop-bots",
                "--db",
                "/tmp/x.db",
                "remove-trusted",
                "--address",
                "203.0.113.7"
            ])
        );
        assert!(warning.is_some());
        let cli = Cli::try_parse_from(rewritten).unwrap();
        assert!(matches!(cli.command, Some(Command::RemoveTrusted { .. })));

        let (rewritten, _) = undeprecate(args(&["stop-bots", "block-scanners", "--dry-run"]));
        let cli = Cli::try_parse_from(rewritten).unwrap();
        assert!(
            matches!(
                cli.command,
                Some(Command::RunDetector {
                    detector: DetectorArg(Detector::SshScanners),
                    dry_run: true,
                    ..
                })
            ),
            "block-scanners --dry-run is not run-detector ssh-scanners --dry-run"
        );
    }

    /// The current spellings are left alone, including a `--remove` that
    /// belongs to a verb no deprecation names.
    #[test]
    fn a_current_spelling_is_not_rewritten() {
        for words in [
            &["stop-bots", "add-trusted", "--address", "203.0.113.7"][..],
            &["stop-bots", "run-detector", "injection"][..],
            &["stop-bots", "--db", "trust", "status"][..],
        ] {
            let (rewritten, warning) = undeprecate(args(words));
            assert_eq!(rewritten, args(words));
            assert_eq!(warning, None, "{words:?}");
        }
    }

    /// A detector is named the way it is typed, and the stored id — the
    /// one a settings key or cron job carries — is accepted too.
    #[test]
    fn every_detector_has_a_command_line_name_and_accepts_its_stored_id() {
        for detector in DetectorArg::ALL {
            for spelling in [detector.name(), detector.0.id()] {
                let cli = Cli::try_parse_from(["stop-bots", "set-detector", spelling]).unwrap();
                let Some(Command::SetDetector {
                    detector: parsed, ..
                }) = cli.command
                else {
                    panic!("{spelling} did not parse as set-detector");
                };
                assert_eq!(parsed.0, detector.0, "{spelling}");
            }
        }
    }

    /// An explicit `--ssh-log` that cannot be read must say so about *that
    /// path*, and must not claim the other two sources were tried — they
    /// were not. The wording is the whole point of the test: a message
    /// describing a search that never happened is what sends the reader
    /// hunting for a bug in the fallback chain instead of looking at the
    /// path they passed.
    #[test]
    fn an_unreadable_explicit_ssh_log_names_the_path_it_was_given() {
        let err = read_ssh_log(
            &Db::open_in_memory().unwrap(),
            Some(Path::new("/nonexistent/auth.log")),
        )
        .expect_err("a missing file should not read");
        let said = err.to_string();

        assert!(
            said.contains("/nonexistent/auth.log"),
            "the path the operator passed is missing from: {said}"
        );
        assert!(
            !said.contains("tried /var/log/auth.log"),
            "it claimed a search it did not perform: {said}"
        );
        assert!(
            said.contains("journalctl"),
            "it should say dropping the flag reaches journalctl: {said}"
        );
    }

    /// With no override the search really does happen, so naming all three
    /// sources is correct here.
    #[test]
    fn an_ssh_log_search_that_finds_nothing_names_every_source() {
        // Hermetic only in the sense that matters: if this host *does* have
        // a readable SSH log, the search succeeds and there is no message
        // to check. Asserting on the error in that case would make the test
        // fail on developer machines for a reason unrelated to the code.
        if let Err(err) = read_ssh_log(&Db::open_in_memory().unwrap(), None) {
            let said = err.to_string();
            assert!(
                said.contains("/var/log/auth.log")
                    && said.contains("/var/log/secure")
                    && said.contains("journalctl"),
                "a real search should name all three sources: {said}"
            );
        }
    }

    #[test]
    fn an_unreadable_explicit_access_log_names_the_path_it_was_given() {
        let db = Db::open_in_memory().unwrap();
        let err = read_access_log(&db, Some(Path::new("/nonexistent/access.log")))
            .expect_err("a missing file should not read");
        let said = err.to_string();

        assert!(
            said.contains("/nonexistent/access.log"),
            "the path the operator passed is missing from: {said}"
        );
        assert!(
            !said.contains("tried /var/log/nginx/access.log"),
            "it claimed a search it did not perform: {said}"
        );
    }

    #[test]
    fn resolve_user_db_path_prefers_xdg_data_home() {
        let path = resolve_user_db_path(Some("/custom/data".into()), Some("/home/someone".into()))
            .unwrap();
        assert_eq!(path, PathBuf::from("/custom/data/stop-bots/db.sqlite3"));
    }

    #[test]
    fn resolve_user_db_path_falls_back_to_home_local_share() {
        let path = resolve_user_db_path(None, Some("/home/someone".into())).unwrap();
        assert_eq!(
            path,
            PathBuf::from("/home/someone/.local/share/stop-bots/db.sqlite3")
        );
    }

    #[test]
    fn resolve_user_db_path_errors_without_any_signal() {
        assert!(resolve_user_db_path(None, None).is_err());
    }

    #[test]
    fn open_db_with_an_explicit_path_opens_it_directly() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("explicit.sqlite3");
        assert!(open_db(Some(path.clone())).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn open_or_fallback_uses_fallback_when_primary_directory_cannot_be_created() {
        // A regular file masquerading as a directory component: `mkdir -p`
        // through it must fail for any user, including root, so this is a
        // root-safe way to force the "can't create the directory" path
        // without needing real permission denial.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let primary = blocker.join("db.sqlite3");

        let fallback_dir = tempfile::tempdir().unwrap();
        let fallback = fallback_dir.path().join("fallback.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(fallback.exists());
        assert!(!primary.exists());
    }

    #[test]
    fn open_or_fallback_uses_primary_when_it_works() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");
        let fallback = tmp.path().join("should-not-be-used.sqlite3");

        assert!(open_or_fallback(&primary, || Ok(fallback.clone())).is_ok());
        assert!(primary.exists());
        assert!(!fallback.exists());
    }

    #[test]
    fn open_or_fallback_never_resolves_fallback_when_primary_works() {
        // Regression guard: resolving the fallback path can itself fail
        // (e.g. neither XDG_DATA_HOME nor HOME is set, plausible in a
        // minimal-env root container). That must never get in the way of
        // the common case where the primary path just works.
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp.path().join("nested").join("db.sqlite3");

        let result = open_or_fallback(&primary, || {
            anyhow::bail!("fallback should never be resolved here")
        });

        assert!(result.is_ok());
        assert!(primary.exists());
    }

    #[test]
    fn format_expiry_rounds_to_the_nearest_whole_day() {
        let expires_at = now_secs() + 3 * 86_400 + 100;
        assert_eq!(format_expiry(expires_at), "expires in 3d");
    }

    #[test]
    fn format_expiry_rounds_to_whole_hours_under_a_day() {
        let expires_at = now_secs() + 5 * 3_600;
        assert_eq!(format_expiry(expires_at), "expires in 5h");
    }

    #[test]
    fn format_expiry_floors_at_one_hour_for_an_imminent_expiry() {
        let expires_at = now_secs() + 30;
        assert_eq!(format_expiry(expires_at), "expires in 1h");
    }

    /// With neither flag, a render follows the host: the stored backend,
    /// and that backend's own file. An iptables host used to get
    /// `firewall.nft` holding a shell script.
    #[test]
    fn a_render_with_no_flags_follows_the_stored_backend_and_its_path() {
        use stop_bots::firewall::FirewallBackend as Stored;
        let db = Db::open_in_memory().unwrap();

        let (backend, out) = firewall_target(&db, None, None).unwrap();
        assert_eq!(backend, Stored::Nftables);
        assert_eq!(out, PathBuf::from("/etc/stop-bots/firewall.nft"));

        stop_bots::firewall::store_backend(&db, Stored::Iptables).unwrap();
        let (backend, out) = firewall_target(&db, None, None).unwrap();
        assert_eq!(backend, Stored::Iptables);
        assert_eq!(out, PathBuf::from("/etc/stop-bots/firewall.sh"));
    }

    /// A flag names this run only: it wins over the stored backend, and
    /// the default path follows the backend it chose.
    #[test]
    fn a_render_s_flags_win_over_the_stored_backend() {
        use stop_bots::firewall::FirewallBackend as Stored;
        let db = Db::open_in_memory().unwrap();
        stop_bots::firewall::store_backend(&db, Stored::Iptables).unwrap();

        let (backend, out) = firewall_target(&db, Some(FirewallBackend::Nftables), None).unwrap();
        assert_eq!(backend, Stored::Nftables);
        assert_eq!(out, PathBuf::from("/etc/stop-bots/firewall.nft"));

        let (_, out) = firewall_target(&db, None, Some(PathBuf::from("/tmp/fw"))).unwrap();
        assert_eq!(out, PathBuf::from("/tmp/fw"));
        assert_eq!(
            stop_bots::firewall::stored_backend(&db).unwrap(),
            Stored::Iptables,
            "a run's flag was written back"
        );
    }

    #[test]
    fn render_firewall_rejects_allowlist_mode_on_iptables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            db.set_geo_mode(stop_bots::db::GeoMode::Allowlist).unwrap();
        }
        let out = tmp.path().join("fw.sh");

        let result = render_firewall(
            Some(db_path),
            RenderRequest {
                backend: Some(FirewallBackend::Iptables),
                out: Some(out.clone()),
                apply: false,
                force: false,
                ssh_log: None,
                confirm: None,
            },
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nftables"));
        assert!(!out.exists());
    }

    fn not_found_line(ip: &str, path: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET {path} HTTP/1.1\" 404 1 \"-\" \"Googlebot\"\n"
        )
    }

    /// The property the crawler exclusion exists for: an IP inside a known
    /// crawler's published ranges must never be auto-blocked by
    /// `block_web_scanners`, even when its 404 behavior clears the
    /// scanning threshold — a real Googlebot routinely chases enough stale
    /// links to do exactly that.
    #[test]
    fn block_web_scanners_never_blocks_an_ip_inside_a_known_crawler_range() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            ipranges::store(
                &db,
                ipranges::IpRangeSourceKind::GoogleBot,
                &["198.51.100.0/24".to_string()],
            )
            .unwrap();
        }

        let log_path = tmp.path().join("access.log");
        let log: String = (0..20)
            .map(|i| not_found_line("198.51.100.9", &format!("/missing-{i}")))
            .collect();
        std::fs::write(&log_path, log).unwrap();

        block_web_scanners(
            Some(db_path.clone()),
            Some(15),
            Some(1),
            Some(log_path),
            false,
        )
        .unwrap();

        let db = Db::open(&db_path).unwrap();
        assert!(db.list_firewall_rules().unwrap().is_empty());
    }

    /// The flip side: an IP that scans just as aggressively but *isn't*
    /// inside any known crawler range must still get blocked.
    #[test]
    fn block_web_scanners_still_blocks_a_scanner_outside_known_crawler_ranges() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        {
            let db = Db::open(&db_path).unwrap();
            ipranges::store(
                &db,
                ipranges::IpRangeSourceKind::GoogleBot,
                &["198.51.100.0/24".to_string()],
            )
            .unwrap();
        }

        let log_path = tmp.path().join("access.log");
        let log: String = (0..20)
            .map(|i| not_found_line("203.0.113.9", &format!("/missing-{i}")))
            .collect();
        std::fs::write(&log_path, log).unwrap();

        block_web_scanners(
            Some(db_path.clone()),
            Some(15),
            Some(1),
            Some(log_path),
            false,
        )
        .unwrap();

        let db = Db::open(&db_path).unwrap();
        assert_eq!(
            db.list_firewall_rules().unwrap()[0].address,
            "203.0.113.9".to_string()
        );
    }

    /// The dup-row hazard a naive "list then filter expired" design would
    /// hit: re-running `block_scanners` against an IP whose earlier block
    /// already expired must produce exactly one row for that address, not
    /// two (one stale-but-undeleted, one freshly inserted). Proven here by
    /// calling `block_scanners` twice against the same still-scanning IP —
    /// first with a negative TTL (an instantly-expired "earlier" block),
    /// then with a normal positive one.
    #[test]
    fn block_scanners_re_blocks_cleanly_after_a_rule_expires() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");

        let log_path = tmp.path().join("auth.log");
        let log: String = "Failed password for root from 198.51.100.9 port 4444 ssh2\n".repeat(25);
        std::fs::write(&log_path, &log).unwrap();

        block_scanners(
            Some(db_path.clone()),
            Some(20),
            Some(-1),
            Some(log_path.clone()),
            false,
        )
        .unwrap();
        {
            // The rule from the first (instantly-expired) call must
            // already be gone before the second call ever runs, exactly
            // as `list_firewall_rules`'s pruning intends.
            let db = Db::open(&db_path).unwrap();
            assert!(db.list_firewall_rules().unwrap().is_empty());
        }

        block_scanners(
            Some(db_path.clone()),
            Some(20),
            Some(5),
            Some(log_path),
            false,
        )
        .unwrap();

        let db = Db::open(&db_path).unwrap();
        let rules = db.list_firewall_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].address, "198.51.100.9");
        assert!(rules[0].expires_at.is_some());

        // Guards against a regression to "filter expired rows on read"
        // instead of actually deleting them: under a filter-only
        // implementation every assertion above would still pass (the
        // dead first-call row would just be hidden, not gone), but the
        // raw table would hold two physical rows for this address instead
        // of one.
        let raw = rusqlite::Connection::open(&db_path).unwrap();
        let raw_count: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM firewall_rules WHERE address = '198.51.100.9'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(raw_count, 1);
    }

    fn ok_line(ip: &str, user_agent: &str) -> String {
        format!(
            "{ip} - - [10/Jul/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 512 \"-\" \"{user_agent}\"\n"
        )
    }

    #[test]
    fn record_access_stats_persists_counts_from_the_default_log_path_override() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        let log_path = tmp.path().join("access.log");
        let mut log = String::new();
        log.push_str(&ok_line("203.0.113.5", "Mozilla/5.0"));
        log.push_str(&ok_line("203.0.113.6", "Mozilla/5.0"));
        std::fs::write(&log_path, log).unwrap();

        record_access_stats(Some(db_path.clone()), Some(log_path)).unwrap();

        let db = Db::open(&db_path).unwrap();
        let stats = db.list_user_agent_stats().unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].user_agent, "Mozilla/5.0");
        assert_eq!(stats[0].hit_count, 2);
    }

    #[test]
    fn list_access_stats_succeeds_on_an_empty_database() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("db.sqlite3");
        Db::open(&db_path).unwrap();

        list_access_stats(Some(db_path), false).unwrap();
    }
}
