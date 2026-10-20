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

//! Shared fixtures for unit tests (only compiled for tests — see
//! `lib.rs`), for the two setups that were being hand-written in eight and
//! eleven files respectively.
//!
//! **The bar for adding something here is that the call site reads better,
//! not that it is shorter.** `block("10.0.0.1")` beats an eight-line struct
//! literal because it *says* "a rule blocking this address" — the reader
//! learns the intent without decoding five fields that were `None`,
//! `true`, `None` in every single case. A helper whose name doesn't carry
//! its meaning makes a test worse, because now you have to look it up.
//!
//! By the same rule, some duplication deliberately stays put:
//!
//! - The `NewBot` literals in `botlist/*`'s parser tests are the *expected
//!   parse result* being asserted. A builder there would hide the thing
//!   under test.
//! - `tests/cli.rs` and `tests/tui.rs` are integration tests and cannot see
//!   a `#[cfg(test)]` module at all. Their own local helpers are the right
//!   answer, and they already have them.
//!
//! Builders take `&Db` and mutate rather than returning one: a helper that
//! hands back a database hides which database the test is actually using.

use crate::db::{BotStatus, Db, FirewallAction, FirewallRule, NewBot, Source};

/// A `FirewallRule` blocking `address`, with every other field at the
/// value it has in almost every test: no port, enabled, no expiry.
pub(crate) fn block(address: &str) -> FirewallRule {
    rule(address, FirewallAction::Block)
}

/// A `FirewallRule` allowing `address`. The counterpart to [`block`] —
/// spelled out separately rather than as `rule(addr, Allow)` because
/// allow-vs-block is the single most important fact about a rule, and a
/// reader shouldn't have to parse an argument to find it.
pub(crate) fn allow(address: &str) -> FirewallRule {
    rule(address, FirewallAction::Allow)
}

/// For the few tests that genuinely vary the action, e.g. by looping over
/// both.
pub(crate) fn rule(address: &str, action: FirewallAction) -> FirewallRule {
    FirewallRule {
        // Zero rather than a running counter: no code path looks a rule up
        // by id, and a meaningless-but-distinct number in a test invites
        // the reader to hunt for significance it doesn't have.
        id: 0,
        address: address.to_string(),
        port: None,
        action,
        enabled: true,
        expires_at: None,
        source: None,
        created_at: None,
        evidence: None,
    }
}

/// A rule restricted to a single TCP port.
pub(crate) fn block_port(address: &str, port: u16) -> FirewallRule {
    FirewallRule {
        port: Some(port),
        ..block(address)
    }
}

/// A Block that lapses at `expires_at` (Unix seconds), the way every
/// detector writes one.
pub(crate) fn block_until(address: &str, expires_at: i64) -> FirewallRule {
    FirewallRule {
        expires_at: Some(expires_at),
        ..block(address)
    }
}

/// The port-scan detector's trap with the built-in ports, on a host where
/// MySQL listens: what a typical web host renders.
pub(crate) fn trap() -> crate::portscan::Trap {
    crate::portscan::resolve(
        &crate::portscan::DEFAULT_TRAP_PORTS,
        &[22, 80, 443, 3306],
        &[22],
    )
}

/// A rule that exists but is switched off — renderers must skip it.
pub(crate) fn disabled(address: &str) -> FirewallRule {
    FirewallRule {
        enabled: false,
        ..block(address)
    }
}

/// Registers a bot list source in `db`. Bots are foreign-keyed to one, so
/// anything that stores a bot needs this first; the source itself is
/// almost never what a test is about.
pub(crate) fn seed_source(db: &Db, id: &str) {
    db.upsert_source(&Source {
        id: id.to_string(),
        name: id.to_string(),
        url: format!("https://example.invalid/{id}.json"),
        last_fetched_at: None,
        bot_count: 0,
    })
    .expect("failed to seed a bot-list source");
}

/// A minimal [`NewBot`], for tests that only need *a* bot to exist.
///
/// Separate from [`blocked_bot`]: that one seeds a source and pins the
/// bot's status, which is what a test about applying NGINX config wants.
/// This is the plain value, for callers that hand it to something which
/// does the storing itself.
pub(crate) fn new_bot(slug: &str, source_id: &str) -> NewBot {
    NewBot {
        slug: slug.to_string(),
        name: slug.to_string(),
        is_ai: false,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: format!("{slug}-ua"),
        source_id: source_id.to_string(),
    }
}

/// A bot pinned to Blocked, matching `pattern` — the "there is something
/// to block" setup, previously ~20 lines of `upsert_source` +
/// `upsert_bot` + `set_bot_status` in eleven places.
///
/// Pinned per-bot rather than via a category default on purpose: it makes
/// the bot blocked regardless of what the test does to category settings,
/// so a test about applying NGINX config can't be quietly changed into a
/// test about the category cascade.
pub(crate) fn blocked_bot(db: &Db, slug: &str, pattern: &str) {
    seed_source(db, "test-source");
    db.upsert_bot(&NewBot {
        slug: slug.to_string(),
        name: slug.to_string(),
        is_ai: false,
        is_search_engine: false,
        is_scanner: false,
        user_agent_pattern: pattern.to_string(),
        source_id: "test-source".to_string(),
    })
    .expect("failed to seed a bot");
    db.set_bot_status(slug, BotStatus::Blocked)
        .expect("failed to pin the seeded bot to Blocked");
}

/// Writes an executable `#!/bin/sh` script at `path`, for a test that then
/// runs it in this same process.
///
/// Written by a short-lived `sh`, not with `fs::write`. Tests run on many
/// threads, and a thread that forks while another holds a script open for
/// writing hands that descriptor to its child until the child execs. For
/// that moment the file is open for writing somewhere, and running it
/// fails with `Text file busy` — a test that fails one run in five for a
/// reason unrelated to what it tests. A descriptor opened in another
/// process is never ours to leak.
pub(crate) fn write_script(path: &std::path::Path, body: &str) {
    use std::io::Write;
    let mut child = std::process::Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "could not write {}",
        path.display()
    );
}

/// Makes a FIFO at `path`: what a root process that opened it to read
/// would wait on for ever, with nobody writing.
pub(crate) fn mkfifo(path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a NUL-terminated path, for the length of the call.
    assert_eq!(
        unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
        0,
        "could not make a FIFO at {}",
        path.display()
    );
}

/// Writes `text` gzipped to `path`, as logrotate's `compress` leaves an
/// old log, and sets its modification time to `at`, the moment its last
/// line was written.
pub(crate) fn write_gzip(path: &std::path::Path, text: &str, at: i64) {
    use std::io::Write;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(text.as_bytes()).unwrap();
    std::fs::write(path, gz.finish().unwrap()).unwrap();
    set_modified(path, at);
}

/// Sets `path`'s modification time to `at`, in Unix seconds.
pub(crate) fn set_modified(path: &std::path::Path, at: i64) {
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(at.max(0) as u64);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(when)
        .unwrap();
}

/// Now, in Unix seconds.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// `at` as NGINX's `$time_local` writes it, in UTC: a log line from a
/// given moment, for the tests where when it happened is the point.
pub(crate) fn nginx_time(at: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, mo, d, h, mi, s) = crate::logtime::civil(at);
    format!(
        "{d:02}/{}/{y}:{h:02}:{mi:02}:{s:02} +0000",
        MONTHS[mo as usize - 1]
    )
}

/// One combined-format access-log line: `request` (the whole `GET /path
/// HTTP/1.1` triple) from `ip` as `user_agent`, answered `status` at `at`.
pub(crate) fn access_line_at(
    ip: &str,
    request: &str,
    status: u16,
    user_agent: &str,
    at: i64,
) -> String {
    format!(
        "{ip} - - [{}] \"{request}\" {status} 0 \"-\" \"{user_agent}\"",
        nginx_time(at)
    )
}

/// Reads `lines` as one scheduled pass does at `now` (for the detectors
/// `db` has on, each inside its window) and stores what they show, for
/// `scanblock::run_detector` to decide on.
pub(crate) fn ingest_access_lines(db: &Db, lines: &[String], now: i64) {
    let watch = crate::logscan::watch(db, now).unwrap();
    let mut observer = crate::accesslog::Observer::new(watch);
    for line in lines {
        observer.line(line, crate::accesslog::Clock::Logged { now, undated: None });
    }
    let (evidence, _, _) = observer.finish();
    let from = db.get_log_cursor("test").unwrap();
    let to = format!("{}x", from.clone().unwrap_or_default());
    assert!(db
        .ingest(&crate::db::evidence::Ingested {
            source: "test",
            from: from.as_deref(),
            to: Some(&to),
            evidence: &evidence,
            user_agents: &std::collections::HashMap::new(),
            logins: &[],
            now,
        })
        .unwrap());
}

/// `at` as `journalctl -o short-iso` and a high-precision rsyslog write it.
pub(crate) fn iso_time(at: i64) -> String {
    let (y, mo, d, h, mi, s) = crate::logtime::civil(at);
    format!("{y}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+0000")
}

/// One entry as `journalctl -o json` prints it, from sshd at `at`,
/// saying `message`, with `cursor` as its cursor, which comes first.
pub(crate) fn journal_entry(cursor: &str, at: i64, message: &str) -> String {
    let rest = serde_json::json!({
        "__REALTIME_TIMESTAMP": (at * 1_000_000).to_string(),
        "_HOSTNAME": "host",
        "SYSLOG_IDENTIFIER": "sshd",
        "_PID": "1",
        "_SYSTEMD_UNIT": "ssh.service",
        "MESSAGE": message,
    })
    .to_string();
    format!(
        "{{\"__CURSOR\":{},{}",
        serde_json::Value::from(cursor),
        &rest[1..]
    )
}

/// A kernel message as `journalctl -o json` prints it: no pid, and
/// `kernel` for the identifier, as the kernel's own entries have.
pub(crate) fn kernel_journal_entry(cursor: &str, at: i64, message: &str) -> String {
    let rest = serde_json::json!({
        "__REALTIME_TIMESTAMP": (at * 1_000_000).to_string(),
        "_HOSTNAME": "host",
        "SYSLOG_IDENTIFIER": "kernel",
        "_TRANSPORT": "kernel",
        "MESSAGE": message,
    })
    .to_string();
    format!(
        "{{\"__CURSOR\":{},{}",
        serde_json::Value::from(cursor),
        &rest[1..]
    )
}

/// A stand-in for `journalctl` in `dir`, which appends the arguments of
/// each call to `dir/calls` and then runs `body`: typically an `echo` of a
/// [`journal_entry`] or two.
pub(crate) fn fake_journalctl(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("journalctl");
    write_script(
        &path,
        &format!("echo \"$@\" >> \"$(dirname \"$0\")/calls\"\n{body}"),
    );
    path
}

/// The arguments of every call a [`fake_journalctl`] in `dir` received,
/// one call a line.
pub(crate) fn journalctl_calls(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("calls"))
        .unwrap_or_default()
        .lines()
        .map(String::from)
        .collect()
}

/// A fake program `name` in `dir` that appends `<name> <args>` to
/// `dir/calls` (read with [`fake_calls`]) and then runs `body`.
pub(crate) fn logging_fake(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    write_script(
        &path,
        &format!("echo \"{name} $*\" >> \"$(dirname \"$0\")/calls\"\n{body}"),
    );
    path
}

/// Scans an NGINX site named `server_name` whose document root holds
/// `files` (each an empty file), as `scan-sites` would have stored it.
/// The returned directory holds both, and must be kept alive.
pub(crate) fn site_serving(db: &Db, server_name: &str, files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("www");
    std::fs::create_dir_all(&root).unwrap();
    for file in files {
        std::fs::write(root.join(file), "").unwrap();
    }
    let config = dir.path().join(server_name);
    std::fs::write(
        &config,
        format!(
            "server {{\n    server_name {server_name};\n    root {};\n}}\n",
            root.display()
        ),
    )
    .unwrap();
    db.upsert_site(server_name, config.to_str().unwrap())
        .unwrap();
    dir
}

/// Every call the fakes in `dir` received, one a line.
pub(crate) fn fake_calls(dir: &std::path::Path) -> Vec<String> {
    journalctl_calls(dir)
}

/// [`crate::revert::Tools`] that are all [`logging_fake`]s in `dir`,
/// succeeding: `systemd-run`, `systemctl`, the `stop-bots` the timer would
/// run, `nft`, `sh`, `iptables` and `ip6tables`.
pub(crate) fn fake_revert_tools(dir: &std::path::Path) -> crate::revert::Tools {
    let fake = |name: &str| logging_fake(dir, name, "exit 0");
    crate::revert::Tools {
        systemd_run: fake("systemd-run"),
        systemctl: fake("systemctl"),
        exe: fake("stop-bots"),
        nft: fake("nft"),
        sh: fake("sh"),
        iptables: vec![fake("iptables"), fake("ip6tables")],
    }
}
