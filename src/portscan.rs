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

//! The port-scan detector: trap ports in the firewall, and the kernel log
//! lines they write.
//!
//! Every other detector reads a log some service already writes: sshd's,
//! or the web server's. A port scan touches no service, so nothing logs
//! it. The firewall is the only thing that sees the packets, and the
//! firewall cannot know which ports are closed. So it is told: a short list
//! of **trap ports**, ones commonly scanned and almost never served by a
//! web host (telnet, SMB, RDP, the databases' and caches' defaults). The
//! generated script drops a new connection to one, and logs it to the
//! kernel log with [`LOG_PREFIX`], at most [`LOG_RATE`]. The detector
//! reads those lines back, and an address that tried
//! `PORT_SCANNERS_MIN_PORTS` (see `crate::protection`) different trap
//! ports inside the window is blocked everywhere.
//!
//! ## What is never a trap port
//!
//! - **22, 80 and 443**, whatever the list says: [`NEVER_TRAPPED`].
//! - **Whatever sshd is configured to listen on** ([`sshd_ports`]), and
//!   the port of the SSH session running this, if there is one.
//! - **Anything listening right now** on an address other than loopback,
//!   as `ss -ltnH` reports it ([`listening_ports`]). Decided at render
//!   time: a service started afterwards on a trap port is dropped until the
//!   firewall is rendered and applied again, which is said where the
//!   detector is described (`Detector::risk`).
//!
//! When `ss` cannot be run, nothing is trapped: not knowing what listens
//! is not the same as nothing listening.
//!
//! ## Input only
//!
//! The trap sits on the `input` path, after every address rule: an Allow
//! (an SSH login, a trusted address) is decided before it, and a packet
//! DNAT'd to a container, which leaves through `forward`, never reaches it.
//! A container that publishes a trap port is therefore never trapped.

use crate::db::{keys, Db};
use crate::evidence::{Evidence, Item};
use crate::ipranges::is_local_or_private;
use crate::protection::Detector;
use crate::sshlog::{Located, SshSource};
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// The trap ports when the operator has not chosen any: ports scanners
/// try on every address and a Linux web host does not serve. Fifteen,
/// which is also the most one iptables `multiport` match takes.
///
/// Telnet (23); Windows RPC, NetBIOS and SMB (135, 139, 445); MS SQL and
/// Oracle (1433, 1521); Docker's unencrypted API (2375); MySQL (3306);
/// RDP (3389); PostgreSQL (5432); VNC (5900); Redis (6379);
/// Elasticsearch (9200); memcached (11211); MongoDB (27017).
///
/// Left out on purpose: 8080 and 8443, where web hosts do run proxies and
/// application servers, and every port a web host serves by design.
pub const DEFAULT_TRAP_PORTS: [u16; 15] = [
    23, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017,
];

/// Never a trap port, whatever is configured: SSH, HTTP and HTTPS.
pub const NEVER_TRAPPED: [u16; 3] = [22, 80, 443];

/// What the firewall puts in front of every line it logs. Fixed, so the
/// detector can find its own lines among everything else the kernel says.
pub const LOG_PREFIX: &str = "stop-bots-trap: ";

/// How many lines a second the trap may log, in total. A scan of the
/// whole internet sends far more than this; the block, once it lands,
/// stops the rest, and the drop happens whether or not the line was
/// written.
pub const LOG_RATE: &str = "10/second";

/// `settings` key: the trap ports, comma-separated.
pub const PORTS: &str = keys::DETECT_PORT_SCANNERS_PORTS;

/// The trap ports the operator chose, or [`DEFAULT_TRAP_PORTS`]. A stored
/// value [`parse_ports`] would refuse (written by hand) reads as the
/// default, as the honeypot path does.
pub fn configured_ports(db: &Db) -> Result<Vec<u16>> {
    Ok(db
        .get_text_setting(PORTS)?
        .and_then(|text| parse_ports(&text).ok())
        .unwrap_or_else(|| DEFAULT_TRAP_PORTS.to_vec()))
}

/// Whether the trap ports are the built-in list.
pub fn ports_are_default(db: &Db) -> Result<bool> {
    Ok(db
        .get_text_setting(PORTS)?
        .and_then(|text| parse_ports(&text).ok())
        .is_none())
}

/// `text` as a list of trap ports: numbers separated by commas or spaces,
/// sorted, each once. Refuses an empty list (switch the detector off
/// instead), anything that is not a port, and [`NEVER_TRAPPED`].
pub fn parse_ports(text: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for word in text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|w| !w.is_empty())
    {
        let port: u16 = match word.parse() {
            Ok(port) if port > 0 => port,
            _ => bail!("{word:?} is not a TCP port (1 to 65535)"),
        };
        if NEVER_TRAPPED.contains(&port) {
            bail!(
                "{port} cannot be a trap port: SSH, HTTP and HTTPS ({}) never are",
                join(&NEVER_TRAPPED)
            );
        }
        ports.insert(port);
    }
    if ports.is_empty() {
        bail!("give at least one port, or switch the detector off");
    }
    Ok(ports.into_iter().collect())
}

/// Stores the trap ports `text` names, or the built-in list for
/// `default`, and returns what is now configured.
pub fn set_ports(db: &Db, text: &str) -> Result<Vec<u16>> {
    if text.trim() == "default" {
        db.delete_setting(PORTS)?;
    } else {
        let ports = parse_ports(text)?;
        db.set_text_setting(PORTS, &join_with(&ports, ","))?;
    }
    configured_ports(db)
}

/// `ports` as `23, 445, 3389`.
pub fn join(ports: &[u16]) -> String {
    join_with(ports, ", ")
}

fn join_with(ports: &[u16], separator: &str) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(separator)
}

/// What the firewall traps, once everything that must not be trapped is
/// taken out of the configured list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trap {
    /// The ports trapped, sorted.
    pub ports: Vec<u16>,
    /// Configured ports left out because something listens on them, or
    /// sshd is configured to, sorted. Named in the script, so the operator
    /// can see why a port they listed is not there.
    pub left_out: Vec<u16>,
}

/// `configured` less [`NEVER_TRAPPED`], `listening` and `ssh`.
pub fn resolve(configured: &[u16], listening: &[u16], ssh: &[u16]) -> Trap {
    let (left_out, ports): (Vec<u16>, Vec<u16>) = configured.iter().copied().partition(|port| {
        NEVER_TRAPPED.contains(port) || listening.contains(port) || ssh.contains(port)
    });
    Trap {
        ports,
        left_out: left_out
            .into_iter()
            .filter(|port| !NEVER_TRAPPED.contains(port))
            .collect(),
    }
}

/// What the firewall should do about trap ports right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrapState {
    /// The detector is off: no trap.
    Off,
    /// The detector is on, but `ss` could not say what listens, so no trap
    /// either.
    Unknown,
    /// The detector is on, and this is the trap.
    Set(Trap),
}

/// Asks this host what listens, unless the detector is off: runs `ss`.
pub fn state(db: &Db) -> Result<TrapState> {
    if !Detector::PortScanners.is_enabled(db)? {
        return Ok(TrapState::Off);
    }
    let Some(listening) = listening_ports() else {
        return Ok(TrapState::Unknown);
    };
    let mut ssh = sshd_ports();
    ssh.extend(session_port());
    Ok(TrapState::Set(resolve(
        &configured_ports(db)?,
        &listening,
        &ssh,
    )))
}

/// The trap to render, if there is one with any port in it.
pub fn for_render(db: &Db) -> Result<Option<Trap>> {
    Ok(match state(db)? {
        TrapState::Set(trap) if !trap.ports.is_empty() => Some(trap),
        _ => None,
    })
}

/// Every TCP port something listens on, on an address other than
/// loopback, as `ss -ltnH` reports it; `None` when `ss` cannot be run.
pub fn listening_ports() -> Option<Vec<u16>> {
    let out = std::process::Command::new(crate::host::program("ss"))
        .args(["-ltnH"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_listening(&String::from_utf8_lossy(&out.stdout)))
}

/// The ports in `ss -ltnH` output that something listens on reachably
/// from outside, sorted, each once.
///
/// A port bound only to loopback (a Redis on `127.0.0.1:6379`) is not
/// one: nothing from outside can reach it, so trapping it costs nothing
/// and catches the scanner that tries it. An address this cannot read
/// counts as reachable, which only ever leaves a port out of the trap.
pub fn parse_listening(output: &str) -> Vec<u16> {
    let mut ports = BTreeSet::new();
    for line in output.lines() {
        // `State Recv-Q Send-Q Local-Address:Port Peer-Address:Port ...`
        let Some(local) = line.split_whitespace().nth(3) else {
            continue;
        };
        let Some((address, port)) = local.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if !is_loopback_only(address) {
            ports.insert(port);
        }
    }
    ports.into_iter().collect()
}

/// Whether `ss` printed a loopback address: `127.0.0.1`, `[::1]`,
/// `127.0.0.53%lo`, `[::ffff:127.0.0.1]`.
fn is_loopback_only(address: &str) -> bool {
    let address = address.trim_start_matches('[').trim_end_matches(']');
    let address = address.split('%').next().unwrap_or(address);
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

/// Where sshd's configuration is read from for [`sshd_ports`].
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const SSHD_CONFIG_D: &str = "/etc/ssh/sshd_config.d";

/// Every port sshd is configured to listen on: `Port` and the port of a
/// `ListenAddress`, in `/etc/ssh/sshd_config` and the `.conf` files of
/// `sshd_config.d`. Empty when none can be read. Besides what
/// `ss` sees, for an sshd that is not running right now.
pub fn sshd_ports() -> Vec<u16> {
    let mut texts: Vec<String> = std::fs::read_to_string(SSHD_CONFIG).into_iter().collect();
    if let Ok(entries) = std::fs::read_dir(SSHD_CONFIG_D) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "conf") {
                texts.extend(std::fs::read_to_string(path));
            }
        }
    }
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for text in texts {
        ports.extend(sshd_config_ports(&text));
    }
    ports.into_iter().collect()
}

/// The ports one sshd configuration file names.
pub fn sshd_config_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(key), Some(value)) = (words.next(), words.next()) else {
            continue;
        };
        let port = if key.eq_ignore_ascii_case("Port") {
            value.parse::<u16>().ok()
        } else if key.eq_ignore_ascii_case("ListenAddress") {
            // `0.0.0.0:2222` or `[::]:2222`; a bare address has no port.
            value
                .rsplit_once(':')
                .filter(|(host, _)| !host.contains(':') || host.ends_with(']'))
                .and_then(|(_, port)| port.parse().ok())
        } else {
            None
        };
        ports.extend(port);
    }
    ports
}

/// The server port of the SSH session this runs in, from
/// `SSH_CONNECTION`: `client port server port`.
fn session_port() -> Option<u16> {
    std::env::var("SSH_CONNECTION")
        .ok()?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()
}

// ---- the kernel log ----

/// Where the kernel log is read from: a named file, or a search of
/// [`DEFAULT_KERNEL_LOG_PATHS`] and then the journal. The same shape the
/// SSH log has, and the same resolution (see `crate::logpaths`).
pub type KernelSource = SshSource;

/// Debian and Ubuntu with rsyslog write the kernel's lines to `kern.log`;
/// RHEL's rsyslog to `messages`. A host with neither has the journal.
pub const DEFAULT_KERNEL_LOG_PATHS: &[&str] = &["/var/log/kern.log", "/var/log/messages"];

/// The key the journal's read cursor is stored under.
pub const JOURNAL_SOURCE: &str = "journald:kernel";

/// The journal match for the kernel's own messages. Not `-k`, which is
/// the current boot only: a cursor from before a reboot must still find
/// what came after it.
pub const JOURNAL_MATCHES: &[&str] = &["_TRANSPORT=kernel"];

/// Whether anything can be read from the kernel log `source` names,
/// without reading it: for the health check.
pub fn kernel_log_is_readable(source: &KernelSource) -> bool {
    match locate(source) {
        Located::File(path) => std::fs::File::open(path).is_ok(),
        Located::Journal => {
            let query = crate::logread::JournalQuery {
                program: Path::new("journalctl"),
                units: &[],
                matches: JOURNAL_MATCHES,
                after_cursor: None,
                since: None,
                last: Some(1),
                max_bytes: None,
            };
            crate::logread::read_journal(&query, &mut |_| {}).is_ok_and(|read| read.lines > 0)
        }
    }
}

/// Where `source` turns out to be, searching the default paths.
pub fn locate(source: &KernelSource) -> Located {
    let defaults: Vec<PathBuf> = DEFAULT_KERNEL_LOG_PATHS.iter().map(PathBuf::from).collect();
    source.locate_among(&defaults)
}

/// The trap's lines in the kernel log `source` names, read whole (the
/// journal from `since`), or `None` when it cannot be read.
pub fn read_kernel_log(source: &KernelSource, since: i64) -> Option<String> {
    let mut sources = crate::hostlog::Sources::ssh_only(SshSource::Search);
    sources.kernel = source.clone();
    crate::hostlog::kernel_since(&sources, since)
}

/// What one logged trap hit says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrapHit {
    pub address: IpAddr,
    pub port: u16,
}

/// Reads `line` as a line the trap logged, or `None` for any other line.
///
/// Both firewalls log in the kernel's one format, nftables' `log` and
/// iptables' `LOG` alike: `IN=eth0 OUT= MAC=… SRC=203.0.113.5
/// DST=192.0.2.1 … PROTO=TCP SPT=51234 DPT=445 … SYN URGP=0`, with an IPv6
/// source written out in full. Where it lands decides what is in front of
/// it: `kernel: [ 123.456] ` in `kern.log`, `kernel: ` from the journal.
///
/// The prefix must follow the `kernel:` tag, so a line some other program
/// wrote that quotes the prefix is not one of ours. Only TCP counts, and
/// only a source and a port that parse.
pub fn parse_trap_line(line: &str) -> Option<TrapHit> {
    let at = line.find(LOG_PREFIX)?;
    let before = line[..at].trim_end();
    let before = match before.strip_suffix(']') {
        // The kernel's own timestamp, `[ 1234.567890]`.
        Some(rest) => rest.rsplit_once('[')?.0.trim_end(),
        None => before,
    };
    if !before.ends_with("kernel:") {
        return None;
    }
    let mut address = None;
    let mut port = None;
    let mut tcp = false;
    for field in line[at + LOG_PREFIX.len()..].split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            continue;
        };
        match key {
            "SRC" if address.is_none() => address = value.parse::<IpAddr>().ok(),
            "DPT" if port.is_none() => port = value.parse::<u16>().ok(),
            "PROTO" => tcp = value == "TCP",
            _ => {}
        }
    }
    Some(TrapHit {
        address: address?,
        port: port.filter(|_| tcp)?,
    })
}

/// Whether `line` is one the trap logged: the only lines of the kernel log
/// anything here keeps.
pub fn is_trap_line(line: &str) -> bool {
    parse_trap_line(line).is_some()
}

/// Reads kernel log lines one at a time into evidence: the trap port each
/// public address tried, and when.
pub struct Observer {
    cutoff: i64,
    now: i64,
    undated: Option<i64>,
    /// The host's offset from UTC, once per read: see `sshlog::Observer`.
    offset: i64,
    evidence: Evidence,
}

impl Observer {
    /// `cutoff`: the oldest a hit may be and still count. `undated`: the
    /// time to give a line that carries none, which only a read of what
    /// was just appended can say.
    pub fn new(cutoff: i64, now: i64, undated: Option<i64>) -> Observer {
        Observer::with_offset(cutoff, now, undated, crate::logtime::local_offset(now))
    }

    fn with_offset(cutoff: i64, now: i64, undated: Option<i64>, offset: i64) -> Observer {
        Observer {
            cutoff,
            now,
            undated,
            offset,
            evidence: Evidence::default(),
        }
    }

    pub fn line(&mut self, text: &str) {
        let Some(hit) = parse_trap_line(text) else {
            return;
        };
        if is_local_or_private(&hit.address) {
            return;
        }
        let offset = self.offset;
        let at = crate::logtime::syslog_line(text, self.now, &|_| offset)
            .or(self.undated)
            .map(|at| at.min(self.now));
        if let Some(at) = at.filter(|at| *at >= self.cutoff) {
            self.evidence.add(
                Detector::PortScanners,
                hit.address,
                Item::seen(&hit.port.to_string()),
                at,
            );
        }
    }

    pub fn finish(self) -> Evidence {
        self.evidence
    }
}

/// Every public address in `log_text` that tried at least `threshold`
/// different trap ports, with the ports it tried, sorted by address: for
/// the one-off `run-detector port-scanners`, which judges a whole log.
pub fn scanning_ips(log_text: &str, threshold: usize) -> Vec<(String, Vec<u16>)> {
    let mut tried: BTreeMap<IpAddr, BTreeSet<u16>> = BTreeMap::new();
    for hit in log_text.lines().filter_map(parse_trap_line) {
        if !is_local_or_private(&hit.address) {
            tried.entry(hit.address).or_default().insert(hit.port);
        }
    }
    tried
        .into_iter()
        .filter(|(_, ports)| ports.len() >= threshold)
        .map(|(address, ports)| (address.to_string(), ports.into_iter().collect()))
        .collect()
}

/// What a block by this detector records as its evidence.
pub fn evidence_line(ports: &str) -> String {
    format!("new connections to trap ports {ports}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// As rsyslog writes it to `kern.log` on Debian, with the kernel's
    /// own timestamp after the tag.
    const KERN_LOG_V4: &str = "2026-10-16T10:00:01.123456+00:00 web kernel: [81234.567890] \
        stop-bots-trap: IN=eth0 OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:08:00 \
        SRC=203.0.113.5 DST=192.0.2.10 LEN=44 TOS=0x00 PREC=0x00 TTL=242 ID=54321 \
        PROTO=TCP SPT=40000 DPT=445 WINDOW=1024 RES=0x00 SYN URGP=0";

    /// From the journal, as `logread` prints an entry: no kernel
    /// timestamp, and an IPv6 source written out in full, as the kernel
    /// writes it.
    const JOURNAL_V6: &str = "2026-10-16T10:00:02+0000 web kernel: stop-bots-trap: IN=eth0 \
        OUT= MAC=52:54:00:12:34:56:52:54:00:65:43:21:86:dd \
        SRC=2001:0db8:0000:0000:0000:0000:0000:0007 DST=2001:0db8:0000:0000:0000:0000:0000:0001 \
        LEN=80 TC=0 HOPLIMIT=55 FLOWLBL=0 PROTO=TCP SPT=51234 DPT=3389 WINDOW=64240 RES=0x00 \
        SYN URGP=0";

    /// The classic syslog prefix, as iptables' `LOG` lands in it: the same
    /// fields, the same format.
    const SYSLOG_IPTABLES: &str = "Oct 16 10:00:03 web kernel: [ 9.876543] stop-bots-trap: \
        IN=ens3 OUT= MAC=00:00:00:00:00:00:00:00:00:00:00:00:08:00 SRC=198.51.100.9 \
        DST=192.0.2.10 LEN=40 TOS=0x00 PREC=0x00 TTL=50 ID=1 PROTO=TCP SPT=1 DPT=23 \
        WINDOW=1024 RES=0x00 SYN URGP=0";

    #[test]
    fn a_trap_line_is_read_in_every_format_the_kernel_log_arrives_in() {
        let cases = [
            ("kern.log, nftables, IPv4", KERN_LOG_V4, "203.0.113.5", 445),
            ("journal, IPv6 in full", JOURNAL_V6, "2001:db8::7", 3389),
            ("syslog, iptables LOG", SYSLOG_IPTABLES, "198.51.100.9", 23),
        ];
        for (what, line, address, port) in cases {
            let hit = parse_trap_line(line).unwrap_or_else(|| panic!("{what}: not read"));
            assert_eq!(
                (hit.address.to_string(), hit.port),
                (address.to_string(), port),
                "{what}"
            );
        }
    }

    #[test]
    fn a_line_that_is_not_the_trap_s_is_not_read() {
        let cases = [
            (
                "another program quoting the prefix",
                "Oct 16 10:00:03 web logger: stop-bots-trap: SRC=203.0.113.5 PROTO=TCP DPT=23",
            ),
            (
                "another firewall's log line",
                "Oct 16 10:00:03 web kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.5 PROTO=TCP DPT=23",
            ),
            (
                "UDP",
                "Oct 16 10:00:03 web kernel: stop-bots-trap: SRC=203.0.113.5 PROTO=UDP DPT=23",
            ),
            (
                "no source",
                "Oct 16 10:00:03 web kernel: stop-bots-trap: SRC= PROTO=TCP DPT=23",
            ),
            (
                "no port",
                "Oct 16 10:00:03 web kernel: stop-bots-trap: SRC=203.0.113.5 PROTO=TCP",
            ),
        ];
        for (what, line) in cases {
            assert_eq!(parse_trap_line(line), None, "{what}: {line}");
        }
    }

    fn hit(address: &str, port: u16) -> String {
        format!(
            "Oct 16 10:00:00 web kernel: stop-bots-trap: IN=eth0 OUT= SRC={address} \
             DST=192.0.2.10 PROTO=TCP SPT=40000 DPT={port} SYN URGP=0\n"
        )
    }

    /// One port might be a misdirected client; two different trap ports
    /// is a scan. Hits on the same port count once.
    #[test]
    fn an_address_is_a_scanner_at_two_different_trap_ports() {
        let cases = [
            ("one hit", vec![("203.0.113.5", 23)], false),
            (
                "one port, many times",
                vec![
                    ("203.0.113.5", 23),
                    ("203.0.113.5", 23),
                    ("203.0.113.5", 23),
                ],
                false,
            ),
            (
                "two ports",
                vec![("203.0.113.5", 23), ("203.0.113.5", 445)],
                true,
            ),
            (
                "two addresses, a port each",
                vec![("203.0.113.5", 23), ("203.0.113.6", 445)],
                false,
            ),
            (
                "a private address, many ports",
                vec![("10.0.0.5", 23), ("10.0.0.5", 445), ("10.0.0.5", 3389)],
                false,
            ),
        ];
        for (what, hits, convicted) in cases {
            let log: String = hits.iter().map(|(a, p)| hit(a, *p)).collect();
            let found = scanning_ips(&log, 2);
            assert_eq!(!found.is_empty(), convicted, "{what}: {found:?}");
        }
    }

    #[test]
    fn a_scanner_is_reported_with_every_port_it_tried() {
        let log = [
            hit("203.0.113.5", 3389),
            hit("203.0.113.5", 23),
            hit("203.0.113.5", 23),
        ]
        .concat();
        assert_eq!(
            scanning_ips(&log, 2),
            [("203.0.113.5".to_string(), vec![23, 3389])]
        );
    }

    /// The stored evidence is what the scheduled detector decides on: one
    /// distinct item per port, and nothing older than the window.
    #[test]
    fn the_observer_keeps_each_port_tried_inside_the_window() {
        let now = crate::logtime::iso8601("2026-10-16T12:00:00+00:00").unwrap();
        let mut observer = Observer::with_offset(now - 3600, now, None, 0);
        for line in [
            KERN_LOG_V4.replace("10:00:01", "11:30:00"),
            KERN_LOG_V4
                .replace("10:00:01", "11:31:00")
                .replace("DPT=445", "DPT=23"),
            // Before the window.
            KERN_LOG_V4
                .replace("10:00:01", "09:00:00")
                .replace("DPT=445", "DPT=3389"),
        ] {
            observer.line(&line);
        }

        let mut ports: Vec<String> = observer
            .finish()
            .rows_for(Detector::PortScanners)
            .into_iter()
            .filter_map(|row| match row.item {
                Item::Seen(port) => Some(port),
                _ => None,
            })
            .collect();
        ports.sort();
        assert_eq!(ports, ["23", "445"]);
    }

    #[test]
    fn the_ports_given_are_parsed_sorted_and_once() {
        assert_eq!(parse_ports("3389, 23 445,23").unwrap(), vec![23, 445, 3389]);
    }

    #[test]
    fn a_port_list_that_could_lock_out_ssh_or_the_web_is_refused() {
        for bad in ["22", "23,80", "443", "", " , ", "0", "65536", "telnet"] {
            assert!(parse_ports(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_ports_are_the_default_until_set_and_after_a_reset() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(configured_ports(&db).unwrap(), DEFAULT_TRAP_PORTS);
        assert!(ports_are_default(&db).unwrap());

        assert_eq!(set_ports(&db, "23 2323").unwrap(), [23, 2323]);
        assert!(!ports_are_default(&db).unwrap());

        assert_eq!(set_ports(&db, "default").unwrap(), DEFAULT_TRAP_PORTS);
    }

    /// Written by hand: a list that would trap SSH is never used.
    #[test]
    fn a_stored_list_the_parser_refuses_reads_as_the_default() {
        let db = Db::open_in_memory().unwrap();
        db.set_text_setting(PORTS, "22,23").unwrap();
        assert_eq!(configured_ports(&db).unwrap(), DEFAULT_TRAP_PORTS);
    }

    #[test]
    fn the_default_list_never_holds_a_port_that_is_never_trapped() {
        for port in NEVER_TRAPPED {
            assert!(!DEFAULT_TRAP_PORTS.contains(&port), "{port}");
        }
        assert!(parse_ports(&join(&DEFAULT_TRAP_PORTS)).is_ok());
    }

    /// `ss -ltnH`, as iproute2 prints it.
    const SS: &str = "\
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*
LISTEN 0      4096       127.0.0.1:6379      0.0.0.0:*
LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*
LISTEN 0      151        192.0.2.10:3306     0.0.0.0:*
LISTEN 0      511             [::]:443          [::]:*
LISTEN 0      244            [::1]:5432         [::]:*
LISTEN 0      50                 *:9200            *:*
";

    #[test]
    fn a_port_listening_beyond_loopback_is_listening_and_a_loopback_one_is_not() {
        assert_eq!(parse_listening(SS), [22, 80, 443, 3306, 9200]);
    }

    #[test]
    fn what_listens_and_sshd_s_port_are_left_out_of_the_trap() {
        let trap = resolve(&DEFAULT_TRAP_PORTS, &parse_listening(SS), &[2222, 23]);

        assert!(!trap.ports.contains(&3306), "listening: {trap:?}");
        assert!(!trap.ports.contains(&9200), "listening on *: {trap:?}");
        assert!(!trap.ports.contains(&23), "sshd's port: {trap:?}");
        assert!(trap.ports.contains(&6379), "only on loopback: {trap:?}");
        assert!(trap.ports.contains(&5432), "only on loopback: {trap:?}");
        assert_eq!(trap.left_out, [23, 3306, 9200]);
    }

    #[test]
    fn sshd_s_configured_ports_are_found() {
        let config = "\
# Port 2200
Port 2222
port 22
ListenAddress 0.0.0.0:4444
ListenAddress [::]:5555
ListenAddress ::1
ListenAddress 192.0.2.1
";
        assert_eq!(sshd_config_ports(config), [2222, 22, 4444, 5555]);
    }

    #[test]
    fn a_detector_that_is_off_traps_nothing_and_runs_nothing() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(state(&db).unwrap(), TrapState::Off);
        assert_eq!(for_render(&db).unwrap(), None);
    }
}
