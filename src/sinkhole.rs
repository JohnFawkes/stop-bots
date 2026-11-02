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

//! Command-and-control *domains*, which a firewall cannot see: it only
//! ever meets the address a name resolved to, and a domain's address
//! moves. So the resolver is told instead. Every domain the enabled domain
//! feeds list resolves to one **sinkhole** address, and the sinkhole is a
//! listed destination like any other ([`crate::egress::Egress::listed`]):
//! a connection to it is logged with the user or container that made it,
//! and in Block mode dropped. The resolver turns a name into a hit the
//! firewall can attribute.
//!
//! ## Which resolver
//!
//! Whichever this host runs, and only one, chosen with `set-egress-dns`:
//!
//! - **`hosts`**: a marked block in `/etc/hosts`. Every program on the
//!   host that uses the system resolver reads it; containers do not, since
//!   each has an `/etc/hosts` of its own. An exact name only, no
//!   subdomains.
//! - **`dnsmasq`**: `address=/domain/sinkhole` lines in
//!   `/etc/dnsmasq.d/`. A domain and everything under it.
//! - **`unbound`**: a `redirect` zone per domain in
//!   `/etc/unbound/unbound.conf.d/`. A domain and everything under it.
//!
//! A container asks the resolver its runtime gives it. With Docker, that
//! is the host's upstream servers unless the host's resolver listens on
//! the bridge and containers are started with `--dns` pointing at it;
//! nothing here can change that, so it is said where the target is set.
//!
//! ## The sinkhole
//!
//! `192.0.2.1` unless set: TEST-NET-1, reserved for documentation, so no
//! real server is ever there, and a connection to it that is let through
//! in Watch mode goes nowhere.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::db::{keys, Db};
use crate::egress::EntryKind;

/// Where a sinkhole hit is reported from, in place of a feed's id.
pub const FEED_LABEL: &str = "dns-sinkhole";

/// The sinkhole when none is set.
pub const DEFAULT_SINKHOLE: &str = "192.0.2.1";

/// Marks the block this writes into `/etc/hosts`. Frozen: uninstall finds
/// the block by them.
pub const HOSTS_BEGIN: &str = "# BEGIN stop-bots egress (DO NOT EDIT)";
pub const HOSTS_END: &str = "# END stop-bots egress";

/// Which resolver is told about listed domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Off,
    Hosts,
    Dnsmasq,
    Unbound,
}

impl Target {
    pub const ALL: [Target; 4] = [Target::Off, Target::Hosts, Target::Dnsmasq, Target::Unbound];

    pub fn as_str(self) -> &'static str {
        match self {
            Target::Off => "off",
            Target::Hosts => "hosts",
            Target::Dnsmasq => "dnsmasq",
            Target::Unbound => "unbound",
        }
    }

    pub fn parse(text: &str) -> Option<Target> {
        Target::ALL.into_iter().find(|t| t.as_str() == text)
    }

    pub fn get(db: &Db) -> Result<Target> {
        Ok(db
            .get_text_setting(keys::EGRESS_DNS_TARGET)?
            .as_deref()
            .and_then(Target::parse)
            .unwrap_or(Target::Off))
    }

    /// The file it writes, under `prefix` (`/` on a host).
    pub fn path(self, prefix: &Path) -> Option<PathBuf> {
        let relative = match self {
            Target::Off => return None,
            Target::Hosts => "etc/hosts",
            Target::Dnsmasq => "etc/dnsmasq.d/stop-bots-egress.conf",
            Target::Unbound => "etc/unbound/unbound.conf.d/stop-bots-egress.conf",
        };
        Some(prefix.join(relative))
    }

    /// What makes the resolver read the file again: a fixed command, never
    /// one from the database. `/etc/hosts` is read on every lookup.
    pub fn reload_command(self) -> Option<&'static [&'static str]> {
        match self {
            Target::Off | Target::Hosts => None,
            // dnsmasq reads `address=` lines only when it starts.
            Target::Dnsmasq => Some(&["systemctl", "restart", "dnsmasq"]),
            Target::Unbound => Some(&["systemctl", "reload", "unbound"]),
        }
    }

    /// The managed-file kind it is recorded under, for uninstall. The
    /// hosts file is not one: it is the operator's, and only the block in
    /// it is ours.
    pub fn managed_kind(self) -> Option<&'static str> {
        match self {
            Target::Dnsmasq => Some("egress-dnsmasq"),
            Target::Unbound => Some("egress-unbound"),
            Target::Off | Target::Hosts => None,
        }
    }
}

/// Chooses the resolver, and the sinkhole if one is given.
pub fn set(db: &Db, target: Target, sinkhole: Option<&str>) -> Result<()> {
    if let Some(sinkhole) = sinkhole {
        let parsed: std::net::IpAddr = sinkhole
            .parse()
            .with_context(|| format!("the sinkhole must be one address: {sinkhole:?}"))?;
        if !parsed.is_ipv4() || parsed.is_loopback() || parsed.is_unspecified() {
            bail!(
                "the sinkhole must be an IPv4 address that is not this host's own: a connection \
                 to {parsed} would never leave it, so the firewall would never see it"
            );
        }
        db.set_text_setting(keys::EGRESS_SINKHOLE, &parsed.to_string())?;
    }
    db.set_text_setting(keys::EGRESS_DNS_TARGET, target.as_str())
}

/// The sinkhole address.
pub fn sinkhole(db: &Db) -> Result<String> {
    Ok(db
        .get_text_setting(keys::EGRESS_SINKHOLE)?
        .filter(|s| s.parse::<std::net::Ipv4Addr>().is_ok())
        .unwrap_or_else(|| DEFAULT_SINKHOLE.to_string()))
}

/// The sinkhole, when a resolver is being told to use it.
pub fn active_address(db: &Db) -> Result<Option<String>> {
    Ok(match Target::get(db)? {
        Target::Off => None,
        _ => Some(sinkhole(db)?),
    })
}

/// Every domain the enabled domain feeds list, once each, sorted.
pub fn domains(db: &Db) -> Result<Vec<String>> {
    let mut domains: Vec<String> = db
        .enabled_egress_entries(EntryKind::Domain)?
        .into_iter()
        .map(|(_, domain)| domain)
        .filter(|d| crate::egress::is_domain(d))
        .collect();
    domains.sort();
    domains.dedup();
    Ok(domains)
}

/// What `target` is given for `domains`: the whole file for dnsmasq and
/// unbound, the block between the markers for `/etc/hosts`.
pub fn render(target: Target, domains: &[String], sinkhole: &str) -> String {
    let mut out = String::new();
    match target {
        Target::Off => {}
        Target::Hosts => {
            out.push_str(HOSTS_BEGIN);
            out.push('\n');
            out.push_str(&format!(
                "# {}. Listed command-and-control domains, sent to the sinkhole.\n",
                crate::generated::generated_by()
            ));
            for domain in domains {
                out.push_str(&format!("{sinkhole} {domain}\n"));
            }
            out.push_str(HOSTS_END);
            out.push('\n');
        }
        Target::Dnsmasq => {
            out.push_str(&format!("# {}.\n", crate::generated::generated_by()));
            out.push_str("# Listed command-and-control domains, and everything under them,\n");
            out.push_str("# answered with the sinkhole. Rewritten when the feeds update.\n");
            for domain in domains {
                out.push_str(&format!("address=/{domain}/{sinkhole}\n"));
            }
        }
        Target::Unbound => {
            out.push_str(&format!("# {}.\n", crate::generated::generated_by()));
            out.push_str("# Listed command-and-control domains, and everything under them,\n");
            out.push_str("# answered with the sinkhole. Rewritten when the feeds update.\n");
            out.push_str("server:\n");
            for domain in domains {
                out.push_str(&format!("    local-zone: \"{domain}.\" redirect\n"));
                out.push_str(&format!("    local-data: \"{domain}. A {sinkhole}\"\n"));
            }
        }
    }
    out
}

/// `hosts` with its stop-bots block replaced by `block`, or appended when
/// it has none; with `block` empty, without it.
pub fn splice_hosts(hosts: &str, block: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    let mut replaced = false;
    for line in hosts.lines() {
        if line.trim_end() == HOSTS_BEGIN {
            inside = true;
            if !replaced {
                out.push_str(block);
                replaced = true;
            }
            continue;
        }
        if inside {
            if line.trim_end() == HOSTS_END {
                inside = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced && !block.is_empty() {
        if !out.is_empty() && !out.ends_with("\n\n") {
            out.push('\n');
        }
        out.push_str(block);
    }
    out
}

/// What [`apply`] would write, or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub path: PathBuf,
    pub domains: usize,
    pub changed: bool,
    /// What reloading the resolver said, when it was reloaded.
    pub reload: Option<std::result::Result<(), String>>,
}

impl Written {
    pub fn summary(&self) -> String {
        let mut out = format!(
            "{} domain(s) to the sinkhole in {}",
            self.domains,
            self.path.display()
        );
        if !self.changed {
            out.push_str(", unchanged");
        }
        match &self.reload {
            Some(Ok(())) => out.push_str(", resolver reloaded"),
            Some(Err(err)) => out.push_str(&format!(", reload failed: {err}")),
            None => {}
        }
        out
    }
}

/// Writes the listed domains for the chosen resolver under `prefix`, and
/// reloads it when `reload` and the file changed. `None` when no resolver
/// is chosen.
pub fn apply(db: &Db, prefix: &Path, reload: bool) -> Result<Option<Written>> {
    let target = Target::get(db)?;
    let Some(path) = target.path(prefix) else {
        return Ok(None);
    };
    let domains = domains(db)?;
    let content = render(target, &domains, &sinkhole(db)?);
    let (before, after) = match target {
        Target::Hosts => {
            let before = std::fs::read_to_string(&path)
                .with_context(|| format!("could not read {}", path.display()))?;
            let after = splice_hosts(&before, &content);
            (Some(before), after)
        }
        _ => (std::fs::read_to_string(&path).ok(), content),
    };
    let changed = before.as_deref() != Some(after.as_str());
    if changed {
        if let Some(kind) = target.managed_kind() {
            db.record_managed_file(&path, kind)?;
        }
        write_atomically(&path, &after)?;
    }
    let reload = (changed && reload)
        .then(|| target.reload_command())
        .flatten()
        .map(run_reload);
    Ok(Some(Written {
        path,
        domains: domains.len(),
        changed,
        reload,
    }))
}

fn run_reload(command: &[&str]) -> std::result::Result<(), String> {
    let output = std::process::Command::new(command[0])
        .args(&command[1..])
        .output()
        .map_err(|err| format!("could not run {}: {err}", command[0]))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Takes the stop-bots block out of `/etc/hosts` under `prefix`, and
/// removes the dnsmasq and unbound files: what uninstall does. The paths
/// removed or changed.
pub fn remove(prefix: &Path) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    if let Some(hosts) = Target::Hosts.path(prefix) {
        if let Ok(text) = std::fs::read_to_string(&hosts) {
            let spliced = splice_hosts(&text, "");
            if spliced != text {
                write_atomically(&hosts, &spliced)?;
                removed.push(hosts);
            }
        }
    }
    for target in [Target::Dnsmasq, Target::Unbound] {
        if let Some(path) = target.path(prefix) {
            if path.exists() {
                std::fs::remove_file(&path)
                    .with_context(|| format!("could not remove {}", path.display()))?;
                removed.push(path);
            }
        }
    }
    Ok(removed)
}

/// Replaces `path` in one step: written beside it, then renamed over it,
/// keeping its mode. A resolver never reads half a file.
fn write_atomically(path: &Path, content: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let dir = path
        .parent()
        .with_context(|| format!("{} has no directory", path.display()))?;
    if !dir.is_dir() {
        bail!(
            "{} does not exist: is the resolver installed?",
            dir.display()
        );
    }
    let mode = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let mut temp_name = std::ffi::OsString::from(".");
    temp_name.push(name);
    temp_name.push(format!(".stop-bots-{}", std::process::id()));
    let temp = dir.join(temp_name);
    let _ = std::fs::remove_file(&temp);
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(content.as_bytes())?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if let Err(err) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(err).with_context(|| format!("could not replace {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains() -> Vec<String> {
        vec!["c2.example.org".to_string(), "evil.example.com".to_string()]
    }

    #[test]
    fn each_resolver_is_given_every_domain_at_the_sinkhole() {
        let cases = [
            (
                Target::Hosts,
                vec!["192.0.2.1 c2.example.org", "192.0.2.1 evil.example.com"],
            ),
            (
                Target::Dnsmasq,
                vec![
                    "address=/c2.example.org/192.0.2.1",
                    "address=/evil.example.com/192.0.2.1",
                ],
            ),
            (
                Target::Unbound,
                vec![
                    "local-zone: \"c2.example.org.\" redirect",
                    "local-data: \"c2.example.org. A 192.0.2.1\"",
                    "local-zone: \"evil.example.com.\" redirect",
                ],
            ),
        ];
        for (target, lines) in cases {
            let rendered = render(target, &domains(), "192.0.2.1");
            for line in lines {
                assert!(
                    rendered.lines().any(|l| l.trim() == line),
                    "{} lacks {line:?}:\n{rendered}",
                    target.as_str()
                );
            }
        }
    }

    #[test]
    fn the_hosts_block_replaces_itself_and_nothing_else() {
        let hosts = "127.0.0.1 localhost\n::1 localhost\n";
        let block = render(Target::Hosts, &domains(), "192.0.2.1");
        let once = splice_hosts(hosts, &block);
        let twice = splice_hosts(&once, &block);
        assert_eq!(once, twice, "splicing again changed the file");
        assert!(once.starts_with(hosts), "{once}");
        assert_eq!(splice_hosts(&once, ""), format!("{hosts}\n"));
    }

    #[test]
    fn a_sinkhole_on_this_host_is_refused() {
        let db = Db::open_in_memory().unwrap();
        for bad in ["127.0.0.1", "0.0.0.0", "2001:db8::1", "example.com"] {
            assert!(
                set(&db, Target::Hosts, Some(bad)).is_err(),
                "{bad} was taken"
            );
        }
        set(&db, Target::Dnsmasq, Some("192.0.2.99")).unwrap();
        assert_eq!(active_address(&db).unwrap().as_deref(), Some("192.0.2.99"));
    }

    #[test]
    fn with_no_resolver_chosen_nothing_is_sent_to_the_sinkhole() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(active_address(&db).unwrap(), None);
        assert_eq!(apply(&db, Path::new("/nonexistent"), false).unwrap(), None);
    }

    #[test]
    fn applying_writes_the_block_once_and_uninstall_takes_it_out() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("etc")).unwrap();
        let hosts = dir.path().join("etc/hosts");
        std::fs::write(&hosts, "127.0.0.1 localhost\n").unwrap();
        let db = Db::open_in_memory().unwrap();
        crate::egress::register_builtin_feeds(&db).unwrap();
        db.set_egress_feed_enabled("c2intel-domains", true).unwrap();
        db.replace_egress_entries("c2intel-domains", &domains(), 0)
            .unwrap();
        set(&db, Target::Hosts, None).unwrap();

        let first = apply(&db, dir.path(), false).unwrap().unwrap();
        let second = apply(&db, dir.path(), false).unwrap().unwrap();
        assert!(
            first.changed && !second.changed,
            "{first:?} then {second:?}"
        );
        let text = std::fs::read_to_string(&hosts).unwrap();
        assert!(text.contains("192.0.2.1 evil.example.com"), "{text}");

        assert_eq!(remove(dir.path()).unwrap(), vec![hosts.clone()]);
        let text = std::fs::read_to_string(&hosts).unwrap();
        assert!(!text.contains("stop-bots"), "{text}");
    }
}
