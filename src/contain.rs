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

//! Containment: what happens to the container or user that called a
//! command-and-control server ([`crate::egress`]).
//!
//! A hit means something on this host is probably compromised already.
//! Blocking the one connection is the firewall's job and it has done it;
//! containment is about the next step the attacker takes. A container is
//! cut off from the network in both directions and, by default, paused:
//! every process in it frozen where it stands, so it can neither try
//! another server nor carry on towards root, and its memory is kept for
//! whoever looks at it next. A user on the host has every outbound
//! connection it starts cut off, so it can fetch no tooling and reach no
//! other server, while what it serves (a web server's replies) still goes
//! out.
//!
//! ## By hand, or automatically
//!
//! `contain` and `release` do it by hand. With `set-containment --auto
//! true`, a hit does it by itself, within the minute `tick` runs in, and
//! only:
//!
//! - in Block mode, never while only watching;
//! - for a hit on a feed allowed to contain (Feodo's, by default: see
//!   `egress::FeedKind::contains_by_default`);
//! - for containers, and for users only when that is switched on too;
//! - never for root, a user with a login session open right now (most
//!   likely the operator), or anything on the never-contain list.
//!
//! **And not too much at once.** A feed that lists something everyone
//! talks to by mistake would otherwise contain every container on the
//! host in one minute. More than [`DEFAULT_BREAKER_MAX`] automatic
//! containments in an hour, or one destination reached from that many
//! sources in one pass, trips a breaker instead: nothing more is
//! contained automatically until the operator resets it, and the alert
//! says why. Real compromises are rarely simultaneous.
//!
//! ## What stays contained
//!
//! A containment is a row until released, and the firewall script renders
//! every open one, so a reboot keeps it. Every pass also checks each open
//! one against what is running: a paused container that a restart policy
//! brought back is paused again, and one that came back with a new address
//! is cut off at that address instead, the old one let go (Docker gives a
//! stopped container's address to the next one). Releasing is always the
//! operator's: `release`, or `uninstall`, which releases everything.

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};

use crate::db::egress::{short_id, Containment, ContainmentKind, EgressHit, NewContainment};
use crate::db::{keys, Db};
use crate::egress::{self, Mode};
use crate::firewall::FirewallBackend;

/// What is done to what is contained, besides cutting it off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Cut off from the network, and nothing else.
    Isolate,
    /// A container cut off and frozen: `docker pause`.
    Pause,
    /// A container cut off and stopped: `docker stop`. Its memory is lost.
    Stop,
    /// A user cut off, and every process it runs killed.
    Kill,
}

impl Action {
    pub const ALL: [Action; 4] = [Action::Isolate, Action::Pause, Action::Stop, Action::Kill];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Isolate => "isolate",
            Action::Pause => "pause",
            Action::Stop => "stop",
            Action::Kill => "kill",
        }
    }

    pub fn parse(text: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == text)
    }

    /// Whether it means anything for `kind`.
    pub fn applies_to(self, kind: ContainmentKind) -> bool {
        match self {
            Action::Isolate => true,
            Action::Pause | Action::Stop => kind == ContainmentKind::Container,
            Action::Kill => kind == ContainmentKind::User,
        }
    }

    /// What it did, for a summary.
    pub fn done(self) -> &'static str {
        match self {
            Action::Isolate => "cut off",
            Action::Pause => "cut off and paused",
            Action::Stop => "cut off and stopped",
            Action::Kill => "cut off and its processes killed",
        }
    }
}

/// The most automatic containments in an hour before the breaker trips.
pub const DEFAULT_BREAKER_MAX: usize = 3;

/// How containment is set up on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub auto: bool,
    pub containers: bool,
    pub users: bool,
    pub container_action: Action,
    pub user_action: Action,
    /// Container names, user names and uids, never contained
    /// automatically.
    pub never: Vec<String>,
    pub breaker_max: usize,
    /// When the breaker tripped, while it is tripped.
    pub tripped_at: Option<i64>,
}

impl Settings {
    /// The stored settings. Automatic containment is off until switched
    /// on; once on, it applies to containers and not to users, and pauses.
    pub fn get(db: &Db) -> Result<Settings> {
        let action = |key: &str, default: Action, kind: ContainmentKind| -> Result<Action> {
            Ok(db
                .get_text_setting(key)?
                .as_deref()
                .and_then(Action::parse)
                .filter(|a| a.applies_to(kind))
                .unwrap_or(default))
        };
        Ok(Settings {
            auto: db.get_bool_setting(keys::EGRESS_AUTO_CONTAIN, false)?,
            containers: db.get_bool_setting(keys::EGRESS_CONTAIN_CONTAINERS, true)?,
            users: db.get_bool_setting(keys::EGRESS_CONTAIN_USERS, false)?,
            container_action: action(
                keys::EGRESS_CONTAINER_ACTION,
                Action::Pause,
                ContainmentKind::Container,
            )?,
            user_action: action(
                keys::EGRESS_USER_ACTION,
                Action::Isolate,
                ContainmentKind::User,
            )?,
            never: split_list(
                &db.get_text_setting(keys::EGRESS_NEVER_CONTAIN)?
                    .unwrap_or_default(),
            ),
            breaker_max: db
                .get_int_setting(keys::EGRESS_BREAKER_MAX, DEFAULT_BREAKER_MAX as i64)?
                .max(1) as usize,
            tripped_at: db
                .get_text_setting(keys::EGRESS_BREAKER_TRIPPED)?
                .and_then(|v| v.parse().ok()),
        })
    }

    /// Whether `name` (or `uid`) is on the never-contain list.
    fn never_contains(&self, names: &[&str]) -> bool {
        self.never
            .iter()
            .any(|never| names.iter().any(|name| never == name))
    }
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Adds `names` to the never-contain list, or takes them off it.
pub fn set_never(db: &Db, names: &[String], never: bool) -> Result<Vec<String>> {
    let mut list = Settings::get(db)?.never;
    for name in names {
        let name = name.trim();
        if name.is_empty() || name.contains(',') || name.chars().any(char::is_control) {
            bail!("not a container or user name: {name:?}");
        }
        if never {
            if !list.iter().any(|n| n == name) {
                list.push(name.to_string());
            }
        } else {
            list.retain(|n| n != name);
        }
    }
    db.set_text_setting(keys::EGRESS_NEVER_CONTAIN, &list.join(","))?;
    Ok(list)
}

/// Re-arms the breaker.
pub fn reset_breaker(db: &Db) -> Result<()> {
    db.delete_setting(keys::EGRESS_BREAKER_TRIPPED)
}

// ---- the container runtime ----

/// A container, as the runtime describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub addresses: Vec<String>,
    pub running: bool,
    pub paused: bool,
}

/// The container runtime's command line: `docker`, or one that takes the
/// same commands (`podman`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runtime {
    pub program: PathBuf,
}

impl Runtime {
    /// The runtime the host settings name, else `docker`, else `podman`,
    /// whichever is on `PATH`. `None` on a host with neither.
    pub fn find(host: &crate::hostconf::HostConf) -> Option<Runtime> {
        if let Some(program) = &host.container_runtime {
            return Some(Runtime {
                program: program.clone(),
            });
        }
        ["docker", "podman"]
            .into_iter()
            .find_map(crate::host::which)
            .map(|program| Runtime { program })
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let output = std::process::Command::new(&self.program)
            .args(args)
            .output()
            .with_context(|| format!("could not run {}", self.program.display()))?;
        if !output.status.success() {
            bail!(
                "`{} {}` failed: {}",
                self.program.display(),
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Every container, running or not.
    pub fn containers(&self) -> Result<Vec<Container>> {
        let ids = self.run(&["ps", "-a", "-q", "--no-trunc"])?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut args = vec!["inspect"];
        args.extend(&ids);
        parse_inspect(&self.run(&args)?)
    }

    pub fn pause(&self, id: &str) -> Result<()> {
        self.run(&["pause", id]).map(|_| ())
    }

    pub fn unpause(&self, id: &str) -> Result<()> {
        self.run(&["unpause", id]).map(|_| ())
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        self.run(&["stop", id]).map(|_| ())
    }
}

/// Reads `docker inspect` (or `podman inspect`) output: an array of
/// objects with `Id`, `Name`, `State.Running`, `State.Paused` and an
/// address per network in `NetworkSettings.Networks`.
pub fn parse_inspect(json: &str) -> Result<Vec<Container>> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("the container runtime's inspect is not JSON")?;
    let Some(items) = value.as_array() else {
        bail!("the container runtime's inspect is not a list");
    };
    let mut containers = Vec::new();
    for item in items {
        let Some(id) = item.get("Id").and_then(|v| v.as_str()) else {
            continue;
        };
        let name = item
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();
        let state = item.get("State");
        let flag = |key: &str| {
            state
                .and_then(|s| s.get(key))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        };
        let mut addresses = Vec::new();
        if let Some(networks) = item
            .pointer("/NetworkSettings/Networks")
            .and_then(|v| v.as_object())
        {
            for network in networks.values() {
                for key in ["IPAddress", "GlobalIPv6Address"] {
                    if let Some(address) = network.get(key).and_then(|v| v.as_str()) {
                        if address.parse::<IpAddr>().is_ok()
                            && !addresses.iter().any(|a| a == address)
                        {
                            addresses.push(address.to_string());
                        }
                    }
                }
            }
        }
        // The runtime lists networks in no particular order.
        addresses.sort();
        containers.push(Container {
            id: id.to_string(),
            name,
            addresses,
            running: flag("Running"),
            paused: flag("Paused"),
        });
    }
    Ok(containers)
}

// ---- the live firewall ----

/// Changes the containment sets of the loaded firewall in place, without
/// applying a script: containment must not apply the rest of what is
/// pending, which the operator has not looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFirewall {
    pub backend: FirewallBackend,
}

/// The nft sets and iptables chains containment changes. Frozen: the
/// renderers declare them and this module fills them.
pub const NFT_CONTAINED_V4: &str = "contained_v4";
pub const NFT_CONTAINED_V6: &str = "contained_v6";
pub const NFT_CONTAINED_UIDS: &str = "contained_uids";
pub const IPTABLES_EGRESS_CHAIN: &str = "STOP-BOTS-EGRESS";
pub const IPTABLES_OUT_CHAIN: &str = "STOP-BOTS-OUT";

fn run_program(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("could not run {program}"))?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

/// Whether `program args` succeeds, for an iptables `-C`.
fn succeeds(program: &str, args: &[&str]) -> bool {
    std::process::Command::new(program)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

const NOT_LOADED: &str = "the loaded firewall has no containment rules: apply the firewall with \
     outbound checks on (`set-egress --mode`), and this is enforced from then on";

impl LiveFirewall {
    /// Cuts `address` off, both ways. Adding what is already there is no
    /// change.
    pub fn add_address(&self, address: &str) -> Result<()> {
        let ip: IpAddr = address
            .parse()
            .with_context(|| format!("not an IP address: {address:?}"))?;
        match self.backend {
            FirewallBackend::Nftables => {
                let set = if ip.is_ipv6() {
                    NFT_CONTAINED_V6
                } else {
                    NFT_CONTAINED_V4
                };
                run_program(
                    "nft",
                    &[
                        "add",
                        "element",
                        "inet",
                        "stop_bots",
                        set,
                        &format!("{{ {ip} }}"),
                    ],
                )
                .context(NOT_LOADED)
            }
            FirewallBackend::Iptables => {
                let tool = if ip.is_ipv6() {
                    "ip6tables"
                } else {
                    "iptables"
                };
                let ip = ip.to_string();
                for flag in ["-s", "-d"] {
                    let rule = [IPTABLES_EGRESS_CHAIN, flag, ip.as_str(), "-j", "DROP"];
                    if !succeeds(tool, &[&["-w", "-C"][..], &rule].concat()) {
                        run_program(
                            tool,
                            &[&["-w", "-I"][..], &rule[..1], &["1"], &rule[1..]].concat(),
                        )
                        .context(NOT_LOADED)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Lets `address` back. Removing what is not there is no change.
    pub fn remove_address(&self, address: &str) -> Result<()> {
        let ip: IpAddr = address
            .parse()
            .with_context(|| format!("not an IP address: {address:?}"))?;
        match self.backend {
            FirewallBackend::Nftables => {
                let set = if ip.is_ipv6() {
                    NFT_CONTAINED_V6
                } else {
                    NFT_CONTAINED_V4
                };
                let element = format!("{{ {ip} }}");
                if succeeds(
                    "nft",
                    &["get", "element", "inet", "stop_bots", set, &element],
                ) {
                    run_program(
                        "nft",
                        &["delete", "element", "inet", "stop_bots", set, &element],
                    )?;
                }
                Ok(())
            }
            FirewallBackend::Iptables => {
                let tool = if ip.is_ipv6() {
                    "ip6tables"
                } else {
                    "iptables"
                };
                let ip = ip.to_string();
                for flag in ["-s", "-d"] {
                    let rule = [IPTABLES_EGRESS_CHAIN, flag, ip.as_str(), "-j", "DROP"];
                    while succeeds(tool, &[&["-w", "-C"][..], &rule].concat()) {
                        run_program(tool, &[&["-w", "-D"][..], &rule].concat())?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Cuts off every outbound connection `uid` starts.
    pub fn add_uid(&self, uid: u32) -> Result<()> {
        let uid = uid.to_string();
        match self.backend {
            FirewallBackend::Nftables => run_program(
                "nft",
                &[
                    "add",
                    "element",
                    "inet",
                    "stop_bots",
                    NFT_CONTAINED_UIDS,
                    &format!("{{ {uid} }}"),
                ],
            )
            .context(NOT_LOADED),
            FirewallBackend::Iptables => {
                for tool in ["iptables", "ip6tables"] {
                    let rule = uid_rule(&uid);
                    if !succeeds(tool, &[&["-w", "-C"][..], &rule].concat()) {
                        // After the loopback RETURN, which is the chain's
                        // first rule.
                        let insert =
                            [&["-w", "-I", IPTABLES_OUT_CHAIN, "2"][..], &rule[1..]].concat();
                        let result = run_program(tool, &insert).context(NOT_LOADED);
                        // ip6tables is missing on a host with IPv6 off,
                        // which leaves nothing to cut off there.
                        if tool == "iptables" {
                            result?;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Lets `uid` connect out again.
    pub fn remove_uid(&self, uid: u32) -> Result<()> {
        let uid = uid.to_string();
        match self.backend {
            FirewallBackend::Nftables => {
                let element = format!("{{ {uid} }}");
                if succeeds(
                    "nft",
                    &[
                        "get",
                        "element",
                        "inet",
                        "stop_bots",
                        NFT_CONTAINED_UIDS,
                        &element,
                    ],
                ) {
                    run_program(
                        "nft",
                        &[
                            "delete",
                            "element",
                            "inet",
                            "stop_bots",
                            NFT_CONTAINED_UIDS,
                            &element,
                        ],
                    )?;
                }
                Ok(())
            }
            FirewallBackend::Iptables => {
                for tool in ["iptables", "ip6tables"] {
                    let rule = uid_rule(&uid);
                    while succeeds(tool, &[&["-w", "-C"][..], &rule].concat()) {
                        run_program(tool, &[&["-w", "-D"][..], &rule].concat())?;
                    }
                }
                Ok(())
            }
        }
    }
}

/// The iptables rule that cuts off what `uid` starts, chain first.
fn uid_rule(uid: &str) -> Vec<&str> {
    vec![
        IPTABLES_OUT_CHAIN,
        "-m",
        "owner",
        "--uid-owner",
        uid,
        "-m",
        "conntrack",
        "--ctdir",
        "ORIGINAL",
        "-j",
        "DROP",
    ]
}

// ---- users ----

/// The name of `uid` in `passwd` (the text of `/etc/passwd`).
pub fn user_name(passwd: &str, uid: u32) -> Option<String> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let id = fields.nth(1)?.parse::<u32>().ok()?;
        (id == uid).then(|| name.to_string())
    })
}

/// The uid of `name` in `passwd`.
pub fn user_id(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == name).then_some(())?;
        fields.nth(1)?.parse::<u32>().ok()
    })
}

/// The first uid of an account a person logs in with, on Debian and its
/// kin: below it are the system's own accounts, `www-data` among them.
pub const FIRST_LOGIN_UID: u32 = 1000;

/// What the host looks like to containment, read before a decision: so
/// that a decision is a function of these and the database, testable, and
/// a test never asks the real host who is logged in.
#[derive(Debug, Clone, Default)]
pub struct Host {
    /// Every container, or `None` when there is no runtime or it could not
    /// be asked.
    pub containers: Option<Vec<Container>>,
    /// The text of `/etc/passwd`.
    pub passwd: String,
    /// The users with a login session open now, by name.
    pub logged_in: Vec<String>,
}

impl Host {
    /// Asks the real host. `runtime` is only asked when `containers`.
    pub fn look(runtime: Option<&Runtime>, containers: bool) -> Host {
        Host {
            containers: if containers {
                runtime.and_then(|r| r.containers().ok())
            } else {
                None
            },
            passwd: std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
            logged_in: logged_in_users(),
        }
    }

    fn container_with(&self, address: &str) -> Option<&Container> {
        self.containers
            .as_ref()?
            .iter()
            .find(|c| c.addresses.iter().any(|a| a == address))
    }

    fn container(&self, id: &str) -> Option<&Container> {
        self.containers.as_ref()?.iter().find(|c| c.id == id)
    }
}

/// The users `who` lists: those with a session open now.
fn logged_in_users() -> Vec<String> {
    let Ok(output) = std::process::Command::new("who").output() else {
        return Vec::new();
    };
    let mut users: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect();
    users.sort();
    users.dedup();
    users
}

// ---- containing and releasing ----

/// What to contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Container(Container),
    User { uid: u32, name: Option<String> },
    Address(String),
}

impl Target {
    pub fn kind(&self) -> ContainmentKind {
        match self {
            Target::Container(_) => ContainmentKind::Container,
            Target::User { .. } => ContainmentKind::User,
            Target::Address(_) => ContainmentKind::Address,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Target::Container(c) if !c.name.is_empty() => format!("container {}", c.name),
            Target::Container(c) => format!("container {}", short_id(&c.id)),
            Target::User {
                uid,
                name: Some(name),
            } => format!("user {name} (uid {uid})"),
            Target::User { uid, name: None } => format!("uid {uid}"),
            Target::Address(address) => format!("address {address}"),
        }
    }
}

/// What a front-end hands containment to act with.
pub struct Ctx<'a> {
    pub firewall: &'a LiveFirewall,
    pub runtime: Option<&'a Runtime>,
    /// Whether to change the host. `false` records what would be done and
    /// does none of it, for `--dry-run` and the TUI's `--no-reload`.
    pub for_real: bool,
}

/// Contains `target`: records it, cuts it off and does `action`. Each
/// step that fails is said in the summary and the rest still happen: a
/// container the firewall could not cut off is still paused.
pub fn contain(
    db: &Db,
    ctx: &Ctx,
    target: &Target,
    action: Action,
    reason: &str,
    automatic: bool,
) -> Result<String> {
    if !action.applies_to(target.kind()) {
        bail!(
            "{} cannot be done to a {}",
            action.as_str(),
            target.kind().as_str()
        );
    }
    let (target_key, name, addresses) = match target {
        Target::Container(c) => (c.id.clone(), Some(c.name.clone()), c.addresses.clone()),
        Target::User { uid, name } => {
            if *uid == 0 {
                bail!(
                    "root cannot be contained: what runs as root can undo anything this does, \
                     and cutting it off would cut off the host"
                );
            }
            (uid.to_string(), name.clone(), Vec::new())
        }
        Target::Address(address) => {
            let ip: IpAddr = address
                .parse()
                .with_context(|| format!("not one IP address: {address:?}"))?;
            if ip.is_loopback() || ip.is_unspecified() {
                bail!("{ip} is this host itself");
            }
            (ip.to_string(), None, vec![ip.to_string()])
        }
    };
    if !ctx.for_real {
        return Ok(format!("would have {} {}", action.done(), target.label()));
    }
    let (_, opened) = db.open_containment(&NewContainment {
        kind: target.kind(),
        target: target_key.clone(),
        name,
        addresses: addresses.clone(),
        action: action.as_str().to_string(),
        reason: reason.to_string(),
        automatic,
    })?;
    if !opened {
        return Ok(format!("{} was already contained", target.label()));
    }
    let mut notes = Vec::new();
    match target {
        Target::User { uid, .. } => {
            if let Err(err) = ctx.firewall.add_uid(*uid) {
                notes.push(format!("{err:#}"));
            }
        }
        _ => {
            for address in &addresses {
                if let Err(err) = ctx.firewall.add_address(address) {
                    notes.push(format!("{err:#}"));
                    break;
                }
            }
        }
    }
    match (target, action) {
        (Target::Container(c), Action::Pause) if !c.paused => {
            if let Err(err) = runtime_of(ctx).and_then(|r| r.pause(&c.id)) {
                notes.push(format!("could not pause it: {err:#}"));
            }
        }
        (Target::Container(c), Action::Stop) if c.running => {
            if let Err(err) = runtime_of(ctx).and_then(|r| r.stop(&c.id)) {
                notes.push(format!("could not stop it: {err:#}"));
            }
        }
        (Target::User { uid, .. }, Action::Kill) => {
            if *uid < FIRST_LOGIN_UID {
                notes.push(format!(
                    "its processes were not killed: uid {uid} is a system account, and killing \
                     what it runs would take a service down"
                ));
            } else if let Err(err) = run_program("pkill", &["-KILL", "-U", &uid.to_string()]) {
                notes.push(format!("could not kill its processes: {err:#}"));
            }
        }
        _ => {}
    }
    let mut summary = format!("{} {}", target.label(), action.done());
    if !notes.is_empty() {
        summary.push_str(&format!(" (but {})", notes.join("; ")));
    }
    Ok(summary)
}

fn runtime_of<'a>(ctx: &Ctx<'a>) -> Result<&'a Runtime> {
    ctx.runtime.context(
        "no container runtime: install docker or podman, or set one with `set-container-runtime`",
    )
}

/// Releases open containment `id`: lets it back onto the network, and
/// unpauses a container this paused. A stopped container is left stopped:
/// starting it again is the operator's call, once it has been looked at.
pub fn release(db: &Db, ctx: &Ctx, id: i64) -> Result<String> {
    let Some(containment) = db.containment(id)?.filter(|c| c.released_at.is_none()) else {
        bail!("no open containment with id {id}");
    };
    if !ctx.for_real {
        return Ok(format!("would have released {}", containment.label()));
    }
    let mut notes = Vec::new();
    let still_contained = |address: &str| -> Result<bool> {
        Ok(db
            .open_containments()?
            .iter()
            .any(|c| c.id != id && c.addresses.iter().any(|a| a == address)))
    };
    match containment.kind {
        ContainmentKind::User => {
            if let Ok(uid) = containment.target.parse::<u32>() {
                if let Err(err) = ctx.firewall.remove_uid(uid) {
                    notes.push(format!("{err:#}"));
                }
            }
        }
        _ => {
            for address in &containment.addresses {
                if still_contained(address)? {
                    continue;
                }
                if let Err(err) = ctx.firewall.remove_address(address) {
                    notes.push(format!("{err:#}"));
                }
            }
        }
    }
    if containment.kind == ContainmentKind::Container {
        match Action::parse(&containment.action) {
            Some(Action::Pause) => {
                if let Err(err) = runtime_of(ctx).and_then(|r| r.unpause(&containment.target)) {
                    notes.push(format!("could not unpause it: {err:#}"));
                }
            }
            Some(Action::Stop) => {
                notes.push("it stays stopped: start it when it is clean".to_string())
            }
            _ => {}
        }
    }
    db.release_containment(id)?;
    let mut summary = format!("released {}", containment.label());
    if !notes.is_empty() {
        summary.push_str(&format!(" ({})", notes.join("; ")));
    }
    Ok(summary)
}

/// Keeps every open containment true to what is running: see "What stays
/// contained" in the module docs. One line per thing it had to do.
pub fn maintain(db: &Db, ctx: &Ctx, host: &Host) -> Result<Vec<String>> {
    let mut said = Vec::new();
    if !ctx.for_real {
        return Ok(said);
    }
    for containment in db.open_containments()? {
        match containment.kind {
            ContainmentKind::User => {
                if let Ok(uid) = containment.target.parse::<u32>() {
                    if let Err(err) = ctx.firewall.add_uid(uid) {
                        said.push(format!("{}: {err:#}", containment.label()));
                    }
                }
            }
            ContainmentKind::Address => {
                for address in &containment.addresses {
                    if let Err(err) = ctx.firewall.add_address(address) {
                        said.push(format!("{}: {err:#}", containment.label()));
                    }
                }
            }
            ContainmentKind::Container => {
                said.extend(maintain_container(db, ctx, host, &containment)?);
            }
        }
    }
    Ok(said)
}

fn maintain_container(
    db: &Db,
    ctx: &Ctx,
    host: &Host,
    containment: &Containment,
) -> Result<Vec<String>> {
    let mut said = Vec::new();
    let label = containment.label();
    let Some(container) = host.container(&containment.target) else {
        // Without a runtime to ask, keep what is known cut off. A
        // container that is gone has no address to keep.
        if host.containers.is_none() {
            for address in &containment.addresses {
                if let Err(err) = ctx.firewall.add_address(address) {
                    said.push(format!("{label}: {err:#}"));
                }
            }
        }
        return Ok(said);
    };
    let mut current = container.addresses.clone();
    current.sort();
    let mut known = containment.addresses.clone();
    known.sort();
    if current != known && !current.is_empty() {
        for gone in known.iter().filter(|a| !current.contains(a)) {
            let elsewhere = db
                .open_containments()?
                .iter()
                .any(|c| c.id != containment.id && c.addresses.contains(gone));
            if !elsewhere {
                let _ = ctx.firewall.remove_address(gone);
            }
        }
        db.set_containment_addresses(containment.id, &current)?;
        said.push(format!(
            "{label} came back at {}, cut off there",
            current.join(", ")
        ));
    }
    for address in &current {
        if let Err(err) = ctx.firewall.add_address(address) {
            said.push(format!("{label}: {err:#}"));
        }
    }
    if Action::parse(&containment.action) == Some(Action::Pause)
        && container.running
        && !container.paused
    {
        match runtime_of(ctx).and_then(|r| r.pause(&container.id)) {
            Ok(()) => said.push(format!("{label} was running again, paused")),
            Err(err) => said.push(format!(
                "{label} is running again and could not be paused: {err:#}"
            )),
        }
    }
    Ok(said)
}

// ---- answering hits ----

/// Who a hit came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Culprit {
    Container(Container),
    User {
        uid: u32,
        name: Option<String>,
    },
    /// Forwarded from an address no container has: another machine this
    /// host routes for, or a container the runtime could not be asked
    /// about.
    Forwarded(String),
    /// From this host, with no user in the log line.
    Unknown,
}

impl Culprit {
    pub fn label(&self) -> String {
        match self {
            Culprit::Container(c) => format!(
                "container {} ({})",
                if c.name.is_empty() {
                    short_id(&c.id)
                } else {
                    &c.name
                },
                c.addresses.join(", ")
            ),
            Culprit::User {
                uid,
                name: Some(name),
            } => format!("user {name} (uid {uid})"),
            Culprit::User { uid, name: None } => format!("uid {uid}"),
            Culprit::Forwarded(address) => format!("{address}, forwarded through this host"),
            Culprit::Unknown => "a process on this host".to_string(),
        }
    }

    fn target(&self) -> Option<Target> {
        match self {
            Culprit::Container(c) => Some(Target::Container(c.clone())),
            Culprit::User { uid, name } => Some(Target::User {
                uid: *uid,
                name: name.clone(),
            }),
            Culprit::Forwarded(_) | Culprit::Unknown => None,
        }
    }
}

/// Who `hit` came from, as `host` describes it.
pub fn culprit(hit: &EgressHit, host: &Host) -> Culprit {
    match hit.path {
        egress::Path::Forward => match host.container_with(&hit.source) {
            Some(container) => Culprit::Container(container.clone()),
            None => Culprit::Forwarded(hit.source.clone()),
        },
        egress::Path::Host => match hit.uid {
            Some(uid) => Culprit::User {
                uid,
                name: user_name(&host.passwd, uid),
            },
            None => Culprit::Unknown,
        },
    }
}

/// Whether `culprit` may be contained automatically, or why not.
fn may_contain_automatically(
    culprit: &Culprit,
    settings: &Settings,
    host: &Host,
) -> std::result::Result<(), String> {
    match culprit {
        Culprit::Container(c) => {
            if !settings.containers {
                return Err("containers are not contained automatically".to_string());
            }
            if settings.never_contains(&[&c.name, &c.id, short_id(&c.id)]) {
                return Err(format!("{} is on the never-contain list", c.name));
            }
            Ok(())
        }
        Culprit::User { uid, name } => {
            if *uid == 0 {
                return Err("root is never contained".to_string());
            }
            if !settings.users {
                return Err("users are not contained automatically".to_string());
            }
            let uid_text = uid.to_string();
            let name = name.as_deref().unwrap_or("");
            if settings.never_contains(&[name, &uid_text]) {
                return Err(format!("{} is on the never-contain list", culprit.label()));
            }
            if !name.is_empty() && host.logged_in.iter().any(|u| u == name) {
                return Err(format!("{name} is logged in right now"));
            }
            Ok(())
        }
        Culprit::Forwarded(_) => Err("no container has that address".to_string()),
        Culprit::Unknown => Err("the log line names no user".to_string()),
    }
}

/// What answering the unanswered hits came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// One line per hit newly seen, for the operator.
    pub alerts: Vec<String>,
    /// What was contained, released or kept up, and why not where it was
    /// not.
    pub actions: Vec<String>,
    /// Whether the breaker tripped in this pass.
    pub tripped: bool,
}

impl Response {
    /// The job's summary: `ALERT: …` first when there is anything new,
    /// which is what `tick` prints for cron to mail.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.alerts.is_empty() {
            parts.push(format!("ALERT: {}", self.alerts.join("; ")));
        }
        parts.extend(self.actions.iter().cloned());
        if parts.is_empty() {
            "no outbound connections to listed addresses".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// Answers every unanswered hit at `now`: says who it came from and, when
/// automatic containment allows it, contains them; then keeps every open
/// containment true to `host`.
pub fn respond(db: &Db, ctx: &Ctx, host: &Host, now: i64) -> Result<Response> {
    let mode = Mode::get(db)?;
    let settings = Settings::get(db)?;
    let mut response = Response::default();
    let hits = db.unanswered_egress_hits()?;

    // Who is behind each hit, and whether its destination may contain.
    let mut decided: Vec<(EgressHit, Culprit, Vec<String>, bool)> = Vec::new();
    for hit in hits {
        let culprit = culprit(&hit, host);
        let feeds = match hit.destination.parse::<IpAddr>() {
            Ok(address) => egress::feeds_listing(db, address)?,
            Err(_) => Vec::new(),
        };
        let may = feeds_may_contain(db, &feeds)?;
        decided.push((hit, culprit, feeds, may));
    }

    // One destination reached from many sources in a pass is a feed
    // listing something everyone talks to, far more often than that many
    // compromises at once.
    let mut sources_per_destination: std::collections::HashMap<
        &str,
        std::collections::BTreeSet<String>,
    > = Default::default();
    for (hit, culprit, _, _) in &decided {
        sources_per_destination
            .entry(hit.destination.as_str())
            .or_default()
            .insert(culprit.label());
    }
    let crowded: Vec<String> = sources_per_destination
        .iter()
        .filter(|(_, sources)| sources.len() >= settings.breaker_max.max(2))
        .map(|(destination, _)| destination.to_string())
        .collect();

    let automatic = settings.auto && mode == Mode::Block;
    let mut candidates: Vec<(usize, Target)> = Vec::new();
    for (index, (hit, culprit, feeds, may)) in decided.iter().enumerate() {
        let blocked = if mode == Mode::Block {
            "blocked"
        } else {
            "let through: watching only"
        };
        let port = hit.port.map(|p| format!(":{p}")).unwrap_or_default();
        let listed = if feeds.is_empty() {
            "no longer listed".to_string()
        } else {
            format!("listed by {}", feeds.join(", "))
        };
        if hit.responded_at.is_none() {
            response.alerts.push(format!(
                "{} connected out to {}{port}, {listed} ({blocked})",
                culprit.label(),
                hit.destination
            ));
        }
        if !automatic {
            continue;
        }
        let Some(target) = culprit.target() else {
            continue;
        };
        if db
            .open_containment_of(target.kind(), &target_key(&target))?
            .is_some()
        {
            continue;
        }
        if !may {
            response.actions.push(format!(
                "{} not contained: no feed listing {} may contain",
                target.label(),
                hit.destination
            ));
            continue;
        }
        if crowded.contains(&hit.destination) {
            continue;
        }
        if let Err(why) = may_contain_automatically(culprit, &settings, host) {
            response
                .actions
                .push(format!("{} not contained: {why}", target.label()));
            continue;
        }
        if !candidates.iter().any(|(_, t)| t == &target) {
            candidates.push((index, target));
        }
    }

    if automatic && !crowded.is_empty() {
        response.tripped = true;
        response.actions.push(format!(
            "breaker tripped: {} reached from {} or more sources at once, which looks like a \
             feed listing something it should not; nothing more is contained automatically until \
             `set-containment --reset-breaker`",
            crowded.join(", "),
            settings.breaker_max.max(2)
        ));
    }
    let within_hour = db.automatic_containments_since(now - 3_600)?;
    if automatic && !response.tripped && within_hour + candidates.len() > settings.breaker_max {
        response.tripped = true;
        response.actions.push(format!(
            "breaker tripped: {} automatic containments within an hour is more than {}; nothing \
             more is contained automatically until `set-containment --reset-breaker`",
            within_hour + candidates.len(),
            settings.breaker_max
        ));
    }
    if response.tripped && ctx.for_real {
        db.set_text_setting(keys::EGRESS_BREAKER_TRIPPED, &now.to_string())?;
    }
    let tripped = response.tripped || settings.tripped_at.is_some();
    if automatic && tripped && !response.tripped && !candidates.is_empty() {
        response.actions.push(format!(
            "{} not contained: the breaker is tripped (`set-containment --reset-breaker`)",
            candidates
                .iter()
                .map(|(_, t)| t.label())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !tripped {
        for (index, target) in &candidates {
            let (hit, _, feeds, _) = &decided[*index];
            let action = match target.kind() {
                ContainmentKind::User => settings.user_action,
                _ => settings.container_action,
            };
            let port = hit.port.map(|p| format!(":{p}")).unwrap_or_default();
            let reason = format!(
                "connected out to {}{port}, listed by {}: {}",
                hit.destination,
                feeds.join(", "),
                hit.evidence
            );
            response
                .actions
                .push(contain(db, ctx, target, action, &reason, true)?);
        }
    }

    if ctx.for_real {
        for (hit, culprit, _, _) in &decided {
            let container = match culprit {
                Culprit::Container(c) => Some((c.id.as_str(), c.name.as_str())),
                _ => None,
            };
            db.answer_egress_hit(hit.id, container, now)?;
        }
    }
    response.actions.extend(maintain(db, ctx, host)?);
    Ok(response)
}

fn target_key(target: &Target) -> String {
    match target {
        Target::Container(c) => c.id.clone(),
        Target::User { uid, .. } => uid.to_string(),
        Target::Address(address) => address.clone(),
    }
}

/// Whether a hit on `feeds` may contain: one of them is allowed to. The
/// sinkhole stands for every enabled domain feed.
fn feeds_may_contain(db: &Db, feeds: &[String]) -> Result<bool> {
    let all = db.list_egress_feeds()?;
    Ok(feeds.iter().any(|id| {
        if id == crate::sinkhole::FEED_LABEL {
            all.iter()
                .any(|f| f.enabled && f.contain && f.kind == egress::EntryKind::Domain)
        } else {
            all.iter().any(|f| &f.id == id && f.contain)
        }
    }))
}

/// Finds what the operator named for `contain`: a container by name or id,
/// a user by name or uid, or an address.
pub fn resolve_target(spec: &str, kind: ContainmentKind, host: &Host) -> Result<Target> {
    match kind {
        ContainmentKind::Container => {
            let Some(containers) = &host.containers else {
                bail!("the container runtime could not be asked which containers there are");
            };
            let matching: Vec<&Container> = containers
                .iter()
                .filter(|c| {
                    c.name == spec || c.id == spec || (spec.len() >= 4 && c.id.starts_with(spec))
                })
                .collect();
            match matching.as_slice() {
                [one] => Ok(Target::Container((*one).clone())),
                [] => bail!("no container called {spec}"),
                _ => bail!("{spec} names more than one container: give more of its id"),
            }
        }
        ContainmentKind::User => {
            let uid = match spec.parse::<u32>() {
                Ok(uid) => uid,
                Err(_) => {
                    user_id(&host.passwd, spec).with_context(|| format!("no user called {spec}"))?
                }
            };
            Ok(Target::User {
                uid,
                name: user_name(&host.passwd, uid),
            })
        }
        ContainmentKind::Address => Ok(Target::Address(spec.to_string())),
    }
}

/// Releases every open containment: what `uninstall` does first, so that
/// nothing stays paused or cut off after the tool is gone.
pub fn release_all(db: &Db, ctx: &Ctx) -> Vec<std::result::Result<String, String>> {
    let open = match db.open_containments() {
        Ok(open) => open,
        Err(err) => return vec![Err(format!("{err:#}"))],
    };
    open.iter()
        .map(|c| release(db, ctx, c.id).map_err(|err| format!("{err:#}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::egress::NewEgressHit;

    const NOW: i64 = 1_800_000_000;

    fn web() -> Container {
        Container {
            id: "f".repeat(64),
            name: "web".to_string(),
            addresses: vec!["172.18.0.5".to_string()],
            running: true,
            paused: false,
        }
    }

    fn host() -> Host {
        Host {
            containers: Some(vec![web()]),
            passwd: "root:x:0:0::/root:/bin/sh\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n\
                     marko:x:1000:1000::/home/marko:/bin/sh\napp:x:1001:1001::/srv/app:/bin/sh\n"
                .to_string(),
            logged_in: vec!["marko".to_string()],
        }
    }

    /// A database in Block mode with Feodo on and listing 198.51.100.7.
    fn blocking() -> Db {
        let db = Db::open_in_memory().unwrap();
        egress::register_builtin_feeds(&db).unwrap();
        db.set_egress_feed_enabled("feodo", true).unwrap();
        let feed = db.get_egress_feed("feodo").unwrap().unwrap();
        egress::store(&db, &feed, "198.51.100.7\n", &[]).unwrap();
        Mode::Block.set(&db).unwrap();
        db
    }

    fn auto(db: &Db) {
        db.set_bool_setting(keys::EGRESS_AUTO_CONTAIN, true)
            .unwrap();
    }

    fn hit_from(path: egress::Path, source: &str, uid: Option<u32>) -> NewEgressHit {
        NewEgressHit {
            path,
            source: source.to_string(),
            destination: "198.51.100.7".to_string(),
            port: Some(443),
            protocol: "TCP".to_string(),
            uid,
            count: 1,
            first_seen: NOW,
            last_seen: NOW,
            evidence: "a kernel log line".to_string(),
        }
    }

    /// Records nothing on the host: `for_real` is what would run `nft` and
    /// `docker`, so these tests decide and record without it, and the
    /// container suite does the rest.
    fn decide(db: &Db, host: &Host) -> Response {
        let firewall = LiveFirewall {
            backend: FirewallBackend::Nftables,
        };
        let ctx = Ctx {
            firewall: &firewall,
            runtime: None,
            for_real: false,
        };
        // The real time: the containments it counts are dated by it.
        respond(db, &ctx, host, crate::testing::now_secs()).unwrap()
    }

    #[test]
    fn a_container_s_hit_is_reported_as_that_container() {
        let db = blocking();
        db.upsert_egress_hits(&[hit_from(egress::Path::Forward, "172.18.0.5", None)])
            .unwrap();
        let response = decide(&db, &host());
        assert_eq!(
            response.alerts,
            vec!["container web (172.18.0.5) connected out to 198.51.100.7:443, listed by feodo (blocked)"]
        );
        assert!(
            response.summary().starts_with("ALERT: "),
            "{}",
            response.summary()
        );
    }

    #[test]
    fn a_host_hit_is_reported_as_its_user() {
        let db = blocking();
        db.upsert_egress_hits(&[hit_from(egress::Path::Host, "192.0.2.10", Some(33))])
            .unwrap();
        let response = decide(&db, &host());
        assert_eq!(
            response.alerts,
            vec!["user www-data (uid 33) connected out to 198.51.100.7:443, listed by feodo (blocked)"]
        );
    }

    #[test]
    fn without_auto_containment_a_hit_is_only_reported() {
        let db = blocking();
        db.upsert_egress_hits(&[hit_from(egress::Path::Forward, "172.18.0.5", None)])
            .unwrap();
        assert!(decide(&db, &host()).actions.is_empty());
    }

    #[test]
    fn with_auto_containment_a_container_s_hit_contains_it() {
        let db = blocking();
        auto(&db);
        db.upsert_egress_hits(&[hit_from(egress::Path::Forward, "172.18.0.5", None)])
            .unwrap();
        assert_eq!(
            decide(&db, &host()).actions,
            vec!["would have cut off and paused container web"]
        );
    }

    /// Watching is for finding out what would be stopped, so nothing is
    /// contained while the mode is only that.
    #[test]
    fn nothing_is_contained_while_only_watching() {
        let db = blocking();
        auto(&db);
        Mode::Watch.set(&db).unwrap();
        db.upsert_egress_hits(&[hit_from(egress::Path::Forward, "172.18.0.5", None)])
            .unwrap();
        let response = decide(&db, &host());
        assert!(response.actions.is_empty(), "{:?}", response.actions);
        assert!(
            response.alerts[0].ends_with("(let through: watching only)"),
            "{:?}",
            response.alerts
        );
    }

    #[test]
    fn who_is_never_contained_automatically_and_why() {
        type Case<'a> = (&'a str, NewEgressHit, &'a dyn Fn(&Db));
        let cases: [Case; 5] = [
            (
                "users are not contained automatically",
                hit_from(egress::Path::Host, "192.0.2.10", Some(1001)),
                &|_| {},
            ),
            (
                "root is never contained",
                hit_from(egress::Path::Host, "192.0.2.10", Some(0)),
                &|db| {
                    db.set_bool_setting(keys::EGRESS_CONTAIN_USERS, true)
                        .unwrap()
                },
            ),
            (
                "marko is logged in right now",
                hit_from(egress::Path::Host, "192.0.2.10", Some(1000)),
                &|db| {
                    db.set_bool_setting(keys::EGRESS_CONTAIN_USERS, true)
                        .unwrap()
                },
            ),
            (
                "web is on the never-contain list",
                hit_from(egress::Path::Forward, "172.18.0.5", None),
                &|db| {
                    set_never(db, &["web".to_string()], true).unwrap();
                },
            ),
            (
                "no feed listing 198.51.100.7 may contain",
                hit_from(egress::Path::Forward, "172.18.0.5", None),
                &|db| db.set_egress_feed_contain("feodo", false).unwrap(),
            ),
        ];
        for (why, hit, setup) in cases {
            let db = blocking();
            auto(&db);
            setup(&db);
            db.upsert_egress_hits(&[hit]).unwrap();
            let actions = decide(&db, &host()).actions;
            assert!(
                actions.len() == 1 && actions[0].contains(why),
                "expected {why:?}, got {actions:?}"
            );
        }
    }

    #[test]
    fn a_user_is_contained_once_users_are_switched_on() {
        let db = blocking();
        auto(&db);
        db.set_bool_setting(keys::EGRESS_CONTAIN_USERS, true)
            .unwrap();
        db.upsert_egress_hits(&[hit_from(egress::Path::Host, "192.0.2.10", Some(1001))])
            .unwrap();
        assert_eq!(
            decide(&db, &host()).actions,
            vec!["would have cut off user app (uid 1001)"]
        );
    }

    /// One destination from many sources in one pass trips the breaker
    /// rather than containing them all.
    #[test]
    fn many_sources_at_one_destination_trip_the_breaker() {
        let db = blocking();
        auto(&db);
        let mut host = host();
        let mut hits = Vec::new();
        for n in 1..=3 {
            let address = format!("172.18.0.{}", 10 + n);
            host.containers.as_mut().unwrap().push(Container {
                id: format!("{n}").repeat(64),
                name: format!("app{n}"),
                addresses: vec![address.clone()],
                running: true,
                paused: false,
            });
            hits.push(hit_from(egress::Path::Forward, &address, None));
        }
        db.upsert_egress_hits(&hits).unwrap();
        let response = decide(&db, &host);
        assert!(response.tripped, "{response:?}");
        assert!(
            response.actions.iter().all(|a| !a.contains("would have")),
            "something was contained: {:?}",
            response.actions
        );
    }

    #[test]
    fn more_containments_in_an_hour_than_allowed_trip_the_breaker() {
        let db = blocking();
        auto(&db);
        db.set_int_setting(keys::EGRESS_BREAKER_MAX, 1).unwrap();
        db.open_containment(&NewContainment {
            kind: ContainmentKind::Container,
            target: "e".repeat(64),
            name: Some("earlier".to_string()),
            addresses: vec!["172.18.0.99".to_string()],
            action: "pause".to_string(),
            reason: "earlier".to_string(),
            automatic: true,
        })
        .unwrap();
        db.upsert_egress_hits(&[hit_from(egress::Path::Forward, "172.18.0.5", None)])
            .unwrap();
        let response = decide(&db, &host());
        assert!(response.tripped, "{response:?}");
    }

    #[test]
    fn inspect_output_gives_each_container_s_name_state_and_addresses() {
        let json = r#"[{"Id":"abc123","Name":"/web","State":{"Running":true,"Paused":false},
            "NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2","GlobalIPv6Address":""},
            "app":{"IPAddress":"172.18.0.5","GlobalIPv6Address":"fd00::5"}}}},
            {"Id":"def456","Name":"db","State":{"Running":false,"Paused":false},
            "NetworkSettings":{"Networks":{}}}]"#;
        let containers = parse_inspect(json).unwrap();
        assert_eq!(
            containers,
            vec![
                Container {
                    id: "abc123".to_string(),
                    name: "web".to_string(),
                    addresses: vec![
                        "172.17.0.2".to_string(),
                        "172.18.0.5".to_string(),
                        "fd00::5".to_string()
                    ],
                    running: true,
                    paused: false,
                },
                Container {
                    id: "def456".to_string(),
                    name: "db".to_string(),
                    addresses: Vec::new(),
                    running: false,
                    paused: false,
                },
            ]
        );
    }

    #[test]
    fn a_target_is_found_by_name_id_or_uid() {
        let host = host();
        let cases = [
            ("web", ContainmentKind::Container, "container web"),
            ("ffff", ContainmentKind::Container, "container web"),
            ("www-data", ContainmentKind::User, "user www-data (uid 33)"),
            ("1001", ContainmentKind::User, "user app (uid 1001)"),
        ];
        for (spec, kind, want) in cases {
            assert_eq!(
                resolve_target(spec, kind, &host).unwrap().label(),
                want,
                "{spec}"
            );
        }
        assert!(resolve_target("nobody-here", ContainmentKind::User, &host).is_err());
    }

    #[test]
    fn root_and_the_host_itself_cannot_be_contained() {
        let db = Db::open_in_memory().unwrap();
        let firewall = LiveFirewall {
            backend: FirewallBackend::Nftables,
        };
        let ctx = Ctx {
            firewall: &firewall,
            runtime: None,
            for_real: true,
        };
        let root = Target::User { uid: 0, name: None };
        assert!(contain(&db, &ctx, &root, Action::Isolate, "", false).is_err());
        let localhost = Target::Address("127.0.0.1".to_string());
        assert!(contain(&db, &ctx, &localhost, Action::Isolate, "", false).is_err());
        assert!(db.open_containments().unwrap().is_empty());
    }
}
