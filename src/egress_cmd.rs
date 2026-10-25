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

//! The verbs for outbound traffic and containment: what each does, for
//! `cli.rs`'s definitions. Apart from `main.rs` because they are a family
//! of their own, around `stop_bots::egress` and `stop_bots::contain`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use stop_bots::contain::{self, Action, Ctx, LiveFirewall, Runtime};
use stop_bots::db::egress::ContainmentKind;
use stop_bots::db::{keys, Db};
use stop_bots::egress::{self, EntryKind, Mode};
use stop_bots::present::terminal_safe;
use stop_bots::{say, say_err, sinkhole};

use crate::cli::{
    ContainActionArg, ContainerActionArg, DnsTargetArg, EgressModeArg, UserActionArg,
};
use crate::open_db;

/// The database, with every built-in feed known to it.
fn open(db_path: Option<PathBuf>) -> Result<Db> {
    let db = open_db(db_path)?;
    egress::register_builtin_feeds(&db)?;
    Ok(db)
}

fn when(at: Option<i64>) -> String {
    match at {
        Some(at) => stop_bots::present::ago(at),
        None => "never".to_string(),
    }
}

pub(crate) fn set_egress(db_path: Option<PathBuf>, mode: EgressModeArg) -> Result<()> {
    let db = open(db_path)?;
    let mode = match mode {
        EgressModeArg::Off => Mode::Off,
        EgressModeArg::Watch => Mode::Watch,
        EgressModeArg::Block => Mode::Block,
    };
    mode.set(&db)?;
    say!("Outbound checks: {} ({}).", mode.as_str(), mode.describe());
    let on: Vec<String> = db
        .list_egress_feeds()?
        .into_iter()
        .filter(|f| f.enabled && f.kind == EntryKind::Ip)
        .map(|f| f.id)
        .collect();
    if mode != Mode::Off && on.is_empty() {
        say!(
            "No address feed is switched on yet, so nothing is checked: `stop-bots \
             set-egress-feed --feed-id feodo --enabled true`, then `update-egress-feeds`."
        );
    }
    say!("Takes effect when the firewall is applied next (`stop-bots render-firewall --apply`).");
    Ok(())
}

pub(crate) fn list_feeds(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open(db_path)?;
    let feeds = db.list_egress_feeds()?;
    if json {
        return stop_bots::output::print(&stop_bots::output::EgressFeeds {
            feeds: feeds
                .iter()
                .map(|f| stop_bots::output::EgressFeed {
                    id: f.id.clone(),
                    name: f.name.clone(),
                    url: egress::feed_urls(f)
                        .iter()
                        .map(|u| egress::masked_url(u))
                        .collect(),
                    kind: f.kind.as_str(),
                    builtin: f.builtin,
                    enabled: f.enabled,
                    contain: f.contain,
                    last_fetched_at: f.last_fetched_at,
                    entries: f.entry_count,
                    kept_off: f.kept_off,
                })
                .collect(),
        });
    }
    for feed in feeds {
        say!(
            "{:<16} {:<3} {:<6} {:<8} {:>6} entries  fetched {}  {}",
            terminal_safe(&feed.id),
            if feed.enabled { "on" } else { "off" },
            feed.kind.as_str(),
            if feed.contain { "contains" } else { "" },
            feed.entry_count,
            when(feed.last_fetched_at),
            terminal_safe(&feed.name)
        );
        if !feed.builtin {
            say!("{:<16} from {}", "", egress::masked_url(&feed.url));
        }
        if feed.kept_off > 0 {
            say!(
                "{:<16} {} left out, to keep this host reachable",
                "",
                feed.kept_off
            );
        }
    }
    Ok(())
}

pub(crate) fn set_feed(
    db_path: Option<PathBuf>,
    feed_id: String,
    enabled: Option<bool>,
    contain: Option<bool>,
) -> Result<()> {
    let db = open(db_path)?;
    if enabled.is_none() && contain.is_none() {
        bail!("nothing to change: give --enabled, --contain or both");
    }
    if let Some(enabled) = enabled {
        db.set_egress_feed_enabled(&feed_id, enabled)?;
    }
    if let Some(contain) = contain {
        db.set_egress_feed_contain(&feed_id, contain)?;
    }
    let feed = db
        .get_egress_feed(&feed_id)?
        .context("the feed went away")?;
    say!(
        "{} is {}{}.",
        terminal_safe(&feed.id),
        if feed.enabled { "on" } else { "off" },
        if feed.contain {
            ", and a hit on it may contain"
        } else {
            ""
        }
    );
    if feed.enabled && feed.last_fetched_at.is_none() {
        say!("It has not been downloaded yet: `stop-bots update-egress-feeds`.");
    }
    Ok(())
}

pub(crate) fn add_feed(
    db_path: Option<PathBuf>,
    name: String,
    url: String,
    domains: bool,
    contain: bool,
) -> Result<()> {
    let db = open(db_path)?;
    let kind = if domains {
        EntryKind::Domain
    } else {
        EntryKind::Ip
    };
    let id = egress::add_custom_feed(&db, &name, &url, kind, contain)?;
    say!(
        "Added {id}, from {}. It is off: `stop-bots set-egress-feed --feed-id {id} --enabled true`.",
        egress::masked_url(&url)
    );
    Ok(())
}

pub(crate) fn remove_feed(db_path: Option<PathBuf>, feed_id: String) -> Result<()> {
    let db = open(db_path)?;
    db.remove_egress_feed(&feed_id)?;
    say!("Removed {}.", terminal_safe(&feed_id));
    Ok(())
}

pub(crate) async fn update_feeds(
    db_path: Option<PathBuf>,
    feed_id: Option<String>,
    source: Option<PathBuf>,
) -> Result<()> {
    let db = open(db_path)?;
    // A file given is a host with no outbound access, which has nothing to
    // resolve: its resolvers are still read from its own files.
    let offline = |_: &str| Vec::new();
    let around = egress::Surroundings {
        root: Path::new("/"),
        resolve: if source.is_some() {
            &offline
        } else {
            &egress::system_resolve
        },
    };
    let feeds: Vec<_> = match &feed_id {
        Some(id) => vec![db
            .get_egress_feed(id)?
            .with_context(|| format!("no egress feed with id: {id}"))?],
        None => db
            .list_egress_feeds()?
            .into_iter()
            .filter(|f| f.enabled)
            .collect(),
    };
    if feeds.is_empty() {
        say!("No C&C feed is switched on, so there is nothing to update (`list-egress-feeds`).");
        return Ok(());
    }
    let mut fetched = Vec::new();
    for feed in feeds {
        let raw = match &source {
            Some(path) => std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))
                .map_err(|err| format!("{err:#}")),
            None => egress::fetch(&feed).await.map_err(|err| format!("{err:#}")),
        };
        fetched.push((feed, raw));
    }
    let urls: Vec<String> = fetched
        .iter()
        .flat_map(|(feed, _)| egress::feed_urls(feed))
        .collect();
    let protected = egress::protected_destinations(&around, &urls);
    let (summary, ok) = egress::store_fetched(&db, &protected, fetched);
    for part in summary.split("; ") {
        say!("{}", terminal_safe(part));
    }
    if let Some(written) = sinkhole::apply(&db, Path::new("/"), true)? {
        say!("{}", terminal_safe(&written.summary()));
    }
    if !ok {
        bail!("a feed could not be updated; it keeps what it held");
    }
    Ok(())
}

pub(crate) fn list_hits(db_path: Option<PathBuf>, json: bool) -> Result<()> {
    let db = open(db_path)?;
    let hits = db.list_egress_hits()?;
    if json {
        return stop_bots::output::print(&stop_bots::output::EgressHits {
            hits: hits
                .iter()
                .map(|h| stop_bots::output::EgressHit {
                    path: h.path.as_str(),
                    source: h.source.clone(),
                    destination: h.destination.clone(),
                    port: h.port,
                    protocol: h.protocol.clone(),
                    uid: h.uid,
                    container: h.container_name.clone(),
                    count: h.count,
                    first_seen: h.first_seen,
                    last_seen: h.last_seen,
                    evidence: h.evidence.clone(),
                })
                .collect(),
        });
    }
    if hits.is_empty() {
        say!("No outbound attempt to a listed address is on record.");
    }
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    for hit in hits {
        let who = match (&hit.container_name, hit.uid) {
            (Some(name), _) => format!("container {name} ({})", hit.source),
            (None, Some(uid)) => match contain::user_name(&passwd, uid) {
                Some(name) => format!("user {name} (uid {uid})"),
                None => format!("uid {uid}"),
            },
            (None, None) => format!("{} ({})", hit.source, hit.path.as_str()),
        };
        let port = hit.port.map(|p| format!(":{p}")).unwrap_or_default();
        say!(
            "{}  {} -> {}{port} {}  {}x, last {}",
            when(Some(hit.first_seen)),
            terminal_safe(&who),
            hit.destination,
            hit.protocol,
            hit.count,
            when(Some(hit.last_seen))
        );
    }
    Ok(())
}

pub(crate) fn clear_hits(db_path: Option<PathBuf>, older_than_days: Option<u32>) -> Result<()> {
    let db = open(db_path)?;
    let before = older_than_days.map(|days| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
            - i64::from(days) * 86_400
    });
    let cleared = db.clear_egress_hits(before)?;
    say!("Forgot {cleared} outbound attempt(s).");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn set_containment(
    db_path: Option<PathBuf>,
    auto: Option<bool>,
    containers: Option<bool>,
    users: Option<bool>,
    container_action: Option<ContainerActionArg>,
    user_action: Option<UserActionArg>,
    never_contain: Vec<String>,
    may_contain: Vec<String>,
    breaker_max: Option<u32>,
    reset_breaker: bool,
) -> Result<()> {
    let db = open(db_path)?;
    if let Some(auto) = auto {
        db.set_bool_setting(keys::EGRESS_AUTO_CONTAIN, auto)?;
    }
    if let Some(containers) = containers {
        db.set_bool_setting(keys::EGRESS_CONTAIN_CONTAINERS, containers)?;
    }
    if let Some(users) = users {
        db.set_bool_setting(keys::EGRESS_CONTAIN_USERS, users)?;
    }
    if let Some(action) = container_action {
        let action = match action {
            ContainerActionArg::Isolate => Action::Isolate,
            ContainerActionArg::Pause => Action::Pause,
            ContainerActionArg::Stop => Action::Stop,
        };
        db.set_text_setting(keys::EGRESS_CONTAINER_ACTION, action.as_str())?;
    }
    if let Some(action) = user_action {
        let action = match action {
            UserActionArg::Isolate => Action::Isolate,
            UserActionArg::Kill => Action::Kill,
        };
        db.set_text_setting(keys::EGRESS_USER_ACTION, action.as_str())?;
    }
    if !never_contain.is_empty() {
        contain::set_never(&db, &never_contain, true)?;
    }
    if !may_contain.is_empty() {
        contain::set_never(&db, &may_contain, false)?;
    }
    if let Some(max) = breaker_max {
        db.set_int_setting(keys::EGRESS_BREAKER_MAX, i64::from(max))?;
    }
    if reset_breaker {
        contain::reset_breaker(&db)?;
    }
    say_containment(&db)
}

/// What `set-containment` and `status` say about the settings.
fn say_containment(db: &Db) -> Result<()> {
    let settings = contain::Settings::get(db)?;
    say!(
        "Automatic containment: {}.",
        if settings.auto { "on" } else { "off" }
    );
    if settings.auto {
        let mut applies = Vec::new();
        if settings.containers {
            applies.push(format!("containers ({})", settings.container_action.done()));
        }
        if settings.users {
            applies.push(format!("users ({})", settings.user_action.done()));
        }
        say!(
            "  Applies to: {}.",
            if applies.is_empty() {
                "nothing".to_string()
            } else {
                applies.join(", ")
            }
        );
        if Mode::get(db)? != Mode::Block {
            say!("  Only in Block mode, which this host is not in (`set-egress --mode block`).");
        }
    }
    if !settings.never.is_empty() {
        say!(
            "  Never contained: {}.",
            terminal_safe(&settings.never.join(", "))
        );
    }
    say!(
        "  Breaker: at most {} automatic containment(s) an hour{}.",
        settings.breaker_max,
        match settings.tripped_at {
            Some(at) => format!(
                "; TRIPPED {}, nothing more is contained until `--reset-breaker`",
                when(Some(at))
            ),
            None => String::new(),
        }
    );
    Ok(())
}

/// The context every containment verb acts with.
fn context_parts(db: &Db) -> Result<(LiveFirewall, Option<Runtime>)> {
    let host = stop_bots::hostconf::HostConf::load()?;
    Ok((
        LiveFirewall {
            backend: stop_bots::firewall::stored_backend(db)?,
        },
        Runtime::find(&host),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn contain_by_hand(
    db_path: Option<PathBuf>,
    container: Option<String>,
    user: Option<String>,
    address: Option<String>,
    action: Option<ContainActionArg>,
    reason: String,
    dry_run: bool,
) -> Result<()> {
    let db = open(db_path)?;
    let (firewall, runtime) = context_parts(&db)?;
    let (spec, kind) = match (container, user, address) {
        (Some(c), _, _) => (c, ContainmentKind::Container),
        (_, Some(u), _) => (u, ContainmentKind::User),
        (_, _, Some(a)) => (a, ContainmentKind::Address),
        _ => bail!("name a --container, a --user or an --address"),
    };
    let host = contain::Host::look(runtime.as_ref(), kind == ContainmentKind::Container);
    if kind == ContainmentKind::Container && runtime.is_none() {
        bail!("no container runtime found: install docker or podman, or `set-container-runtime`");
    }
    let target = contain::resolve_target(&spec, kind, &host)?;
    let settings = contain::Settings::get(&db)?;
    let action = match action {
        Some(ContainActionArg::Isolate) => Action::Isolate,
        Some(ContainActionArg::Pause) => Action::Pause,
        Some(ContainActionArg::Stop) => Action::Stop,
        Some(ContainActionArg::Kill) => Action::Kill,
        None => match kind {
            ContainmentKind::Container => settings.container_action,
            ContainmentKind::User => settings.user_action,
            ContainmentKind::Address => Action::Isolate,
        },
    };
    let ctx = Ctx {
        firewall: &firewall,
        runtime: runtime.as_ref(),
        for_real: !dry_run,
    };
    let said = contain::contain(&db, &ctx, &target, action, &reason, false)?;
    say!("{}.", terminal_safe(&said));
    if !dry_run {
        say!("Kept in every firewall script rendered until `stop-bots release`.");
    }
    Ok(())
}

pub(crate) fn release(
    db_path: Option<PathBuf>,
    id: Option<i64>,
    all: bool,
    dry_run: bool,
) -> Result<()> {
    let db = open(db_path)?;
    let (firewall, runtime) = context_parts(&db)?;
    let ctx = Ctx {
        firewall: &firewall,
        runtime: runtime.as_ref(),
        for_real: !dry_run,
    };
    let ids: Vec<i64> = match (id, all) {
        (Some(id), _) => vec![id],
        (None, true) => db.open_containments()?.iter().map(|c| c.id).collect(),
        (None, false) => bail!("name a containment with --id, or give --all"),
    };
    if ids.is_empty() {
        say!("Nothing is contained.");
    }
    let mut failed = 0;
    for id in ids {
        match contain::release(&db, &ctx, id) {
            Ok(said) => say!("{}.", terminal_safe(&said)),
            Err(err) => {
                failed += 1;
                say_err!("{}", terminal_safe(&format!("{err:#}")));
            }
        }
    }
    if failed > 0 {
        bail!("{failed} containment(s) could not be released");
    }
    Ok(())
}

pub(crate) fn list_containments(db_path: Option<PathBuf>, all: bool, json: bool) -> Result<()> {
    let db = open(db_path)?;
    let list = if all {
        db.list_containments()?
    } else {
        db.open_containments()?
    };
    if json {
        return stop_bots::output::print(&stop_bots::output::Containments {
            containments: list
                .iter()
                .map(|c| stop_bots::output::Containment {
                    id: c.id,
                    kind: c.kind.as_str(),
                    target: c.target.clone(),
                    name: c.name.clone(),
                    addresses: c.addresses.clone(),
                    action: c.action.clone(),
                    reason: c.reason.clone(),
                    automatic: c.automatic,
                    created_at: c.created_at,
                    released_at: c.released_at,
                })
                .collect(),
        });
    }
    if list.is_empty() {
        say!("Nothing is contained.");
    }
    for c in list {
        say!(
            "{:>4}  {}  {}, {}{}",
            c.id,
            terminal_safe(&c.label()),
            c.action,
            if c.automatic {
                "automatically "
            } else {
                "by hand "
            },
            when(Some(c.created_at))
        );
        say!("      {}", terminal_safe(&c.reason));
        if let Some(at) = c.released_at {
            say!("      released {}", when(Some(at)));
        }
    }
    Ok(())
}

pub(crate) fn set_dns(
    db_path: Option<PathBuf>,
    target: DnsTargetArg,
    sinkhole: Option<String>,
) -> Result<()> {
    let db = open(db_path)?;
    let target = match target {
        DnsTargetArg::Off => sinkhole::Target::Off,
        DnsTargetArg::Hosts => sinkhole::Target::Hosts,
        DnsTargetArg::Dnsmasq => sinkhole::Target::Dnsmasq,
        DnsTargetArg::Unbound => sinkhole::Target::Unbound,
    };
    let before = sinkhole::Target::get(&db)?;
    sinkhole::set(&db, target, sinkhole.as_deref())?;
    if target == sinkhole::Target::Off {
        if before != sinkhole::Target::Off {
            for path in sinkhole::remove(Path::new("/"))? {
                say!("Took the sinkhole out of {}.", path.display());
            }
        }
        say!("Listed domains are not sent to a sinkhole.");
        return Ok(());
    }
    say!(
        "Listed domains resolve to {} through {}. The sinkhole is checked like a listed address \
         once the firewall is applied next.",
        sinkhole::sinkhole(&db)?,
        target.as_str()
    );
    if sinkhole::domains(&db)?.is_empty() {
        say!(
            "No domain feed is on yet: `stop-bots set-egress-feed --feed-id c2intel-domains \
             --enabled true`, then `update-egress-feeds`."
        );
    }
    if matches!(
        target,
        sinkhole::Target::Dnsmasq | sinkhole::Target::Unbound
    ) {
        say!(
            "Containers ask this resolver only if they are given it: Docker's default is this \
             host's upstream servers. Start them with `--dns` set to an address it listens on."
        );
    }
    Ok(())
}

pub(crate) fn apply_dns(db_path: Option<PathBuf>, dry_run: bool, no_reload: bool) -> Result<()> {
    let db = open(db_path)?;
    let target = sinkhole::Target::get(&db)?;
    if target == sinkhole::Target::Off {
        bail!("no resolver is chosen: `stop-bots set-egress-dns --target hosts` (or dnsmasq, unbound)");
    }
    if dry_run {
        let domains = sinkhole::domains(&db)?;
        say!(
            "Would write {} domain(s) to {}:",
            domains.len(),
            target
                .path(Path::new("/"))
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        say!(
            "{}",
            terminal_safe(&sinkhole::render(
                target,
                &domains,
                &sinkhole::sinkhole(&db)?
            ))
        );
        return Ok(());
    }
    if let Some(written) = sinkhole::apply(&db, Path::new("/"), !no_reload)? {
        say!("{}.", terminal_safe(&written.summary()));
    }
    Ok(())
}

pub(crate) fn set_container_runtime(
    db_path: Option<PathBuf>,
    program: Option<PathBuf>,
) -> Result<()> {
    // Opened for the migration only, as `set-log-paths` does.
    let _db = open_db(db_path)?;
    let path = stop_bots::hostconf::path();
    let mut host = stop_bots::hostconf::HostConf::load_from(&path)?;
    host.container_runtime = match program {
        Some(program) if !program.as_os_str().is_empty() => {
            if !program.is_absolute() {
                bail!("{} is not an absolute path", program.display());
            }
            Some(program)
        }
        _ => None,
    };
    host.save_to(&path)?;
    match &host.container_runtime {
        Some(program) => say!("Containment asks {}.", program.display()),
        None => say!(
            "Containment asks docker, else podman: {}.",
            Runtime::find(&host)
                .map(|r| r.program.display().to_string())
                .unwrap_or_else(|| "neither is installed".to_string())
        ),
    }
    Ok(())
}

/// What `uninstall` does first: releases every open containment, so that
/// nothing stays paused once the tool is gone, each as a line of its
/// report. A database that cannot be opened has nothing to release.
pub(crate) fn release_for_uninstall(db_path: Option<PathBuf>, dry_run: bool) -> Vec<String> {
    let Ok(db) = open_db(db_path) else {
        return Vec::new();
    };
    let Ok((firewall, runtime)) = context_parts(&db) else {
        return Vec::new();
    };
    let ctx = Ctx {
        firewall: &firewall,
        runtime: runtime.as_ref(),
        for_real: !dry_run,
    };
    contain::release_all(&db, &ctx)
        .into_iter()
        .map(|result| match result {
            Ok(said) if dry_run => format!("would    {}", said.trim_start_matches("would have ")),
            Ok(said) => format!("done     {said}"),
            Err(err) => format!("FAILED   release a containment: {err}"),
        })
        .collect()
}

pub(crate) fn check(
    db_path: Option<PathBuf>,
    kernel_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    use stop_bots::cron::CronJob;

    let db = open(db_path)?;
    let host = stop_bots::hostconf::HostConf::load()?;
    let flags = stop_bots::logscan::Flags {
        kernel_log,
        stored: host.log_paths(),
        ..Default::default()
    };
    let applied = stop_bots::logscan::run(&db, &[CronJob::Egress], &flags)?;
    let runtime = Runtime::find(&host);
    let inputs = stop_bots::cron::EgressInputs {
        host: contain::Host::look(runtime.as_ref(), true),
        runtime,
    };
    let ran = stop_bots::cron::run_log_jobs(
        &db,
        &[CronJob::Egress],
        &applied,
        None,
        !dry_run,
        Some(&inputs),
    )?;
    for (_, summary) in ran {
        for part in summary.split("; ") {
            say!("{}", terminal_safe(part));
        }
    }
    Ok(())
}
