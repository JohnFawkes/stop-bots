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

//! The verbs for the web application firewall: the exploit rules and
//! ModSecurity, for `cli.rs`'s definitions.

use anyhow::Result;
use std::path::PathBuf;
use stop_bots::modsecurity::{self, Mode};
use stop_bots::present::terminal_safe;
use stop_bots::{exploits, say};

use crate::cli::ModsecModeArg;
use crate::{find_site, open_db, read_access_log};

/// Said wherever a setting only NGINX can carry out is changed on a host
/// that runs something else.
fn nginx_only_note() {
    if let Ok(host) = stop_bots::hostconf::HostConf::load() {
        if host.web_server() != stop_bots::webserver::WebServer::Nginx {
            say!(
                "Note: this host runs {}, and only NGINX carries this out so far: nothing is \
                 written for it.",
                host.web_server().label()
            );
        }
    }
}

pub(crate) fn set_exploit_rules(
    db_path: Option<PathBuf>,
    enabled: Option<bool>,
    site: Option<String>,
    inherit: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    match site {
        Some(name) => {
            let site = find_site(&db, &name)?;
            db.set_site_exploit_rules(site.id, if inherit { None } else { enabled })?;
            let now = exploits::for_site(&db, site.id)?;
            say!(
                "{}: exploit payloads are {}{}.",
                terminal_safe(&site.server_name),
                if now { "turned away" } else { "let through" },
                if inherit { ", as the host says" } else { "" }
            );
        }
        None => {
            let enabled = enabled.unwrap_or(false);
            exploits::set_host_enabled(&db, enabled)?;
            say!(
                "Exploit payloads are {} on every site that has not chosen.",
                if enabled {
                    "turned away"
                } else {
                    "let through"
                }
            );
        }
    }
    nginx_only_note();
    say!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

pub(crate) fn preview_exploit_rules(
    db_path: Option<PathBuf>,
    access_log: Option<PathBuf>,
) -> Result<()> {
    let db = open_db(db_path)?;
    let log_text = read_access_log(&db, access_log.as_deref())?;
    let preview = exploits::preview(&log_text);
    say!(
        "Of {} request(s) in the log, the exploit rules would have turned away {}, from {} \
         address(es).",
        preview.requests,
        preview.matched,
        preview.addresses
    );
    if preview.matched == 0 {
        return Ok(());
    }
    say!(
        "{} of those were answered with a success: the application saw them.",
        preview.answered
    );
    for (signature, count) in &preview.by_signature {
        say!("  {count:>6}  {signature}");
    }
    say!("For example:");
    for sample in &preview.samples {
        say!("  {}", terminal_safe(sample));
    }
    Ok(())
}

/// What the host's NGINX lacks to run ModSecurity, said where it is
/// switched on.
fn installation_note() {
    let Ok(host) = stop_bots::hostconf::HostConf::load() else {
        return;
    };
    if host.web_server() != stop_bots::webserver::WebServer::Nginx {
        nginx_only_note();
        return;
    }
    if let modsecurity::Installation::Missing(why) = modsecurity::installation(&host.root(None)) {
        say!("Not written until it is installed: {why}.");
    }
}

pub(crate) fn set_modsecurity(
    db_path: Option<PathBuf>,
    mode: Option<ModsecModeArg>,
    paranoia: Option<u8>,
    site: Option<String>,
    inherit: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let mode = mode.map(|m| match m {
        ModsecModeArg::Off => Mode::Off,
        ModsecModeArg::Detect => Mode::Detect,
        ModsecModeArg::Block => Mode::Block,
    });
    match site {
        Some(name) => {
            let site = find_site(&db, &name)?;
            if inherit {
                db.set_site_modsecurity(site.id, None)?;
                db.set_site_paranoia(site.id, None)?;
            }
            if let Some(mode) = mode {
                db.set_site_modsecurity(site.id, Some(mode.as_str()))?;
            }
            if let Some(level) = paranoia {
                modsecurity::check_paranoia(level)?;
                db.set_site_paranoia(site.id, Some(level))?;
            }
            let now = modsecurity::site_mode(&db, site.id)?;
            say!(
                "{}: ModSecurity {} ({}), paranoia {}{}.",
                terminal_safe(&site.server_name),
                now.as_str(),
                now.describe(),
                modsecurity::site_paranoia(&db, site.id)?,
                if inherit { ", as the host says" } else { "" }
            );
            let apps = modsecurity::apps_behind(
                std::path::Path::new(&site.config_path),
                &site.server_name,
            );
            if !apps.is_empty() {
                say!("Behind it: {}.", apps.join(", "));
            }
        }
        None => {
            if let Some(mode) = mode {
                modsecurity::set_host_mode(&db, mode)?;
            }
            if let Some(level) = paranoia {
                modsecurity::set_host_paranoia(&db, level)?;
            }
            let now = modsecurity::host_mode(&db)?;
            say!(
                "ModSecurity is {} ({}), paranoia {}, on every site that has not chosen.",
                now.as_str(),
                now.describe(),
                modsecurity::host_paranoia(&db)?
            );
            if now == Mode::Block {
                say!(
                    "Block mode turns away what the Core Rule Set scores as an attack, including \
                     what it gets wrong about your applications. Detect mode first, and \
                     `list-modsecurity-findings`, is how to find that out."
                );
            }
        }
    }
    installation_note();
    say!("Run `stop-bots apply-blocks` to write it into the site config.");
    Ok(())
}

pub(crate) fn list_modsecurity_findings(
    db_path: Option<PathBuf>,
    site: Option<String>,
    audit_log: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let path = audit_log.unwrap_or_else(modsecurity::audit_log_path);
    let text = modsecurity::read_audit_log(&path).map_err(anyhow::Error::msg)?;
    let sites = db.list_sites()?;
    let only = match &site {
        Some(name) => Some(find_site(&db, name)?.id),
        None => None,
    };
    let findings: Vec<_> = modsecurity::findings(&text)
        .into_iter()
        .filter(|f| only.is_none() || f.site_id == only)
        .collect();
    let site_name = |id: Option<i64>| {
        id.and_then(|id| sites.iter().find(|s| s.id == id))
            .map(|s| s.server_name.clone())
    };
    if json {
        return stop_bots::output::print(&stop_bots::output::ModsecFindings {
            findings: findings
                .iter()
                .map(|f| stop_bots::output::ModsecFinding {
                    site: site_name(f.site_id),
                    rule: f.rule_id,
                    path: f.path.clone(),
                    message: f.message.clone(),
                    count: f.count,
                    over_threshold: f.over_threshold,
                    last_seen: f.last_seen.clone(),
                })
                .collect(),
        });
    }
    if findings.is_empty() {
        say!(
            "ModSecurity found nothing{}.",
            if only.is_some() { " on that site" } else { "" }
        );
        return Ok(());
    }
    say!(
        "{:<24} {:>7} {:>6} {:>5}  path, and what the rule says",
        "site",
        "rule",
        "seen",
        "over"
    );
    for finding in findings.iter().take(50) {
        let name = site_name(finding.site_id).unwrap_or_else(|| "(no site)".to_string());
        say!(
            "{:<24} {:>7} {:>6} {:>5}  {}  {}",
            terminal_safe(&name),
            finding.rule_id,
            finding.count,
            finding.over_threshold,
            terminal_safe(&finding.path),
            terminal_safe(&finding.message)
        );
    }
    say!(
        "A rule that fires on what your application really does: `stop-bots \
         exclude-modsecurity-rule --site <site> --rule <rule> --path <path>`."
    );
    Ok(())
}

pub(crate) fn exclude_modsecurity_rule(
    db_path: Option<PathBuf>,
    site: String,
    rule: u32,
    path: String,
    remove: bool,
) -> Result<()> {
    let db = open_db(db_path)?;
    let site = find_site(&db, &site)?;
    if remove {
        if !db.remove_modsec_exclusion(site.id, rule, &path)? {
            anyhow::bail!(
                "rule {rule} is not excluded under {path} on {}",
                site.server_name
            );
        }
        say!(
            "{}: rule {rule} is on again under {}.",
            terminal_safe(&site.server_name),
            terminal_safe(&path)
        );
    } else {
        db.add_modsec_exclusion(site.id, rule, &path)?;
        say!(
            "{}: rule {rule} is off under {}, and on everywhere else.",
            terminal_safe(&site.server_name),
            terminal_safe(&path)
        );
    }
    say!("Run `stop-bots apply-blocks` to write it.");
    Ok(())
}
