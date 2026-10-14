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

//! The Apache httpd backend: finds `<VirtualHost>` sections, and injects
//! and removes a sentinel-marked block of `mod_rewrite` rules at the top of
//! each one.
//!
//! Everything around that — the policy, the transaction an apply runs in,
//! the generated files' lifecycle — is [`crate::webserver`]'s, shared with
//! [`crate::nginx`]. This module only speaks Apache.
//!
//! ## How a block decides
//!
//! `mod_rewrite` is the one module every Apache has that can look at the
//! user agent, the path and the client's trust all at once, and it runs in
//! the translate-name phase, before `Alias`, `<Location>` or `.htaccess`
//! can route the request anywhere. The block uses the same flag idiom the
//! NGINX block does, with an environment variable as the flag: each reason
//! to block sets it, each exemption clears it, and one last rule acts on
//! it. Order is the whole mechanism, and every rule but the last carries
//! no `[L]`, so the site's own rewrite rules after the block still run.
//!
//! ```apache
//! # BEGIN stop-bots (DO NOT EDIT)
//! RewriteEngine On
//! RewriteCond %{HTTP_USER_AGENT} "(?:BadBot|EvilBot)" [NC]
//! RewriteRule ^ - [E=stop_bots_block:1]
//! RewriteCond %{REQUEST_URI} "^(/robots\.txt$)" [NC]
//! RewriteRule ^ - [E=stop_bots_block:0]
//! RewriteCond %{ENV:stop_bots_block} =1
//! RewriteRule ^ - [R=403,L]
//! # END stop-bots
//! ```
//!
//! ## What Apache cannot do that NGINX can
//!
//! - **Rate limiting.** Apache has no request-rate limit of its own (only
//!   third-party modules), so the setting is not rendered here.
//! - **Closing the connection (444), the tarpit and the teapot (418).**
//!   Each answers `403` instead: a block still blocks, only less cheaply.
//!   `mod_rewrite` refuses `[R=418]` outright, which the config test
//!   reports and the apply then undoes.
//!
//! ## Requirements
//!
//! `mod_rewrite`, which Debian ships but does not enable (`a2enmod
//! rewrite`), and `mod_setenvif` and `mod_alias`, which it enables. A
//! missing `mod_rewrite` fails the config test, and the apply puts every
//! file back and says so — a block that silently did nothing would be
//! worse.

use crate::webserver::*;
use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// The same markers NGINX's blocks carry, so an operator reading either
/// finds the same words. Apache only has whole-line comments, which is
/// what these are.
const BLOCK_BEGIN: &str = "# BEGIN stop-bots (DO NOT EDIT)";
const BLOCK_END: &str = "# END stop-bots";

/// The console's own section's markers, NGINX's too, and separate from the
/// block's for the reason `nginx::CONSOLE_BEGIN` gives.
const CONSOLE_BEGIN: &str = "# BEGIN stop-bots console (DO NOT EDIT)";
const CONSOLE_END: &str = "# END stop-bots console";

/// The stock location on Debian and Ubuntu.
pub const DEFAULT_ROOT: &str = "/etc/apache2";

/// The environment variable a block's rules set to block a request.
const BLOCK_VAR: &str = "stop_bots_block";

/// The environment variable the trust file sets for a trusted client.
const TRUSTED_VAR: &str = "stop_bots_trusted";

/// Where this project writes its own Apache files: the generated
/// `robots.txt`. A directory of its own, beside NGINX's, so that
/// switching a host from one server to the other leaves neither's files
/// in the other's way.
pub const MANAGED_DIR: &str = "/etc/stop-bots/apache";

/// Environment override for [`MANAGED_DIR`], for the end-to-end tests,
/// which drive the real binary and must not write to `/etc`. The same
/// test-only rationale as `nginx::MANAGED_DIR_ENV`.
pub const MANAGED_DIR_ENV: &str = "STOP_BOTS_APACHE_DIR";

/// The directory this project writes its own Apache files into.
pub fn managed_dir() -> PathBuf {
    std::env::var_os(MANAGED_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(MANAGED_DIR))
}

/// The generated `robots.txt`, aliased by the block when robots.txt
/// generation is on.
pub fn robots_txt_path() -> PathBuf {
    managed_dir().join("robots.txt")
}

/// The stock directory Debian's `apache2.conf` includes `*.conf` from.
pub const CONF_ENABLED_DIR: &str = "/etc/apache2/conf-enabled";

/// Environment override for [`conf_enabled_dir`], for the end-to-end
/// tests, as [`MANAGED_DIR_ENV`].
pub const CONF_ENABLED_DIR_ENV: &str = "STOP_BOTS_APACHE_CONF_D";

/// Where the server-wide trust file goes: `conf-enabled` beside the sites,
/// for a root that has one or is a tree of its own, and the stock one for a
/// root inside the stock tree (`/etc/apache2/sites-available`) — the same
/// rule, and for the same reasons, as `nginx::conf_d_dir`.
///
/// A plain file in `conf-enabled` rather than one in `conf-available` and
/// a link: `a2enconf` is how an operator enables their own files, and one
/// file is one thing to remove.
pub fn conf_enabled_dir(root: &Path) -> PathBuf {
    if let Some(dir) = std::env::var_os(CONF_ENABLED_DIR_ENV) {
        return PathBuf::from(dir);
    }
    let beside_the_sites = root.join("conf-enabled");
    let in_stock_tree = root.starts_with(DEFAULT_ROOT)
        && !root
            .components()
            .any(|part| part == std::path::Component::ParentDir);
    if beside_the_sites.is_dir() || !in_stock_tree {
        return beside_the_sites;
    }
    PathBuf::from(CONF_ENABLED_DIR)
}

/// The trust file: one `SetEnvIf` per trusted address or user agent.
/// The same name as NGINX's, so `ManagedKind` knows it either way.
pub fn trusted_conf_path(conf_enabled: &Path) -> PathBuf {
    conf_enabled.join("stop-bots-trusted.conf")
}

/// What to do when the config root is not there.
fn missing_root_hint() -> &'static str {
    "If Apache's config lives somewhere else, store where with \
     `stop-bots set-web-server apache --root <dir>`, or pass `--root <dir>` for one run."
}

// ---- reading a config ----

/// One logical line of a config file: physical lines joined where one
/// ends in a backslash, as Apache's own reader joins them.
struct Line {
    /// Byte offset of its first character.
    start: usize,
    /// Byte offset just past it, its line break included.
    end: usize,
    /// Its text, continuations joined, without the line break.
    text: String,
}

fn lines(content: &str) -> Vec<Line> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut text = String::new();
    let mut at = 0;
    for physical in content.split_inclusive('\n') {
        let bare = physical.trim_end_matches('\n').trim_end_matches('\r');
        at += physical.len();
        if let Some(joined) = bare.strip_suffix('\\') {
            text.push_str(joined);
            continue;
        }
        text.push_str(bare);
        out.push(Line {
            start,
            end: at,
            text: std::mem::take(&mut text),
        });
        start = at;
    }
    if !text.is_empty() {
        out.push(Line {
            start,
            end: at,
            text,
        });
    }
    out
}

/// A `<VirtualHost>` section found while scanning a config file.
#[derive(Debug, Clone)]
struct VirtualHost {
    /// `ServerName` first (or `_` when there is none, the catch-all name
    /// NGINX configs use for the same thing), then every `ServerAlias`.
    names: Vec<String>,
    /// Whether it terminates TLS: `SSLEngine on`, or an address on 443.
    /// The same thing NGINX's `is_tls` is load-bearing for — see
    /// `nginx::ServerBlock::is_tls`.
    is_tls: bool,
    /// Byte offset of the line after `<VirtualHost ...>`, where a block
    /// is inserted.
    open: usize,
    /// Byte offset of the `</VirtualHost>` line.
    close: usize,
    /// Every directive inside, nested sections' included, as its name
    /// (lowercased) and its arguments.
    directives: Vec<(String, Vec<String>)>,
}

/// Splits a directive's arguments the way Apache's `ap_getword_conf`
/// does: whitespace separates words, and a word that starts with a quote
/// runs to the matching quote, inside which a backslash escapes that quote
/// or another backslash.
fn words(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else {
            return out;
        };
        let mut word = String::new();
        if first == '"' || first == '\'' {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' if chars.peek().is_some_and(|&n| n == first || n == '\\') => {
                        word.push(chars.next().unwrap_or('\\'));
                    }
                    c if c == first => break,
                    c => word.push(c),
                }
            }
        } else {
            while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                word.push(c);
            }
        }
        out.push(word);
    }
}

/// A section's opening or closing tag on `line`: its name, lowercased,
/// whether it closes, and its arguments.
fn section(line: &str) -> Option<(String, bool, Vec<String>)> {
    let tag = line.trim().strip_prefix('<')?;
    let tag = tag.strip_suffix('>')?;
    let (closing, tag) = match tag.strip_prefix('/') {
        Some(rest) => (true, rest),
        None => (false, tag),
    };
    let mut parts = words(tag);
    if parts.is_empty() {
        return None;
    }
    let name = parts.remove(0).to_ascii_lowercase();
    Some((name, closing, parts))
}

/// A host name as `ServerName` may write it — `https://example.com:443`
/// — reduced to the name, which is what a site is stored under.
fn bare_name(name: &str) -> String {
    let name = name.split_once("://").map_or(name, |(_, rest)| rest);
    let name = match name.strip_prefix('[') {
        // `[2001:db8::1]:443`: the brackets hold the colons.
        Some(v6) => return v6.split(']').next().unwrap_or(v6).to_string(),
        None => name,
    };
    name.split(':').next().unwrap_or(name).to_string()
}

/// Every `<VirtualHost>` in `content`, in order.
///
/// Only whole-line comments are comments in Apache, and only a line
/// starting with `<` can open or close a section, so a line this tool
/// writes — every one of which starts with a directive name or `#` — can
/// never be read as structure, whatever a quoted pattern in it holds.
fn virtual_hosts(content: &str) -> Vec<VirtualHost> {
    let mut hosts = Vec::new();
    // The open `<VirtualHost>`, and how deep inside it nested sections go.
    let mut current: Option<(VirtualHost, usize)> = None;
    for line in lines(content) {
        let text = line.text.trim();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if let Some((name, closing, args)) = section(text) {
            match (&mut current, name.as_str(), closing) {
                (None, "virtualhost", false) => {
                    let is_tls = args.iter().any(|addr| addr.ends_with(":443"));
                    current = Some((
                        VirtualHost {
                            names: Vec::new(),
                            is_tls,
                            open: line.end,
                            close: line.end,
                            directives: Vec::new(),
                        },
                        0,
                    ));
                }
                (Some((host, 0)), "virtualhost", true) => {
                    host.close = line.start;
                    let (mut host, _) = current.take().expect("a host is open");
                    finish(&mut host);
                    hosts.push(host);
                }
                (Some((_, depth)), _, false) => *depth += 1,
                (Some((_, depth)), _, true) => *depth = depth.saturating_sub(1),
                (None, _, _) => {}
            }
            continue;
        }
        if let Some((host, _)) = &mut current {
            let mut parts = words(text);
            if parts.is_empty() {
                continue;
            }
            let name = parts.remove(0).to_ascii_lowercase();
            host.directives.push((name, parts));
        }
    }
    hosts
}

/// Fills in a closed host's names and TLS from its directives.
fn finish(host: &mut VirtualHost) {
    let mut server_name = None;
    let mut aliases = Vec::new();
    for (name, args) in &host.directives {
        match name.as_str() {
            "servername" => server_name = server_name.or(args.first().map(|n| bare_name(n))),
            "serveralias" => aliases.extend(args.iter().map(|n| bare_name(n))),
            "sslengine" => {
                host.is_tls |= args.first().is_some_and(|v| v.eq_ignore_ascii_case("on"))
            }
            _ => {}
        }
    }
    host.names = std::iter::once(server_name.unwrap_or_else(|| "_".to_string()))
        .chain(aliases)
        .collect();
}

/// Walks `root` for config files holding `<VirtualHost>` sections,
/// returning one [`DiscoveredSite`] per section, named after its
/// `ServerName`. The same walk, and the same refusal of a root that does
/// not exist, as `nginx::discover_sites`: links are not followed, so
/// Debian's `sites-enabled` links lead nowhere and each site is found once,
/// in `sites-available`.
pub fn discover_sites(root: &Path) -> Result<Vec<DiscoveredSite>> {
    if !root.exists() {
        return Err(crate::hint::with(
            anyhow::anyhow!("{} does not exist", root.display()),
            missing_root_hint(),
        ));
    }
    let mut sites = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        for host in virtual_hosts(&content) {
            sites.push(DiscoveredSite {
                server_name: host.names[0].clone(),
                config_path: path.to_path_buf(),
            });
        }
    }
    Ok(sites)
}

// ---- writing a block ----

/// `regex` as one double-quoted `RewriteCond` pattern.
///
/// `mod_rewrite` reads its own arguments: a quoted one runs to the next
/// quote of its kind, and nothing escapes it. So a `"` is written as PCRE's
/// `\x22`, which matches the same character without being one — an escaped
/// `\"` included, whose backslash goes with it. Every other character,
/// backslashes too, reaches PCRE as written.
///
/// Wrapped in `(?:...)` as well. A pattern `mod_rewrite` sees starting with
/// `!` is negated, and one that is `-f` or `>x` is a file test or a string
/// comparison, not a regex; a group in front is a regex whatever follows,
/// and matches the same strings.
fn rewrite_quoted(regex: &str) -> String {
    let mut out = String::from("\"(?:");
    let mut chars = regex.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'"') => {
                chars.next();
                out.push_str(r"\x22");
            }
            '\\' => {
                out.push('\\');
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            '"' => out.push_str(r"\x22"),
            c => out.push(c),
        }
    }
    out.push_str(")\"");
    out
}

/// `text` as one double-quoted argument Apache's core reads
/// (`ap_getword_conf`): a backslash or a quote inside is escaped with a
/// backslash.
fn conf_quoted(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', r"\\").replace('"', r#"\""#))
}

/// Whether `regex` can be written into an Apache config at all.
///
/// Apache substitutes `${NAME}` in every config line it reads, before any
/// module sees the line, so a pattern holding `${` would reach PCRE as
/// something else. And a control character would end the line. Neither is
/// a pattern worth guessing about.
fn survives_apache(regex: &str) -> bool {
    !regex.contains("${") && !regex.chars().any(char::is_control)
}

/// The patterns to write, of those `nginx` already finds usable as PCRE
/// (Apache's regex engine too), less any [`survives_apache`] refuses.
fn usable_patterns(patterns: &[String]) -> Vec<&str> {
    crate::nginx::usable_patterns(patterns)
        .into_iter()
        .filter(|p| survives_apache(p))
        .collect()
}

/// A request rule's `RewriteCond`, without the `RewriteCond` itself.
fn condition(rule: RequestRule) -> String {
    let matches = |variable: &str, regex: &str| format!("{variable} {}", rewrite_quoted(regex));
    match rule {
        // `HTTP/2.0` under mod_http2, and only ever 1.x without it.
        RequestRule::Http1x => matches("%{SERVER_PROTOCOL}", r"^HTTP/1\."),
        RequestRule::NoAccept => matches("%{HTTP:Accept}", "^$"),
        RequestRule::NoAcceptLanguage => matches("%{HTTP:Accept-Language}", "^$"),
        RequestRule::NoUserAgent => matches("%{HTTP_USER_AGENT}", "^$"),
        // `HTTP_HOST` keeps a port, which an anchored match ignores.
        RequestRule::IpLiteralHost => matches("%{HTTP_HOST}", r"^(\d+\.\d+\.\d+\.\d+|\[)"),
        RequestRule::OldTls => matches("%{SSL:SSL_PROTOCOL}", r"^TLSv1(\.[01])?$"),
    }
}

/// The status a blocked request is answered with. `444` and the tarpit
/// are NGINX's; here both are the `403` they stand in for. So is `418`:
/// `mod_rewrite` refuses to send a status Apache has no reason phrase for,
/// and a config the test rejects is no block at all.
fn status_code(response: crate::db::BlockResponse) -> u16 {
    match response.status_code() {
        444 | 418 => 403,
        code => code,
    }
}

/// Renders the sentinel block for `config`, or `None` when there is
/// nothing to block and nothing to serve — which is what makes
/// [`apply_block`] remove an existing block. Rate limiting is not
/// rendered: see the module docs.
fn block_text(config: &BlockConfig) -> Option<String> {
    let chunks = crate::nginx::chunk_patterns(
        &usable_patterns(&config.patterns),
        crate::nginx::MAX_PATTERN_CHUNK_LEN,
    );
    let blocks_something = !chunks.is_empty() || !config.request_rules.is_empty();
    if !blocks_something && !config.serve_robots_txt {
        return None;
    }
    let mut out = format!("    {BLOCK_BEGIN}\n    RewriteEngine On\n");
    if config.serve_robots_txt {
        let robots = robots_txt_path();
        let dir = robots.parent().unwrap_or(Path::new("/"));
        out.push_str(&format!(
            "    Alias \"/robots.txt\" {}\n    <Directory {}>\n        Require all granted\n    </Directory>\n",
            conf_quoted(&robots.display().to_string()),
            conf_quoted(&dir.display().to_string()),
        ));
    }
    if blocks_something {
        let set = |value: u8| format!("    RewriteRule ^ - [E={BLOCK_VAR}:{value}]\n");
        for chunk in &chunks {
            out.push_str(&format!(
                "    RewriteCond %{{HTTP_USER_AGENT}} {} [NC]\n{}",
                rewrite_quoted(chunk),
                set(1)
            ));
        }
        for rule in &config.request_rules {
            out.push_str(&format!("    RewriteCond {}\n{}", condition(*rule), set(1)));
        }
        let (prefixes, exact) = effective_exempt_paths(config);
        for paths in crate::nginx::exemption_regexes(&prefixes, exact) {
            out.push_str(&format!(
                "    RewriteCond %{{REQUEST_URI}} {} [NC]\n{}",
                rewrite_quoted(&paths),
                set(0)
            ));
        }
        out.push_str(&agent_exemption_clears(&config.agent_exemptions));
        if config.trust.is_some() {
            out.push_str(&format!(
                "    RewriteCond %{{ENV:{TRUSTED_VAR}}} =1\n{}",
                set(0)
            ));
        }
        out.push_str(&format!(
            "    RewriteCond %{{ENV:{BLOCK_VAR}}} =1\n    RewriteRule ^ - [R={},L]\n",
            status_code(config.response)
        ));
    }
    out.push_str(&format!("    {BLOCK_END}\n"));
    Some(out)
}

/// The rules that clear the flag for agent exemptions: per user agent,
/// one rule whose conditions are the user agent and then its paths, the
/// paths joined by `[OR]` — which `mod_rewrite` reads as "the user agent,
/// and any of these paths", the conjunction NGINX needs a variable for.
fn agent_exemption_clears(exemptions: &[crate::db::AgentExemption]) -> String {
    let mut out = String::new();
    for group in exemptions.chunk_by(|a, b| a.user_agent == b.user_agent) {
        let user_agent = &group[0].user_agent;
        if !is_stored_as_valid(user_agent, crate::db::validate_exemption_user_agent) {
            continue;
        }
        let paths: Vec<String> = group.iter().map(|e| e.path.clone()).collect();
        let paths = crate::nginx::exemption_regexes(&paths, &[]);
        if paths.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "    RewriteCond %{{HTTP_USER_AGENT}} {} [NC]\n",
            rewrite_quoted(&crate::db::escape_regex_literal(user_agent))
        ));
        for (i, regex) in paths.iter().enumerate() {
            let flags = if i + 1 < paths.len() { "NC,OR" } else { "NC" };
            out.push_str(&format!(
                "    RewriteCond %{{REQUEST_URI}} {} [{flags}]\n",
                rewrite_quoted(regex)
            ));
        }
        out.push_str(&format!("    RewriteRule ^ - [E={BLOCK_VAR}:0]\n"));
    }
    out
}

/// Narrows a site's config to what is safe in *this* virtual host: the
/// TLS-only request rules are dropped in one that does not terminate TLS,
/// for the reason `nginx::for_block` gives.
///
/// It also exempts the console's prefix, where Web Access mounted it in
/// this host: `mod_rewrite` runs before the proxy does, so every rule in
/// the block would otherwise reach the console's own requests — the
/// lock-out `nginx::console_prefix_in` describes.
fn for_host(config: &BlockConfig, content: &str, host: &VirtualHost) -> BlockConfig {
    let mut config = config.clone();
    if !host.is_tls {
        config.request_rules.retain(|rule| !rule.needs_tls());
    }
    if let Some(prefix) = console_prefix_in(content, host) {
        if !config.exempt_paths.contains(&prefix) {
            config.exempt_paths.push(prefix);
        }
    }
    config
}

/// The prefix of the console `<Location>` this tool wrote into `host`, if
/// it wrote one, read from the host itself and checked as an exempt path
/// is.
fn console_prefix_in(content: &str, host: &VirtualHost) -> Option<String> {
    let (start, end) = locate_marked(content, host, CONSOLE_BEGIN, CONSOLE_END)?;
    let prefix = lines(&content[start..end]).into_iter().find_map(|line| {
        let (name, closing, args) = section(&line.text)?;
        (name == "location" && !closing).then(|| args.into_iter().next())?
    })?;
    is_stored_as_valid(&prefix, crate::db::validate_exempt_path).then_some(prefix)
}

/// The byte range of the whole lines from the begin marker to the end
/// marker inside `host`, if a block is there. Only a line that is exactly
/// the marker counts.
fn locate_existing_block(content: &str, host: &VirtualHost) -> Option<(usize, usize)> {
    locate_marked(content, host, BLOCK_BEGIN, BLOCK_END)
}

/// The whole lines from a `begin` marker to the next `end` marker inside
/// `host`.
fn locate_marked(
    content: &str,
    host: &VirtualHost,
    begin: &str,
    end: &str,
) -> Option<(usize, usize)> {
    let inside: Vec<Line> = lines(content)
        .into_iter()
        .filter(|line| line.start >= host.open && line.start < host.close)
        .collect();
    let first = inside.iter().position(|l| l.text.trim() == begin)?;
    let last = inside[first..].iter().position(|l| l.text.trim() == end)?;
    Some((inside[first].start, inside[first + last].end))
}

/// Inserts, replaces or removes the block inside `host`. Idempotent.
fn apply_block(content: &str, host: &VirtualHost, config: &BlockConfig) -> String {
    let new_block = block_text(&for_host(config, content, host));
    let (start, end) = locate_existing_block(content, host).unwrap_or((host.open, host.open));
    let mut out = String::with_capacity(content.len() + new_block.as_ref().map_or(0, String::len));
    out.push_str(&content[..start]);
    if let Some(block) = &new_block {
        out.push_str(block);
    }
    out.push_str(&content[end..]);
    out
}

/// Host `i` of `hosts`, which must still number `expected` — the guard
/// `nginx::nth_block` is, for the same reason.
fn nth_host<'a>(
    hosts: &'a [VirtualHost],
    i: usize,
    expected: usize,
    config_path: &Path,
) -> Result<&'a VirtualHost> {
    if hosts.len() != expected {
        anyhow::bail!(
            "refusing to write {}: editing it changed how many <VirtualHost> sections it has",
            config_path.display()
        );
    }
    Ok(&hosts[i])
}

/// What applying `site_configs` (and `default_config` for every host
/// they do not name) to every `<VirtualHost>` in `content` makes of it.
pub fn blocks_for_file(
    content: &str,
    config_path: &Path,
    site_configs: &[(String, BlockConfig)],
    default_config: &BlockConfig,
) -> Result<String> {
    let mut content = content.to_string();
    let count = virtual_hosts(&content).len();
    for i in 0..count {
        let hosts = virtual_hosts(&content);
        let host = nth_host(&hosts, i, count, config_path)?;
        let config = site_configs
            .iter()
            .find(|(name, _)| *name == host.names[0])
            .map_or(default_config, |(_, config)| config);
        content = apply_block(&content, host, config);
    }
    Ok(content)
}

/// What applying `config` to only `server_name`'s hosts in `content`
/// makes of it.
pub fn block_for_site(
    content: &str,
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
) -> Result<String> {
    let mut content = content.to_string();
    let count = virtual_hosts(&content).len();
    for i in 0..count {
        let hosts = virtual_hosts(&content);
        let host = nth_host(&hosts, i, count, config_path)?;
        if host.names[0] == server_name {
            content = apply_block(&content, host, config);
        }
    }
    Ok(content)
}

/// The trust file's body for `trust`: one `SetEnvIf` per entry, read in
/// every virtual host because the main server's are merged into each.
///
/// `SetEnvIfExpr` with `-R` for addresses, because it is the one CIDR-aware
/// match `mod_setenvif` has. User agents match as an escaped,
/// case-insensitive substring, as they do everywhere else.
pub fn trusted_conf_body(trust: &Trust) -> String {
    let mut out = managed_header();
    for address in &trust.addresses {
        out.push_str(&format!(
            "SetEnvIfExpr \"-R '{address}'\" {TRUSTED_VAR}=1\n"
        ));
    }
    for user_agent in &trust.user_agents {
        out.push_str(&format!(
            "SetEnvIfNoCase User-Agent {} {TRUSTED_VAR}=1\n",
            conf_quoted(&crate::db::escape_regex_literal(user_agent))
        ));
    }
    out
}

/// Whether the trust file on disk is the one `config` expects; see
/// `nginx::trust_file_is_current`, which this is for Apache.
fn trust_file_is_current(config: &BlockConfig, on_disk: Option<&str>) -> bool {
    match (&config.trust, block_text(config)) {
        (Some(trust), Some(_)) => on_disk.is_some_and(|text| {
            crate::generated::same_but_for_the_version(text, &trusted_conf_body(trust))
        }),
        _ => true,
    }
}

/// Whether what is written for `server_name` in `config_path` is what
/// `config` renders to.
pub fn site_apply_status(
    config_path: &Path,
    server_name: &str,
    config: &BlockConfig,
    root: &Path,
) -> SiteApplyStatus {
    let Ok(content) = fs::read_to_string(config_path) else {
        return SiteApplyStatus::NotFound;
    };
    let hosts = virtual_hosts(&content);
    let matching: Vec<&VirtualHost> = hosts.iter().filter(|h| h.names[0] == server_name).collect();
    if matching.is_empty() {
        return SiteApplyStatus::NotFound;
    }
    let trust_on_disk = config
        .trust
        .as_ref()
        .and_then(|_| fs::read_to_string(trusted_conf_path(&conf_enabled_dir(root))).ok());
    let current = matching.iter().all(|host| {
        locate_existing_block(&content, host).map(|(start, end)| content[start..end].to_string())
            == block_text(&for_host(config, &content, host))
    });
    if current && trust_file_is_current(config, trust_on_disk.as_deref()) {
        SiteApplyStatus::UpToDate
    } else {
        SiteApplyStatus::Stale
    }
}

/// `content` with every block this project injected taken out: the exact
/// inverse of an insertion, which puts the block's lines right after the
/// `<VirtualHost>` line and adds nothing else.
pub fn without_injected_blocks(content: &str) -> String {
    let mut content = content.to_string();
    loop {
        // Both kinds are inserted right after the `<VirtualHost>` line, so
        // the one nearest it was inserted last and goes first.
        let found = virtual_hosts(&content).iter().find_map(|host| {
            [
                locate_existing_block(&content, host),
                locate_marked(&content, host, CONSOLE_BEGIN, CONSOLE_END),
            ]
            .into_iter()
            .flatten()
            .min()
        });
        let Some((start, end)) = found else {
            return content;
        };
        content.replace_range(start..end, "");
    }
}

/// The generated files the current settings call for: the trust file and
/// `robots.txt`.
pub fn planned_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut files = Vec::new();
    if db.get_serve_robots_txt()? {
        files.push((robots_txt_path(), robots_txt_body(db)?));
    }
    if let Some(trust) = Trust::of(db)? {
        files.push((
            trusted_conf_path(&conf_enabled_dir(root)),
            trusted_conf_body(&trust),
        ));
    }
    Ok(files)
}

/// Where each generated file the current settings do not call for would
/// be.
pub fn fallback_unused_managed_files(db: &crate::db::Db, root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    if !db.get_serve_robots_txt()? {
        paths.push(robots_txt_path());
    }
    if Trust::of(db)?.is_none() {
        paths.push(trusted_conf_path(&conf_enabled_dir(root)));
    }
    Ok(paths)
}

/// The directories a recorded generated file may be removed from.
pub fn managed_directories(root: &Path) -> Vec<PathBuf> {
    [conf_enabled_dir(root), managed_dir()]
        .iter()
        .filter_map(|dir| fs::canonicalize(dir).ok())
        .collect()
}

/// Every name on the host that declares `server_name`, or just that name.
pub fn server_names_for(config_path: &Path, server_name: &str) -> Vec<String> {
    fs::read_to_string(config_path)
        .ok()
        .and_then(|content| {
            virtual_hosts(&content)
                .into_iter()
                .find(|host| host.names.iter().any(|name| name == server_name))
        })
        .map_or_else(|| vec![server_name.to_string()], |host| host.names)
}

/// The application that answers for `server_name` in `config_path`, as
/// [`crate::services::recognise`] reads it, from every `<VirtualHost>`
/// there that declares one of the site's names — as `nginx::site_service`
/// does from `server` blocks, and for the same reasons.
///
/// `recognise` speaks NGINX's directive names, so Apache's are given the
/// name of the NGINX directive that does the same: `ProxyPass` hands
/// requests on as `proxy_pass` does, `DocumentRoot` is `root`, and `Alias`
/// is `alias`. Anything else keeps its own name, which still counts for
/// the one thing `recognise` reads from any directive: Nextcloud's
/// `/remote.php/dav` in a `Redirect` or a `RewriteRule`.
///
/// This project's own block is taken out first: it quotes upstream
/// user-agent patterns, which could name anything.
pub fn site_service(config_path: &Path, server_name: &str) -> Option<crate::services::Service> {
    let content = without_injected_blocks(&fs::read_to_string(config_path).ok()?);
    let hosts = virtual_hosts(&content);
    let names = hosts
        .iter()
        .find(|host| host.names.iter().any(|name| name == server_name))?
        .names
        .clone();
    let directives: Vec<(String, Vec<String>)> = hosts
        .iter()
        .filter(|host| host.names.iter().any(|name| names.contains(name)))
        .flat_map(|host| host.directives.iter())
        .map(|(name, arguments)| (nginx_equivalent(name).to_string(), arguments.clone()))
        .collect();
    crate::services::recognise(&directives)
}

/// The NGINX directive that does what Apache's `name` (lowercased) does,
/// as far as [`site_service`] needs: or `name` itself.
fn nginx_equivalent(name: &str) -> &str {
    match name {
        "proxypass" | "proxypassmatch" => "proxy_pass",
        "documentroot" => "root",
        "alias" | "aliasmatch" => "alias",
        name => name,
    }
}

/// Whether a host declaring `server_name` in `config_path` terminates TLS.
pub fn serves_tls(config_path: &Path, server_name: &str) -> bool {
    fs::read_to_string(config_path).is_ok_and(|content| {
        virtual_hosts(&content)
            .iter()
            .any(|host| host.is_tls && host.names.iter().any(|name| name == server_name))
    })
}

/// The directories `CustomLog` and `ErrorLog` write to under `root`, for
/// the helper's sandbox. `${APACHE_LOG_DIR}` is Debian's `envvars`
/// default, and a relative path is relative to the server root.
pub fn log_dirs(root: &Path) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/var/log/apache2")];
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(content) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for line in lines(&content) {
            let mut parts = words(line.text.trim());
            if parts.len() < 2 || line.text.trim_start().starts_with('#') {
                continue;
            }
            let name = parts.remove(0).to_ascii_lowercase();
            if name != "customlog" && name != "errorlog" {
                continue;
            }
            let target = parts[0].replace("${APACHE_LOG_DIR}", "/var/log/apache2");
            // A pipe or syslog is not a file.
            if target.starts_with('|') || target.starts_with("syslog") {
                continue;
            }
            let path = Path::new(&target);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                Path::new(DEFAULT_ROOT).join(path)
            };
            if let Some(dir) = path.parent() {
                if !dirs.iter().any(|d| d == dir) {
                    dirs.push(dir.to_path_buf());
                }
            }
        }
    }
    dirs
}

/// What fixes a config test that failed because a module this project
/// writes for is not loaded: `mod_rewrite` for the blocks, `mod_proxy`'s
/// HTTP half for Web Access. Debian ships both switched off.
pub fn missing_module_hint(err: &anyhow::Error) -> Option<&'static str> {
    let text = format!("{err:#}");
    let invalid = |command: &str| text.contains(&format!("Invalid command '{command}'"));
    if invalid("RewriteEngine") || invalid("RewriteCond") {
        return Some(
            "stop-bots blocks requests with mod_rewrite, which is not enabled: \
             run `a2enmod rewrite`, then apply again.",
        );
    }
    if invalid("ProxyPass") || invalid("ProxyPreserveHost") {
        return Some(
            "the console is reached through mod_proxy_http, which is not enabled: \
             run `a2enmod proxy_http`, then try again.",
        );
    }
    // Loaded `mod_proxy` without its HTTP half takes the config and then
    // cannot proxy; Apache says so only in its error log.
    None
}

// ---- reaching the console from outside ----

/// Where a subdomain-mode site goes: a file of its own in `sites-enabled`,
/// one thing to delete when an operator changes their mind.
///
/// **Named to sort last.** For a name no site declares — every request
/// that asks for a bare address — Apache answers with the first
/// `<VirtualHost>` it read for that address and port, and Debian reads
/// `sites-enabled` in name order. The console must never be that site.
pub fn console_site_path(root: &Path) -> PathBuf {
    root.join("sites-enabled").join("zz-stop-bots-console.conf")
}

/// The `<Location>` that proxies to the console, shared by both modes.
///
/// The prefix is kept on the way through, as NGINX's `proxy_pass` keeps
/// it, because the console generates links with it. `ProxyPreserveHost`
/// passes the `Host` the browser sent, which is what the console's own
/// host check reads; Apache's proxy appends the client to
/// `X-Forwarded-For` by itself. Both are quoted, though the prefix has
/// passed `BasePath::parse`, for the reason `nginx::console_location`
/// gives.
fn console_location(prefix: &str, upstream: &std::net::SocketAddr) -> String {
    format!(
        "    {CONSOLE_BEGIN}\n    <Location {}>\n        ProxyPass {}\n        \
         ProxyPreserveHost On\n    </Location>\n    {CONSOLE_END}\n",
        conf_quoted(prefix),
        conf_quoted(&format!("http://{upstream}{prefix}")),
    )
}

/// A whole `<VirtualHost>` serving the console on `host` at `/`.
pub fn console_server_block(host: &str, upstream: &std::net::SocketAddr) -> String {
    format!(
        "# {} (`Web Access` panel). Safe to edit or delete.\n\
         #\n\
         # Plain HTTP: the console's password and session cookie are in the clear\n\
         # until this host has a certificate for {host}. Get one with:\n\
         #\n\
         #     certbot --apache -d {host}\n\
         #\n\
         # then run `stop-bots set-web --secure-cookie true` so the cookie is\n\
         # HTTPS-only.\n\
         <VirtualHost *:80>\n    \
         ServerName {host}\n    \
         # The console shows what attackers sent, and its requests carry it:\n    \
         # logged where the detectors read, they would block its operator.\n    \
         CustomLog /dev/null common\n\n\
         {}</VirtualHost>\n",
        crate::generated::generated_by(),
        console_location("/", upstream)
    )
}

/// Inserts (or updates) the console's `<Location>` inside `server_name`'s
/// host in `content`, preferring the one that terminates TLS, as
/// `nginx::with_console_location` does. `None` when no host there declares
/// the name.
fn with_console_location(
    content: &str,
    server_name: &str,
    prefix: &str,
    upstream: &std::net::SocketAddr,
) -> Option<String> {
    let hosts = virtual_hosts(content);
    let host = hosts
        .iter()
        .filter(|h| h.names.iter().any(|n| n == server_name))
        .max_by_key(|h| h.is_tls)?;
    let (start, end) =
        locate_marked(content, host, CONSOLE_BEGIN, CONSOLE_END).unwrap_or((host.open, host.open));
    let mut out = String::with_capacity(content.len() + 256);
    out.push_str(&content[..start]);
    out.push_str(&console_location(prefix, upstream));
    out.push_str(&content[end..]);
    Some(out)
}

/// Sets the console up to be reachable through Apache, validated before
/// it can take effect and put back if the config test refuses it; see
/// `nginx::apply_console_access`, which this is for Apache.
pub fn apply_console_access(
    root: &Path,
    access: &ConsoleAccess,
    upstream: &std::net::SocketAddr,
    commands: &ServerCommands,
) -> Result<PathBuf> {
    validate_console_access(access)?;
    match access {
        ConsoleAccess::Subdomain { host } => {
            let path = console_site_path(root);
            write_validated(
                WebServer::Apache,
                &path,
                &console_server_block(host, upstream),
                commands,
                write_managed,
            )?;
            Ok(path)
        }
        ConsoleAccess::Path {
            prefix,
            config_path,
            server_name,
        } => {
            let content = fs::read_to_string(config_path).map_err(|err| {
                anyhow::anyhow!("failed to read {}: {err}", config_path.display())
            })?;
            let updated = with_console_location(&content, server_name, prefix, upstream)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{} has no <VirtualHost> for {server_name} — re-scan sites and try again",
                        config_path.display()
                    )
                })?;
            write_validated(
                WebServer::Apache,
                config_path,
                &updated,
                commands,
                |path, text| write_site_file(path, root, text),
            )?;
            Ok(config_path.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::BlockResponse;
    use crate::services::Service;

    const SITE: &str = "\
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example
</VirtualHost>
";

    const TWO_HOSTS: &str = "\
<VirtualHost *:80>
    ServerName example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<IfModule mod_ssl.c>
<VirtualHost *:443>
    ServerName example.com
    SSLEngine on
    <Directory /var/www/example>
        AllowOverride All
    </Directory>
</VirtualHost>
</IfModule>

<VirtualHost *:80>
    ServerName other.example
</VirtualHost>
";

    fn cfg(patterns: &[&str]) -> BlockConfig {
        BlockConfig::new(
            patterns.iter().map(|p| p.to_string()).collect(),
            BlockResponse::Forbidden,
        )
    }

    #[test]
    fn finds_every_virtual_host_with_its_names_and_tls() {
        let hosts = virtual_hosts(TWO_HOSTS);
        let seen: Vec<(Vec<String>, bool)> =
            hosts.iter().map(|h| (h.names.clone(), h.is_tls)).collect();
        assert_eq!(
            seen,
            vec![
                (vec!["example.com".to_string()], false),
                (vec!["example.com".to_string()], true),
                (vec!["other.example".to_string()], false),
            ]
        );
        assert_eq!(
            virtual_hosts(SITE)[0].names,
            vec!["example.com", "www.example.com"]
        );
    }

    #[test]
    fn a_host_without_a_server_name_is_the_catch_all() {
        let hosts =
            virtual_hosts("<VirtualHost *:80>\n    DocumentRoot /var/www/html\n</VirtualHost>\n");
        assert_eq!(hosts[0].names, vec!["_"]);
    }

    #[test]
    fn a_server_name_loses_its_scheme_and_port() {
        for (written, stored) in [
            ("example.com", "example.com"),
            ("example.com:443", "example.com"),
            ("https://example.com:8443", "example.com"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            assert_eq!(bare_name(written), stored, "from {written:?}");
        }
    }

    #[test]
    fn commented_sections_are_not_structure() {
        let content =
            "# <VirtualHost *:80>\n#   ServerName ghost\n# </VirtualHost>\n".to_string() + SITE;
        let hosts = virtual_hosts(&content);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].names[0], "example.com");
    }

    #[test]
    fn a_continued_line_is_one_directive() {
        let content =
            "<VirtualHost *:80>\n    ServerName \\\n        joined.example\n</VirtualHost>\n";
        assert_eq!(virtual_hosts(content)[0].names[0], "joined.example");
    }

    #[test]
    fn a_block_matches_the_golden() {
        let config = BlockConfig {
            exempt_paths: vec!["/api/".to_string()],
            ..cfg(&["BadBot", "Evil\"Quote"])
        };
        crate::golden::assert_golden("apache-block-simple.conf", &block_text(&config).unwrap());
    }

    #[test]
    fn a_full_block_matches_the_golden() {
        let config = BlockConfig {
            serve_robots_txt: true,
            request_rules: vec![RequestRule::NoAccept, RequestRule::IpLiteralHost],
            agent_exemptions: vec![crate::db::AgentExemption {
                path: "/remote.php/dav/".to_string(),
                user_agent: "okhttp".to_string(),
            }],
            trust: Trust::from_lists(&["203.0.113.7".to_string()], &[]),
            response: BlockResponse::Gone,
            ..cfg(&["BadBot"])
        };
        // The robots.txt alias names the managed directory, which a test
        // environment may move; pin the stock one.
        let text = block_text(&config)
            .unwrap()
            .replace(&managed_dir().display().to_string(), MANAGED_DIR);
        crate::golden::assert_golden("apache-block-full.conf", &text);
    }

    #[test]
    fn the_trust_file_matches_the_golden() {
        let trust = Trust::from_lists(
            &["203.0.113.7".to_string(), "2001:db8::/48".to_string()],
            &["UptimeRobot".to_string(), "Pingdom.com_bot".to_string()],
        )
        .unwrap();
        let body = trusted_conf_body(&trust);
        let ours = format!("# {}.", crate::generated::generated_by());
        crate::golden::assert_golden(
            "apache-trusted.conf",
            &body.replacen(&ours, "# Generated by stop-bots.", 1),
        );
    }

    #[test]
    fn applying_inserts_after_the_opening_line_and_is_idempotent() {
        let once = blocks_for_file(SITE, Path::new("site.conf"), &[], &cfg(&["BadBot"])).unwrap();
        let twice = blocks_for_file(&once, Path::new("site.conf"), &[], &cfg(&["BadBot"])).unwrap();
        assert_eq!(once, twice);
        assert!(
            once.starts_with(&format!("<VirtualHost *:80>\n    {BLOCK_BEGIN}\n")),
            "applied:\n{once}"
        );
    }

    #[test]
    fn nothing_to_block_takes_the_block_out_byte_for_byte() {
        let applied = blocks_for_file(SITE, Path::new("s"), &[], &cfg(&["BadBot"])).unwrap();
        let removed = blocks_for_file(&applied, Path::new("s"), &[], &cfg(&[])).unwrap();
        assert_eq!(removed, SITE);
        assert_eq!(without_injected_blocks(&applied), SITE);
    }

    #[test]
    fn each_site_gets_its_own_config_and_tls_rules_only_where_tls_is() {
        let strict = BlockConfig {
            request_rules: vec![RequestRule::Http1x],
            ..cfg(&["BadBot"])
        };
        let applied = blocks_for_file(
            TWO_HOSTS,
            Path::new("s"),
            &[("example.com".to_string(), strict)],
            &cfg(&[]),
        )
        .unwrap();
        let hosts = virtual_hosts(&applied);
        let block = |i: usize| {
            locate_existing_block(&applied, &hosts[i]).map(|(s, e)| applied[s..e].to_string())
        };
        assert!(!block(0).unwrap().contains("SERVER_PROTOCOL"), "{applied}");
        assert!(block(1).unwrap().contains("SERVER_PROTOCOL"), "{applied}");
        assert_eq!(block(2), None, "{applied}");
    }

    #[test]
    fn applying_to_one_site_leaves_the_others_alone() {
        let applied = block_for_site(
            TWO_HOSTS,
            Path::new("s"),
            "other.example",
            &cfg(&["BadBot"]),
        )
        .unwrap();
        let hosts = virtual_hosts(&applied);
        assert!(locate_existing_block(&applied, &hosts[0]).is_none());
        assert!(locate_existing_block(&applied, &hosts[2]).is_some());
    }

    #[test]
    fn a_quote_in_a_pattern_cannot_end_the_argument() {
        for (regex, written) in [
            (r#"a"b"#, r#""(?:a\x22b)""#),
            (r#"a\"b"#, r#""(?:a\x22b)""#),
            (r"a\\b", r#""(?:a\\b)""#),
            (r"-f", r#""(?:-f)""#),
            (r"!x", r#""(?:!x)""#),
        ] {
            assert_eq!(rewrite_quoted(regex), written, "for {regex:?}");
        }
    }

    #[test]
    fn a_pattern_apache_would_substitute_into_is_never_written() {
        let text = block_text(&cfg(&["Good", "x${jndi}"])).unwrap();
        assert!(!text.contains("${"), "block was:\n{text}");
        assert!(text.contains("Good"), "block was:\n{text}");
    }

    #[test]
    fn what_apache_cannot_send_answers_403() {
        for response in [
            BlockResponse::Close,
            BlockResponse::Tarpit,
            BlockResponse::Teapot,
        ] {
            let text = block_text(&BlockConfig {
                response,
                ..cfg(&["BadBot"])
            })
            .unwrap();
            assert!(text.contains("[R=403,L]"), "{response:?} gave:\n{text}");
        }
    }

    #[test]
    fn rate_limiting_alone_writes_no_block() {
        let config = BlockConfig {
            rate_limit_burst: Some(20),
            ..cfg(&[])
        };
        assert_eq!(block_text(&config), None);
    }

    #[test]
    fn a_site_reads_up_to_date_only_once_applied() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, SITE).unwrap();
        let config = cfg(&["BadBot"]);
        assert_eq!(
            site_apply_status(&path, "example.com", &config, dir.path()),
            SiteApplyStatus::Stale
        );
        fs::write(&path, blocks_for_file(SITE, &path, &[], &config).unwrap()).unwrap();
        assert_eq!(
            site_apply_status(&path, "example.com", &config, dir.path()),
            SiteApplyStatus::UpToDate
        );
        assert_eq!(
            site_apply_status(&path, "nobody.example", &config, dir.path()),
            SiteApplyStatus::NotFound
        );
    }

    #[test]
    fn discovery_skips_links_and_finds_each_host() {
        let dir = tempfile::tempdir().unwrap();
        let available = dir.path().join("sites-available");
        let enabled = dir.path().join("sites-enabled");
        fs::create_dir_all(&available).unwrap();
        fs::create_dir_all(&enabled).unwrap();
        fs::write(available.join("two.conf"), TWO_HOSTS).unwrap();
        std::os::unix::fs::symlink(available.join("two.conf"), enabled.join("two.conf")).unwrap();
        let sites = discover_sites(dir.path()).unwrap();
        let names: Vec<&str> = sites.iter().map(|s| s.server_name.as_str()).collect();
        assert_eq!(names, vec!["example.com", "example.com", "other.example"]);
        assert!(sites.iter().all(|s| s.config_path.starts_with(&available)));
        assert!(discover_sites(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn recognises_the_application_behind_a_site() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let cases = [
            (
                "ProxyPass / http://127.0.0.1:8096/",
                Some(Service::Jellyfin),
            ),
            (
                "ProxyPassMatch ^/(.*)$ http://immich_server:2283/$1",
                Some(Service::Immich),
            ),
            ("DocumentRoot /var/www/nextcloud", Some(Service::Nextcloud)),
            (
                "Alias /cloud \"/var/www/nextcloud/\"",
                Some(Service::Nextcloud),
            ),
            (
                "Redirect 301 /.well-known/carddav /remote.php/dav",
                Some(Service::Nextcloud),
            ),
            ("DocumentRoot /var/www/blog", None),
            // A name outside anything that hands requests on.
            ("ServerAdmin jellyfin@example.com", None),
        ];
        for (directive, expected) in cases {
            fs::write(
                &path,
                format!("<VirtualHost *:443>\n    ServerName cloud.example\n    {directive}\n</VirtualHost>\n"),
            )
            .unwrap();
            assert_eq!(
                site_service(&path, "cloud.example"),
                expected,
                "{directive}"
            );
        }
    }

    /// The HTTPS host passes requests on; the port-80 one only redirects.
    /// Both are the site.
    #[test]
    fn every_host_of_a_site_counts_and_our_own_block_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        let content = "<VirtualHost *:80>\n    ServerName cloud.example\n    Redirect / https://cloud.example/\n</VirtualHost>\n<VirtualHost *:443>\n    ServerName cloud.example\n    ProxyPass / http://navidrome:4533/\n</VirtualHost>\n";
        fs::write(&path, content).unwrap();
        assert_eq!(
            site_service(&path, "cloud.example"),
            Some(Service::Navidrome)
        );

        // A blocked bot whose pattern names an application says nothing.
        let plain = "<VirtualHost *:80>\n    ServerName blog.example\n</VirtualHost>\n";
        let blocked = blocks_for_file(plain, &path, &[], &cfg(&["nextcloud-crawler"])).unwrap();
        assert!(blocked.contains("nextcloud-crawler"), "applied:\n{blocked}");
        fs::write(&path, blocked).unwrap();
        assert_eq!(site_service(&path, "blog.example"), None);
    }

    // ---- Web Access ----

    fn upstream() -> std::net::SocketAddr {
        "127.0.0.1:8787".parse().unwrap()
    }

    fn commands_that(pass: bool) -> ServerCommands {
        let program = if pass { "true" } else { "false" };
        ServerCommands {
            test: vec![program.to_string()],
            reload: vec!["true".to_string()],
        }
    }

    #[test]
    fn the_console_sections_match_the_goldens() {
        let ours = format!("# {}", crate::generated::generated_by());
        crate::golden::assert_golden(
            "apache-console-subdomain.conf",
            &console_server_block("console.example.com", &upstream()).replacen(
                &ours,
                "# Generated by stop-bots",
                1,
            ),
        );
        crate::golden::assert_golden(
            "apache-console-location.conf",
            &console_location("/stop-bots/", &upstream()),
        );
    }

    #[test]
    fn the_console_goes_into_the_tls_host_once() {
        let once =
            with_console_location(TWO_HOSTS, "example.com", "/stop-bots/", &upstream()).unwrap();
        let twice =
            with_console_location(&once, "example.com", "/stop-bots/", &upstream()).unwrap();
        assert_eq!(once, twice);
        let hosts = virtual_hosts(&once);
        assert!(locate_marked(&once, &hosts[0], CONSOLE_BEGIN, CONSOLE_END).is_none());
        assert!(locate_marked(&once, &hosts[1], CONSOLE_BEGIN, CONSOLE_END).is_some());
        assert_eq!(
            with_console_location(TWO_HOSTS, "nobody.example", "/x/", &upstream()),
            None
        );
    }

    /// Every rule in the block runs before the proxy, so the console's
    /// prefix is exempt wherever the console is mounted — or an operator
    /// whose browser trips a rule is locked out of the console.
    #[test]
    fn the_console_prefix_is_exempt_from_the_block() {
        let mounted =
            with_console_location(SITE, "example.com", "/stop-bots/", &upstream()).unwrap();
        let applied = blocks_for_file(&mounted, Path::new("s"), &[], &cfg(&["BadBot"])).unwrap();
        assert!(
            applied.contains(r#"%{REQUEST_URI} "(?:^(/stop-bots/))" [NC]"#),
            "applied:\n{applied}"
        );
        // And the exemption reads as up to date once applied.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, &applied).unwrap();
        assert_eq!(
            site_apply_status(&path, "example.com", &cfg(&["BadBot"]), dir.path()),
            SiteApplyStatus::UpToDate
        );
    }

    #[test]
    fn uninstalling_takes_the_console_out_too() {
        let mounted =
            with_console_location(SITE, "example.com", "/stop-bots/", &upstream()).unwrap();
        let applied = blocks_for_file(&mounted, Path::new("s"), &[], &cfg(&["BadBot"])).unwrap();
        assert_eq!(without_injected_blocks(&applied), SITE);
    }

    #[test]
    fn a_console_the_config_test_refuses_is_put_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("site.conf");
        fs::write(&path, SITE).unwrap();
        let access = ConsoleAccess::Path {
            prefix: "/stop-bots/".to_string(),
            config_path: path.clone(),
            server_name: "example.com".to_string(),
        };
        let err = apply_console_access(dir.path(), &access, &upstream(), &commands_that(false))
            .unwrap_err();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            SITE,
            "error was: {err:#}"
        );

        apply_console_access(dir.path(), &access, &upstream(), &commands_that(true)).unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("ProxyPass"));

        let subdomain = ConsoleAccess::Subdomain {
            host: "console.example.com".to_string(),
        };
        let written =
            apply_console_access(dir.path(), &subdomain, &upstream(), &commands_that(true))
                .unwrap();
        assert_eq!(written, console_site_path(dir.path()));
        assert!(crate::webserver::is_console_site_file(&written));
    }

    #[test]
    fn a_missing_module_names_the_command_that_enables_it() {
        for (said, fix) in [
            (
                "Invalid command 'RewriteEngine', perhaps misspelled",
                "a2enmod rewrite",
            ),
            (
                "Invalid command 'ProxyPass', perhaps misspelled",
                "a2enmod proxy_http",
            ),
        ] {
            let hint = missing_module_hint(&anyhow::anyhow!("{said}")).unwrap();
            assert!(hint.contains(fix), "{said} gave: {hint}");
        }
        assert_eq!(missing_module_hint(&anyhow::anyhow!("Syntax error")), None);
    }

    #[test]
    fn log_directories_come_from_the_config() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("site.conf"),
            "<VirtualHost *:80>\n    CustomLog /srv/logs/example/access.log combined\n    ErrorLog ${APACHE_LOG_DIR}/error.log\n    CustomLog \"|/usr/bin/rotatelogs x\" common\n</VirtualHost>\n",
        )
        .unwrap();
        assert_eq!(
            log_dirs(dir.path()),
            vec![
                PathBuf::from("/var/log/apache2"),
                PathBuf::from("/srv/logs/example")
            ]
        );
    }
}
