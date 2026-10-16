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

//! Reading a robots.txt: which paths it disallows to which client.
//!
//! What the robots.txt-violator detector judges a request by (see
//! `protection::robots_rules` for which robots.txt that is). The rules are
//! RFC 9309's, as the large crawlers read them:
//!
//! - **Groups.** One or more `User-agent:` lines, then the rules that
//!   apply to them. A client is ruled by every group naming a token its
//!   user agent contains, ignoring case; only when none does, by the `*`
//!   groups. A crawler named in a group of its own does not also obey `*`.
//! - **Rules.** `Allow:` and `Disallow:`, each a path prefix, where `*`
//!   matches anything and a final `$` anchors the end. The longest pattern
//!   that matches decides, and `Allow` wins a tie. An empty `Disallow:`
//!   disallows nothing.
//! - **`/robots.txt` itself** is always allowed.
//!
//! The path judged is the one logged, without its query, so a rule about
//! a query string never matches: that errs towards not blocking.

/// A parsed robots.txt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Robots {
    groups: Vec<Group>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Group {
    /// Lowercased.
    agents: Vec<String>,
    rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Rule {
    allow: bool,
    pattern: String,
}

impl Robots {
    /// Parses `text`. Never fails: a line it cannot read is skipped, as a
    /// crawler skips it.
    pub fn parse(text: &str) -> Robots {
        let mut groups: Vec<Group> = Vec::new();
        // Whether the group being read has had a rule yet: a `User-agent:`
        // after a rule starts the next group, one before it joins this one.
        let mut ruled = true;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default();
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "user-agent" => {
                    if ruled {
                        groups.push(Group::default());
                        ruled = false;
                    }
                    if let Some(group) = groups.last_mut() {
                        group.agents.push(value.to_lowercase());
                    }
                }
                key @ ("allow" | "disallow") => {
                    ruled = true;
                    let Some(group) = groups.last_mut() else {
                        continue;
                    };
                    if !value.is_empty() {
                        group.rules.push(Rule {
                            allow: key == "allow",
                            pattern: value.to_string(),
                        });
                    }
                }
                _ => {}
            }
        }
        Robots { groups }
    }

    /// The `Disallow:` pattern that forbids `path` to a client sending
    /// `user_agent`, or `None` if it may fetch it.
    pub fn disallows(&self, user_agent: &str, path: &str) -> Option<&str> {
        if path.eq_ignore_ascii_case("/robots.txt") {
            return None;
        }
        let user_agent = user_agent.to_lowercase();
        let named = |group: &&Group| {
            group
                .agents
                .iter()
                .any(|agent| agent != "*" && !agent.is_empty() && user_agent.contains(agent))
        };
        let mut groups: Vec<&Group> = self.groups.iter().filter(named).collect();
        if groups.is_empty() {
            groups = self
                .groups
                .iter()
                .filter(|group| group.agents.iter().any(|agent| agent == "*"))
                .collect();
        }
        let decisive = groups
            .iter()
            .flat_map(|group| &group.rules)
            .filter(|rule| matches(&rule.pattern, path))
            .max_by_key(|rule| (rule.pattern.len(), rule.allow))?;
        (!decisive.allow).then_some(decisive.pattern.as_str())
    }
}

/// Whether `pattern` matches `path` from its start: `*` is any run of
/// characters, and a final `$` means the path ends there.
fn matches(pattern: &str, path: &str) -> bool {
    let (pattern, anchored) = match pattern.strip_suffix('$') {
        Some(pattern) => (pattern, true),
        None => (pattern, false),
    };
    let mut pieces = pattern.split('*');
    let first = pieces.next().unwrap_or_default();
    let Some(mut rest) = path.strip_prefix(first) else {
        return false;
    };
    let pieces: Vec<&str> = pieces.collect();
    for (i, piece) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        if last && anchored {
            return rest.ends_with(piece);
        }
        match rest.find(piece) {
            Some(at) => rest = &rest[at + piece.len()..],
            None => return false,
        }
    }
    !anchored || rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROBOTS: &str = "\
# Generated by stop-bots. Edits will be overwritten.

User-agent: GPTBot
User-agent: CCBot
Disallow: /

User-agent: *
Disallow: /private/
Allow: /private/press/
Disallow: /*.pdf$
Disallow: /search*q=
Disallow:

User-agent: *
Disallow: /stop-bots-trap/
";

    #[test]
    fn a_path_is_disallowed_by_the_longest_rule_that_matches_it() {
        let robots = Robots::parse(ROBOTS);
        let browser = "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0";
        let cases = [
            ("the root", browser, "/", None),
            (
                "a disallowed directory",
                browser,
                "/private/a",
                Some("/private/"),
            ),
            (
                "an allowed one inside it",
                browser,
                "/private/press/x",
                None,
            ),
            (
                "a wildcard with an anchor",
                browser,
                "/files/a.pdf",
                Some("/*.pdf$"),
            ),
            ("past the anchor", browser, "/files/a.pdf.html", None),
            (
                "the second * group",
                browser,
                "/stop-bots-trap/x",
                Some("/stop-bots-trap/"),
            ),
            (
                "a group of its own",
                "Mozilla/5.0 (compatible; GPTBot/1.2)",
                "/",
                Some("/"),
            ),
            ("its second token", "CCBot/2.0", "/blog", Some("/")),
            ("robots.txt itself", "GPTBot", "/robots.txt", None),
            ("case is not a disguise", "gptbot", "/a", Some("/")),
        ];
        for (what, agent, path, expected) in cases {
            assert_eq!(robots.disallows(agent, path), expected, "{what}: {path}");
        }
    }

    /// RFC 9309: a crawler with a group of its own obeys that group, and
    /// not the `*` one as well.
    #[test]
    fn a_named_crawler_does_not_also_obey_the_star_group() {
        let robots = Robots::parse("User-agent: Bingbot\nAllow: /\n\nUser-agent: *\nDisallow: /\n");
        assert_eq!(robots.disallows("bingbot/2.0", "/a"), None);
        assert_eq!(robots.disallows("Firefox", "/a"), Some("/"));
    }

    #[test]
    fn a_robots_txt_with_no_rules_disallows_nothing() {
        for text in [
            "",
            "User-agent: *\nDisallow:\n",
            "Sitemap: /s.xml\nnonsense\n",
        ] {
            assert_eq!(
                Robots::parse(text).disallows("Firefox", "/a"),
                None,
                "{text:?}"
            );
        }
    }

    /// A rule before any `User-agent:` belongs to no group, and rules no
    /// one.
    #[test]
    fn a_rule_outside_any_group_is_ignored() {
        let robots = Robots::parse("Disallow: /\nUser-agent: *\nDisallow: /x/\n");
        assert_eq!(robots.disallows("Firefox", "/a"), None);
        assert_eq!(robots.disallows("Firefox", "/x/a"), Some("/x/"));
    }
}
