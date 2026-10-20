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

//! Matching a user agent against a bot list's pattern the way the web
//! server does: as a case-insensitive regular expression, NGINX's `~*` and
//! Apache's `RewriteCond … [NC]`.
//!
//! The screens that say whether a user agent is blocked used to compare
//! patterns as substrings, split on `|`. The web server reads the same
//! pattern as a regex, so the two disagreed: `AdsBot-Google([^-]|$)`,
//! `[cC]laude(?:[bB]ot|-[Ww]eb)` and `Brightbot 1.0` meant one thing to
//! the firewall and another to the tag beside the row.
//!
//! **Not a regex engine.** The `regex` crate would add about 1.5 MB to a
//! static binary (see `crate::injection` for the same decision). This reads
//! what the bot lists actually publish, measured over all 1,811 patterns of
//! the four built-in lists: literals and escapes (`\/`, `\.`, `\ `, `\d`,
//! `\s`, `\w`), `.`, `^`, `$`, alternation, capturing and `(?:…)` groups,
//! classes with ranges and negation, and the quantifiers `?`, `*`, `+` and
//! `{m,n}`. Anything else (a lookaround, a backreference, an inline flag)
//! makes [`UaPattern::compile`] give up, and the caller falls back to the
//! substring comparison rather than guess.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// A compiled pattern: its top-level alternatives, each with the text it
/// was written as, so that a caller can say which one matched.
#[derive(Debug)]
pub struct UaPattern {
    alternatives: Vec<Alternative>,
}

#[derive(Debug)]
struct Alternative {
    /// As written in the pattern.
    source: String,
    nodes: Vec<Node>,
    /// Text every match contains, lowercased: the longest run of plain
    /// characters outside any group or repetition. Most patterns are a
    /// name and nothing else, and a substring test settles those without
    /// the matcher.
    required: String,
}

/// A user agent, prepared once to be matched against many patterns.
pub struct Subject {
    chars: Vec<char>,
    lower: String,
}

impl Subject {
    pub fn new(text: &str) -> Subject {
        Subject {
            chars: text.chars().collect(),
            lower: text.to_lowercase(),
        }
    }
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Any,
    Class(Class),
    Start,
    End,
    Group(Vec<Vec<Node>>),
    Repeat(Box<Node>, u32, Option<u32>),
}

#[derive(Debug, Clone)]
struct Class {
    negated: bool,
    items: Vec<ClassItem>,
}

#[derive(Debug, Clone)]
enum ClassItem {
    Range(char, char),
    Digit(bool),
    Space(bool),
    Word(bool),
}

impl UaPattern {
    /// `pattern` compiled, or `None` when it uses something this does not
    /// read.
    pub fn compile(pattern: &str) -> Option<UaPattern> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut parser = Parser { chars, at: 0 };
        let mut alternatives = Vec::new();
        loop {
            let start = parser.at;
            let nodes = parser.sequence()?;
            let source: String = parser.chars[start..parser.at].iter().collect();
            let required = required(&nodes);
            alternatives.push(Alternative {
                source,
                nodes,
                required,
            });
            match parser.peek() {
                Some('|') => parser.at += 1,
                None => break,
                Some(_) => return None,
            }
        }
        Some(UaPattern { alternatives })
    }

    /// Which top-level alternative `text` matches, as written in the
    /// pattern, if any. Unanchored, like the web server's match.
    pub fn matching_alternative(&self, subject: &Subject) -> Option<&str> {
        let text = &subject.chars;
        self.alternatives
            .iter()
            .find(|alternative| {
                subject.lower.contains(&alternative.required)
                    && (0..=text.len())
                        .any(|at| matches(&alternative.nodes, 0, text, at, &|_| true))
            })
            .map(|alternative| alternative.source.as_str())
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.matching_alternative(&Subject::new(text)).is_some()
    }
}

/// See [`Alternative::required`].
fn required(nodes: &[Node]) -> String {
    let mut longest = String::new();
    let mut run = String::new();
    for node in nodes {
        match node {
            Node::Char(c) => run.extend(c.to_lowercase()),
            _ => {
                if run.chars().count() > longest.chars().count() {
                    longest = std::mem::take(&mut run);
                }
                run.clear();
            }
        }
    }
    if run.chars().count() > longest.chars().count() {
        longest = run;
    }
    longest
}

/// [`UaPattern::compile`], remembered: a screen asks about every bot's
/// pattern for every user agent it shows, and the patterns rarely change.
pub fn compiled(pattern: &str) -> Option<Arc<UaPattern>> {
    /// Cleared when it grows past this, so that patterns that changed do
    /// not pile up in a TUI left running for weeks.
    const MAX: usize = 20_000;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<UaPattern>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(found) = cache.get(pattern) {
        return found.clone();
    }
    if cache.len() >= MAX {
        cache.clear();
    }
    let found = UaPattern::compile(pattern).map(Arc::new);
    cache.insert(pattern.to_string(), found.clone());
    found
}

struct Parser {
    chars: Vec<char>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        Some(c)
    }

    /// Atoms up to a `|`, a `)` or the end.
    fn sequence(&mut self) -> Option<Vec<Node>> {
        let mut nodes = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            nodes.push(self.quantified(atom)?);
        }
        Some(nodes)
    }

    fn atom(&mut self) -> Option<Node> {
        Some(match self.next()? {
            '(' => {
                if self.peek() == Some('?') {
                    self.at += 1;
                    if self.next()? != ':' {
                        return None;
                    }
                }
                let mut alternatives = vec![self.sequence()?];
                while self.peek() == Some('|') {
                    self.at += 1;
                    alternatives.push(self.sequence()?);
                }
                if self.next()? != ')' {
                    return None;
                }
                Node::Group(alternatives)
            }
            '[' => Node::Class(self.class()?),
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '\\' => match self.escape()? {
                Escaped::Char(c) => Node::Char(c),
                Escaped::Class(item) => Node::Class(Class {
                    negated: false,
                    items: vec![item],
                }),
            },
            '*' | '+' | '?' | '{' => return None,
            c => Node::Char(c),
        })
    }

    fn quantified(&mut self, atom: Node) -> Option<Node> {
        let (min, max) = match self.peek() {
            Some('?') => (0, Some(1)),
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('{') => return self.braces(atom),
            _ => return Some(atom),
        };
        self.at += 1;
        self.lazy_or_possessive()?;
        Some(Node::Repeat(Box::new(atom), min, max))
    }

    /// `{n}`, `{n,}` or `{n,m}`. A `{` that starts none of them is
    /// PCRE's literal brace, which no list relies on: given up.
    fn braces(&mut self, atom: Node) -> Option<Node> {
        self.at += 1;
        let number = |parser: &mut Parser| -> Option<u32> {
            let start = parser.at;
            while parser.peek().is_some_and(|c| c.is_ascii_digit()) {
                parser.at += 1;
            }
            let digits: String = parser.chars[start..parser.at].iter().collect();
            digits.parse().ok()
        };
        let min = number(self)?;
        let max = match self.next()? {
            '}' => Some(min),
            ',' if self.peek() == Some('}') => {
                self.at += 1;
                None
            }
            ',' => {
                let max = number(self)?;
                (self.next()? == '}').then_some(())?;
                Some(max)
            }
            _ => return None,
        };
        if max.is_some_and(|max| max < min) {
            return None;
        }
        self.lazy_or_possessive()?;
        Some(Node::Repeat(Box::new(atom), min, max))
    }

    /// A lazy `?` after a quantifier changes nothing about whether a
    /// match exists. A possessive `+` can, and is given up.
    fn lazy_or_possessive(&mut self) -> Option<()> {
        match self.peek() {
            Some('?') => self.at += 1,
            Some('+') => return None,
            _ => {}
        }
        Some(())
    }

    fn escape(&mut self) -> Option<Escaped> {
        let c = self.next()?;
        Some(match c {
            'd' => Escaped::Class(ClassItem::Digit(true)),
            'D' => Escaped::Class(ClassItem::Digit(false)),
            's' => Escaped::Class(ClassItem::Space(true)),
            'S' => Escaped::Class(ClassItem::Space(false)),
            'w' => Escaped::Class(ClassItem::Word(true)),
            'W' => Escaped::Class(ClassItem::Word(false)),
            't' => Escaped::Char('\t'),
            'n' => Escaped::Char('\n'),
            'r' => Escaped::Char('\r'),
            // A backreference, a word boundary, an anchor or a code point
            // escape: none is in any list, and each means something.
            c if c.is_ascii_alphanumeric() => return None,
            c => Escaped::Char(c),
        })
    }

    fn class(&mut self) -> Option<Class> {
        let negated = self.peek() == Some('^');
        if negated {
            self.at += 1;
        }
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = self.next()?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let low = match c {
                '\\' => match self.escape()? {
                    Escaped::Char(c) => c,
                    Escaped::Class(item) => {
                        items.push(item);
                        continue;
                    }
                },
                '[' if self.peek() == Some(':') => return None,
                c => c,
            };
            let range = self.peek() == Some('-') && self.chars.get(self.at + 1) != Some(&']');
            if range {
                self.at += 1;
                let high = match self.next()? {
                    '\\' => match self.escape()? {
                        Escaped::Char(c) => c,
                        Escaped::Class(_) => return None,
                    },
                    c => c,
                };
                if high < low {
                    return None;
                }
                items.push(ClassItem::Range(low, high));
            } else {
                items.push(ClassItem::Range(low, low));
            }
        }
        Some(Class { negated, items })
    }
}

enum Escaped {
    Char(char),
    Class(ClassItem),
}

/// Whether `nodes[i..]` match `text` from `at` on, and `then` accepts
/// where they end. Backtracking, which the patterns lists publish are far
/// too small to make slow.
fn matches(
    nodes: &[Node],
    i: usize,
    text: &[char],
    at: usize,
    then: &dyn Fn(usize) -> bool,
) -> bool {
    let Some(node) = nodes.get(i) else {
        return then(at);
    };
    let rest = |end: usize| matches(nodes, i + 1, text, end, then);
    match node {
        Node::Char(c) => text.get(at).is_some_and(|t| same_letter(*t, *c)) && rest(at + 1),
        Node::Any => at < text.len() && text[at] != '\n' && rest(at + 1),
        Node::Class(class) => text.get(at).is_some_and(|t| class.contains(*t)) && rest(at + 1),
        Node::Start => at == 0 && rest(at),
        Node::End => at == text.len() && rest(at),
        Node::Group(alternatives) => alternatives
            .iter()
            .any(|alternative| matches(alternative, 0, text, at, &rest)),
        Node::Repeat(inner, min, max) => repeat(inner, *min, *max, 0, text, at, &rest),
    }
}

/// `inner` repeated, greedily: as many times as it goes, then fewer.
fn repeat(
    inner: &Node,
    min: u32,
    max: Option<u32>,
    count: u32,
    text: &[char],
    at: usize,
    then: &dyn Fn(usize) -> bool,
) -> bool {
    let more = max.is_none_or(|max| count < max)
        && matches(std::slice::from_ref(inner), 0, text, at, &|end| {
            // A repetition that consumed nothing would go round forever.
            (end != at || count < min) && repeat(inner, min, max, count + 1, text, end, then)
        });
    more || (count >= min && then(at))
}

/// Case-insensitive, as `~*` and `[NC]` are.
fn same_letter(a: char, b: char) -> bool {
    a == b || a.to_lowercase().eq(b.to_lowercase())
}

impl Class {
    fn contains(&self, c: char) -> bool {
        let lower = c.to_lowercase().next().unwrap_or(c);
        let upper = c.to_uppercase().next().unwrap_or(c);
        let hit = self
            .items
            .iter()
            .any(|item| [c, lower, upper].into_iter().any(|c| item.contains(c)));
        hit != self.negated
    }
}

impl ClassItem {
    fn contains(&self, c: char) -> bool {
        match *self {
            ClassItem::Range(low, high) => (low..=high).contains(&c),
            ClassItem::Digit(yes) => c.is_ascii_digit() == yes,
            ClassItem::Space(yes) => c.is_whitespace() == yes,
            ClassItem::Word(yes) => (c.is_alphanumeric() || c == '_') == yes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(pattern: &str, text: &str) -> bool {
        UaPattern::compile(pattern)
            .unwrap_or_else(|| panic!("{pattern} should compile"))
            .is_match(text)
    }

    /// Every pattern here is one a built-in list publishes.
    #[test]
    fn the_shapes_the_bot_lists_use_match_as_a_regex_would() {
        let cases = [
            (
                "AdsBot-Google([^-]|$)",
                "AdsBot-Google (+http://www.google.com/adsbot.html)",
                true,
            ),
            ("AdsBot-Google([^-]|$)", "AdsBot-Google", true),
            ("AdsBot-Google([^-]|$)", "AdsBot-Google-Mobile", false),
            (
                "[cC]laude(?:[bB]ot|-[Ww]eb)",
                "Mozilla/5.0 ClaudeBot/1.0",
                true,
            ),
            ("[cC]laude(?:[bB]ot|-[Ww]eb)", "Claude-User/1.0", false),
            ("Googlebot\\/", "Googlebot/2.1", true),
            (
                "Mediapartners \\(Googlebot\\)",
                "Mediapartners (Googlebot)",
                true,
            ),
            ("^Apache-HttpClient", "Apache-HttpClient/4.5", true),
            ("^Apache-HttpClient", "Java Apache-HttpClient/4.5", false),
            ("Face(book){0,1}[Bb]ot", "FaceBot", true),
            ("Face(book){0,1}[Bb]ot", "Facebookbot", true),
            ("Face(book){0,1}[Bb]ot", "Facebookbookbot", false),
            (
                "BlogTraffic\\/\\d\\.\\d+ Feed-Fetcher",
                "BlogTraffic/1.23 Feed-Fetcher",
                true,
            ),
            (
                "Poduptime;\\s*\\+fediverse\\.observer",
                "Poduptime;  +fediverse.observer",
                true,
            ),
            ("Brightbot 1.0", "Brightbot 1x0", true),
            ("(?:msnbot[-\\/]|librabot\\/)", "msnbot-media/1.1", true),
            ("yacycrawler|yacybot", "YaCyBot", true),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(matched(pattern, text), expected, "{pattern} against {text}");
        }
    }

    #[test]
    fn matching_ignores_case_in_letters_and_classes() {
        assert!(matched("googlebot", "GoogleBot/2.1"));
        assert!(matched("[a-z]+bot", "SEMRUSHBOT"));
    }

    #[test]
    fn the_alternative_that_matched_is_named_as_written() {
        let pattern = UaPattern::compile("Googlebot|Googlebot-Image\\/|Storebot-Google").unwrap();
        let named = |ua: &str| {
            pattern
                .matching_alternative(&Subject::new(ua))
                .map(str::to_string)
        };
        assert_eq!(named("Googlebot-Image/1.0").as_deref(), Some("Googlebot"));
        assert_eq!(
            named("Storebot-Google/1.0").as_deref(),
            Some("Storebot-Google")
        );
    }

    /// Given up rather than guessed: the caller compares as it did before.
    #[test]
    fn what_it_does_not_read_does_not_compile() {
        for pattern in [
            "a(?=b)",
            "(a)\\1",
            "\\bbot",
            "(?i)bot",
            "a++",
            "[[:alpha:]]",
            "(a",
            "a)",
        ] {
            assert!(UaPattern::compile(pattern).is_none(), "{pattern}");
        }
    }

    #[test]
    fn a_repetition_of_something_empty_ends() {
        assert!(matched("(a*)*b", "aaab"));
        assert!(!matched("(a*)*b", "aaac"));
    }
}
