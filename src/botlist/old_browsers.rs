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

//! Old browser agents: the user-agent strings of browsers too old for
//! any real visitor to still be running, which scanners rotate through to
//! look like people.
//!
//! ## Why a list of its own
//!
//! A host's log from April to October 2026 had one scanner asking for
//! `/.env`, `/.git/config`, credentials files and heap dumps 1,150 times
//! from 637 addresses, never twice with the same user agent: Opera 5 to 9,
//! NetFront and UP.Browser feature phones, BlackBerry 7520, Lynx from
//! 2005, Firefox 3. None of those is a bot's *name*, so no bot list can
//! carry them, and blocking one exact string blocks nothing the next
//! request will send. What they share is age.
//!
//! These are not bots, so they are not rows in the `bots` table and carry
//! no category. They are one switch, off by default
//! ([`crate::db::Db::get_block_old_browsers`]): some of these are still a
//! person somewhere — Opera Mini's data-saving mode still sends
//! `Opera/9.80`, and an old e-ink Kindle browses with NetFront — and a new
//! way to turn visitors away arrives off. "Humans only" does not turn it
//! on, for the same reason: it blocks bots, and these may be people.
//!
//! ## What is deliberately not here
//!
//! Each of these would catch a real crawler or a real person's mail:
//!
//! - **Old iOS** (`iPhone OS 7_0`). Bing's mobile crawler still sends it,
//!   and Yandex's sends `iPhone OS 8_1`.
//! - **Windows XP** (`Windows NT 5.1`). Gmail's image proxy sends it, so
//!   blocking it breaks the images in every email that links to the site.
//! - **Android 4.** Too recent to be sure nobody runs it; Android 1 to 3
//!   are here.
//!
//! [`NOT_OLD`] holds those strings and more, and the tests keep every
//! entry off them.
//!
//! ## Matching
//!
//! Every entry is a literal substring, matched case-insensitively and
//! written to the web server escaped ([`patterns`]), so what is blocked is
//! exactly what [`matches`] says — no regex for the Firewall screen's
//! substring check to read differently. A range of versions is spelled out
//! one version at a time ([`Entry::Below`]), each ending in its separator,
//! so `Chrome/1.` is Chrome 1 and never Chrome 120.

/// One kind of old browser.
#[derive(Debug, Clone, Copy)]
enum Entry {
    /// Any of these substrings.
    Literal(&'static [&'static str]),
    /// `prefix`, a version from `from` up to but not including `below`,
    /// then `separator`: `Below("Firefox/", 1, 10, ".")` is `Firefox/1.`
    /// to `Firefox/9.`.
    Below(&'static str, u32, u32, &'static str),
}

/// `(what it is, the strings it covers)`.
const ENTRIES: &[(&str, Entry)] = &[
    // Presto-era Opera, 2000 to 2013. Opera 10 to 12 still send
    // `Opera/9.80`, and so does Opera Mini.
    ("Opera 5 to 12 (Presto)", Entry::Below("Opera/", 5, 10, ".")),
    ("Firefox 1 to 9", Entry::Below("Firefox/", 1, 10, ".")),
    ("Chrome 1 to 39", Entry::Below("Chrome/", 1, 40, ".")),
    (
        "Internet Explorer 2 to 9",
        Entry::Below("MSIE ", 2, 10, "."),
    ),
    // Netscape 1 to 3 and what claims to be them.
    ("Mozilla 1 to 3", Entry::Below("Mozilla/", 1, 4, ".")),
    ("Android 1 to 3", Entry::Below("Android ", 1, 4, ".")),
    // 2.8.7 is from 2009; 2.8.9 and 2.9 are what a Lynx user runs now.
    ("Lynx 2.8.0 to 2.8.7", Entry::Below("Lynx/2.8.", 0, 8, "")),
    (
        "ELinks 0.9 to 0.11",
        Entry::Literal(&["ELinks/0.9.", "ELinks/0.10.", "ELinks/0.11."]),
    ),
    (
        "Windows 95, 98, ME and NT 4",
        Entry::Literal(&["Windows 95", "Windows 98", "Win 9x", "Windows NT 4."]),
    ),
    // Feature phones and their browsers.
    ("NetFront", Entry::Literal(&["NetFront"])),
    (
        "Openwave",
        Entry::Literal(&["UP.Browser", "UP.Link", "Openwave"]),
    ),
    ("J2ME (MIDP) phones", Entry::Literal(&["MIDP-"])),
    (
        "Symbian",
        Entry::Literal(&["SymbOS", "SymbianOS", "Series60"]),
    ),
    ("BlackBerry OS", Entry::Literal(&["BlackBerry"])),
    (
        "Sony Ericsson",
        Entry::Literal(&["SonyEricsson", "SEMC-Browser"]),
    ),
    // Hyphenated: Samsung's phones before Android. Today's send
    // `SAMSUNG SM-` or `SamsungBrowser`, never the hyphen.
    (
        "Samsung feature phones",
        Entry::Literal(&["SAMSUNG-", "SEC-SGH"]),
    ),
    ("Polaris", Entry::Literal(&["POLARIS/"])),
    ("Vodafone feature phones", Entry::Literal(&["Vodafone/"])),
    // Not browsers, and long gone: an email harvester from 1999 and a
    // validator from the 2000s, both in the same scanner's rotation.
    ("EmailWolf", Entry::Literal(&["EmailWolf"])),
    ("WDG Validator", Entry::Literal(&["WDG_Validator"])),
];

/// Every substring the list covers, as it is matched.
pub fn substrings() -> Vec<String> {
    let mut out = Vec::new();
    for (_, entry) in ENTRIES {
        match *entry {
            Entry::Literal(strings) => out.extend(strings.iter().map(|s| (*s).to_string())),
            Entry::Below(prefix, from, below, separator) => {
                out.extend((from..below).map(|version| format!("{prefix}{version}{separator}")));
            }
        }
    }
    out
}

/// The list as web server patterns: each substring escaped, so it matches
/// itself and nothing else.
pub fn patterns() -> Vec<String> {
    substrings()
        .iter()
        .map(|s| crate::db::escape_regex_literal(s))
        .collect()
}

/// Whether `user_agent` is an old browser, matched as the web server
/// matches it: a case-insensitive substring.
pub fn matches(user_agent: &str) -> bool {
    let lower = user_agent.to_lowercase();
    substrings()
        .iter()
        .any(|s| lower.contains(&s.to_lowercase()))
}

/// User agents no entry may match, each with the reason: today's browsers,
/// and the crawlers and proxies that send an old browser's string.
pub const NOT_OLD: &[(&str, &str)] = &[
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36",
        "Chrome on Windows",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Mobile Safari/537.36",
        "Chrome on Android 14",
    ),
    (
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/120.0.0.0 Mobile Safari/537.36",
        "Android 10, the reduced string every Chrome sends",
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
        "Firefox",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
        "Firefox ESR 115, the last for Windows 7",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, \
         like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
        "Safari on iOS 18",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like \
         Gecko) Version/17.5 Safari/605.1.15",
        "Safari on macOS",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
        "Edge",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/126.0.0.0 Safari/537.36 OPR/112.0.0.0",
        "Opera today, which says OPR, not Opera/",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S918B) AppleWebKit/537.36 (KHTML, like \
         Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
        "Samsung Internet, which says SAMSUNG with a space",
    ),
    (
        "Lynx/2.9.0dev.12 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/3.7.9",
        "Lynx as people run it now",
    ),
    (
        "ELinks/0.17.0 (textmode; Linux 6.1 x86_64; 120x40-2)",
        "ELinks now",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, \
         like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; \
         +http://www.bing.com/bingbot.htm)",
        "Bing's mobile crawler, which sends iOS 7",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, \
         like Gecko) Version/8.0 Mobile/12B411 Safari/600.1.4 (compatible; \
         YandexMobileBot/3.0; +http://yandex.com/bots)",
        "Yandex's mobile crawler, which sends iOS 8",
    ),
    (
        "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com \
         GoogleImageProxy)",
        "Gmail's image proxy, which sends Windows XP",
    ),
    (
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, \
         like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; \
         +http://www.google.com/bot.html)",
        "Googlebot's smartphone crawler",
    ),
    (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot",
    ),
    (
        "Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)",
        "certificate renewal",
    ),
    ("facebookexternalhit/1.1", "link previews"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The test that earns a place on someone's server: no entry matches a
    /// browser people use, or a crawler or proxy that sends an old string.
    #[test]
    fn nothing_matches_a_browser_in_use_or_a_crawler_that_borrows_an_old_one() {
        for (user_agent, why) in NOT_OLD {
            let lower = user_agent.to_lowercase();
            let hits: Vec<String> = substrings()
                .into_iter()
                .filter(|s| lower.contains(&s.to_lowercase()))
                .collect();
            assert!(hits.is_empty(), "{hits:?} match {why}: {user_agent:?}");
        }
    }

    /// The strings the list was read off, from the scanner's rotation.
    #[test]
    fn the_scanners_old_browsers_are_all_caught() {
        const SEEN: &[&str] = &[
            "Opera/9.51 Beta (Microsoft Windows; PPC; Opera Mobi/1718; U; en)",
            "Opera/8.54 (Windows NT 5.0; U; en)",
            "Opera/6.01 (Windows 98; U)  [de]",
            "Opera/5.0 (SunOS 5.8 sun4u; U)  [en]",
            "Opera/9.80 (Android; Opera Mini/7.5.33361/31.1543; U; en) Presto/2.8.119 \
             Version/11.1010",
            "SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 \
             configuration/CLDC-1.1 UP.Link/6.3.0.0.0",
            "SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0 \
             Configuration/CLDC-1.1",
            "SEC-SGHX210/1.0 UP.Link/6.3.1.13.0",
            "BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/5.0.3.3 \
             UP.Link/5.1.2.12 (Google WAP Proxy/1.0)",
            "POLARIS/6.01 (BREW 3.1.5; U; en-us; LG; LX265; POLARIS/6.01/WAP) MMP/2.0 \
             profile/MIDP-2.1 Configuration/CLDC-1.1",
            "ELinks/0.9.3 (textmode; Linux 2.6.9-kanotix-8 i686; 127x41)",
            "Lynx/2.8.5rel.1 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/0.8.12",
            "Lynx/2.8.7dev.4 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/0.9.8d",
            "EmailWolf 1.00",
            "WDG_Validator/1.6.2",
            "Openwave/ UCWEB7.0.2.37/28/999",
            "Vodafone/1.0/V802SE/SEJ001 Browser/SEMC-Browser/4.1",
            "Mozilla/5.0 (Linux; U; Android 1.5; de-de; HTC Magic Build/PLAT-RC33) \
             AppleWebKit/528.5  (KHTML, like Gecko) Version/3.1.2 Mobile Safari/525.20.1",
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.0.12) Gecko/2009070611 \
             Firefox/3.0.12 (.NET CLR 3.5.30729) FirePHP/0.3",
            "Mozilla/5.0 Slackware/13.37 (X11; U; Linux x86_64; en-US) AppleWebKit/535.1 \
             (KHTML, like Gecko) Chrome/13.0.782.41",
            "Opera/9.80 (S60; SymbOS; Opera Mobi/35779; U; hu) Presto/2.10.254 Version/12.00",
        ];
        for user_agent in SEEN {
            assert!(matches(user_agent), "nothing catches {user_agent:?}");
        }
    }

    /// A version range ends in its separator, or it reaches into versions
    /// people run: `Chrome/1` would match Chrome 140.
    #[test]
    fn a_version_range_never_reaches_a_current_version() {
        for (user_agent, version) in [
            ("Chrome/140.0.0.0", "Chrome 140"),
            ("Chrome/40.0.2214.85", "Chrome 40"),
            ("Firefox/10.0", "Firefox 10"),
            ("MSIE 10.0", "Internet Explorer 10"),
            ("Android 10; K", "Android 10"),
            (
                "Opera/10.00",
                "an Opera/10 nobody sends, but not ours to match",
            ),
        ] {
            assert!(!matches(user_agent), "{version} matches: {user_agent:?}");
        }
    }

    /// Escaped, every pattern passes the check the web server render
    /// applies, so none is dropped there in silence.
    #[test]
    fn every_pattern_can_be_written_to_the_web_server() {
        for pattern in patterns() {
            assert!(
                crate::nginx::pattern_problem(&pattern).is_none(),
                "{pattern:?} would be dropped: {:?}",
                crate::nginx::pattern_problem(&pattern)
            );
        }
    }

    /// Matched case-insensitively, as `~*` and `[NC]` match.
    #[test]
    fn matching_ignores_case() {
        assert!(matches("NETFRONT/3.4"));
        assert!(matches("opera/9.80 (android; opera mini)"));
    }
}
