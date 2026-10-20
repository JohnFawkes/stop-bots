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

//! Requests that are not for a web page at all: another protocol spoken to
//! the web server, or the web server asked to be a proxy.
//!
//! A scanner that sweeps the internet for open SOCKS proxies, SSH servers,
//! Oracle WebLogic or crypto-mining pools knocks on port 80 with the same
//! bytes it sends everywhere else. NGINX answers 400 and logs whatever
//! arrived as the request line: a TLS handshake as `\x16\x03\x01…`, a
//! SOCKS greeting as `\x05\x01\x00`, `SSH-2.0-Go`, `t3 12.1.2`. None of
//! these is an HTTP request, so no browser, crawler or app sends one, and
//! none of them names a page either, so no other detector judges it.
//!
//! The other half is HTTP asking the server to forward it somewhere else:
//! `CONNECT host:443`, or `GET http://httpbin.org/get`. A web server is
//! nobody's proxy by accident. A full URL naming one of this host's own
//! sites is valid HTTP, though, and some clients send exactly that; such a
//! request is left alone, and so is every full URL when no site has been
//! scanned, since then nothing says whose name it is.
//!
//! ## What is never counted
//!
//! - **An empty request.** NGINX logs `""` with a 400 for a connection
//!   that closed before sending anything, which is also what a browser's
//!   speculative connection that went unused looks like.
//! - **A TLS record other than a handshake.** A TLS client that gets a
//!   plain-HTTP answer sends an alert (`\x15\x03…`) back, and NGINX logs
//!   that. It was found on a real host, sent by its owner's own client.
//!   Only a handshake (`\x16\x03…`) opens a connection, so only a
//!   handshake is someone choosing to speak TLS to a plain-HTTP port.
//!
//! ## Evidence
//!
//! A month of one host's log, its sites known: 248 addresses, 235 of them
//! blocked by no other detector, where every other detector together
//! blocked 335. None had read pages the way a visitor does, and none had
//! logged in over SSH. Two weeks of a second host serving Nextcloud,
//! Jellyfin and Immich to their apps: three, all scanners. The one
//! address there that sent such a line and also used the sites was their
//! owner's, sending the TLS alerts above.
//!
//! An address the site also answered normally is not counted
//! ([`crate::evidence::Rule::OnceUnlessCleared`]), which costs about a
//! fifth of those blocks: scanners fetch `/` too. It is the price of the
//! one way a visitor's browser sends a TLS handshake here, a site whose
//! `https://` port answers plain HTTP. That visitor was redirected there
//! from `http://`, and the redirect is an ordinary answer.

/// What `request`, the request line as logged, is instead of a request for
/// a page, or `None` when it is one. `site` says whether a host name is one
/// of this host's sites: `None` when nothing is known about the sites.
pub fn signature(request: &str, site: impl Fn(&str) -> Option<bool>) -> Option<&'static str> {
    if request.is_empty() || request == "-" {
        return None;
    }
    // NGINX writes a byte outside printable ASCII as `\xHH`.
    if let Some(record) = request.strip_prefix("\\x") {
        return match record.get(..2) {
            Some("16") => Some("tls handshake"),
            Some("14" | "15" | "17") => None,
            Some("04" | "05") if is_socks(record) => Some("socks handshake"),
            _ => Some("not http"),
        };
    }
    if request.starts_with("SSH-") {
        return Some("ssh handshake");
    }
    let mut words = request.split(' ');
    let method = words.next().unwrap_or_default();
    if method == "CONNECT" {
        return Some("proxy request");
    }
    let Some(target) = words.next().filter(|_| is_method(method)) else {
        return Some("not http");
    };
    if target.starts_with('/') || target == "*" {
        return None;
    }
    let lower = target.to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
    else {
        return Some("not http");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = crate::services::host_name(authority.rsplit('@').next().unwrap_or_default());
    // An address could be this host's own, and nothing here knows which.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    match site(host) {
        Some(false) => Some("proxy request"),
        Some(true) | None => None,
    }
}

/// An HTTP method as NGINX accepts one: capital letters, `_` and `-`.
/// WebDAV's are all of that shape too (`PROPFIND`, `VERSION-CONTROL`).
fn is_method(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b == b'-')
}

/// A SOCKS 4 or 5 greeting, after its first `\x`: version 4 asking to
/// connect or bind, or version 5 offering one to three methods.
fn is_socks(record: &str) -> bool {
    let second = record.get(2..6);
    match record.get(..2) {
        Some("04") => matches!(second, Some("\\x01" | "\\x02")),
        Some("05") => matches!(second, Some("\\x01" | "\\x02" | "\\x03")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a host with one site, `example.com`, makes of each request.
    fn judged(request: &str) -> Option<&'static str> {
        signature(request, |host| Some(host == "example.com"))
    }

    /// Every request line in this table was found in a real access log.
    #[test]
    fn each_kind_of_request_that_is_not_for_a_page() {
        let cases = [
            (
                r"\x16\x03\x01\x00\xEE\x01\x00\x00\xEA\x03\x03I\x06",
                Some("tls handshake"),
            ),
            (r"\x05\x01\x00", Some("socks handshake")),
            (
                r"\x04\x01\x00P\x00\x00\x00\x01\x00httpbin.org\x00",
                Some("socks handshake"),
            ),
            ("SSH-2.0-Go", Some("ssh handshake")),
            ("CONNECT ip.cypher.rest:443 HTTP/1.1", Some("proxy request")),
            ("GET http://httpbin.org/get HTTP/1.1", Some("proxy request")),
            ("GET http://api.ipify.org/ HTTP/1.1", Some("proxy request")),
            ("t3 12.1.2", Some("not http")),
            ("MGLNDD_51.158.160.121_443", Some("not http")),
            ("GET stager64 HTTP/1.1", Some("not http")),
            (
                "REQMOD icap://icap-server.net/server?arg=87 ICAP/1.0",
                Some("not http"),
            ),
            (
                r"{\x22id\x22: 1, \x22method\x22: \x22mining.subscribe\x22}",
                Some("not http"),
            ),
            (r"\x03\x00\x00\x13\x0E\xE0\x00\x00", Some("not http")),
        ];
        for (request, expected) in cases {
            assert_eq!(judged(request), expected, "{request}");
        }
    }

    #[test]
    fn requests_for_a_page_and_what_a_real_client_sends_are_not_counted() {
        let cases = [
            ("an ordinary request", "GET /blog/ HTTP/1.1"),
            ("HTTP/2", "GET / HTTP/2.0"),
            ("WebDAV", "PROPFIND /remote.php/dav/files/me/ HTTP/1.1"),
            (
                "a payload with spaces in it",
                "GET /?id=-1 UNION SELECT 1 HTTP/1.1",
            ),
            ("OPTIONS for the whole server", "OPTIONS * HTTP/1.1"),
            ("an empty request", ""),
            ("NGINX's dash for no request", "-"),
            (
                "a full URL naming a site here",
                "GET http://example.com/a HTTP/1.1",
            ),
            (
                "a full URL naming a site here, port and all",
                "GET https://EXAMPLE.com:443/ HTTP/1.1",
            ),
            (
                "a full URL naming an address",
                "GET http://203.0.113.5/ HTTP/1.1",
            ),
            ("a TLS alert", r"\x15\x03\x03\x00\x02\x02F"),
        ];
        for (what, request) in cases {
            assert_eq!(judged(request), None, "{what}: {request}");
        }
    }

    /// With no site scanned, a full URL could name any of them.
    #[test]
    fn a_full_url_is_not_counted_when_nothing_is_known_about_the_sites() {
        assert_eq!(
            signature("GET http://httpbin.org/get HTTP/1.1", |_| None),
            None
        );
    }
}
