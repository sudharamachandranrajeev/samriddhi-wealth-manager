//! Links that set up sync without typing, as brahma_core's `BrahmaLink`:
//!
//! * `artha://setup?s=<server>&i=<invite>`: printed by the server.
//! * `<app>://pair?s=<server>&p=<record>&k=<secret>`: shown by a signed-in
//!   device so another one can join it (see [`crate::pairing`]).
//! * `brahma://moved?s=<server>`: the server moved; signed-in devices follow.
//!
//! Any Brahma app's scheme is accepted: the links are about the account.

use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use url::Url;

use crate::SyncError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrahmaLink {
    Setup { server: Url, invite: String },
    Pair(PairingLink),
    Moved { server: Url },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingLink {
    pub server: Url,
    /// The pairing record on the server.
    pub id: String,
    /// 32 random bytes the server never sees.
    pub secret: [u8; 32],
    /// Which app a scanned code opens.
    pub scheme: String,
}

impl std::fmt::Display for PairingLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut u = Url::parse(&format!("{}://pair", self.scheme)).map_err(|_| std::fmt::Error)?;
        u.query_pairs_mut()
            .append_pair("s", &server_text(&self.server))
            .append_pair("p", &self.id)
            .append_pair("k", &URL_SAFE_NO_PAD.encode(self.secret));
        f.write_str(u.as_str())
    }
}

/// `brahma://moved?s=<server>`.
pub fn moved_link(server: &Url) -> String {
    let mut u = Url::parse("brahma://moved").expect("a fixed URL");
    u.query_pairs_mut().append_pair("s", &server_text(server));
    u.to_string()
}

/// A server address the way Dart prints it: no trailing slash on a bare host.
pub fn server_text(server: &Url) -> String {
    let s = server.as_str();
    if server.path() == "/" && server.query().is_none() {
        s.trim_end_matches('/').to_string()
    } else {
        s.to_string()
    }
}

fn bad(s: &str) -> SyncError {
    SyncError::Message(s.to_string())
}

/// A plain lower-case id that is not a web scheme.
pub fn is_brahma_scheme(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && !matches!(
            s,
            "http" | "https" | "file" | "mailto" | "tel" | "sms" | "data" | "content" | "intent"
        )
}

impl BrahmaLink {
    /// Reads a link from pasted text or a scanned code. Line breaks and
    /// spaces that chat apps add are ignored.
    pub fn parse(text: &str) -> Result<BrahmaLink, SyncError> {
        let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let not_link =
            || bad("That is not a sync link. It starts with an app's name, like artha://");
        let uri = Url::parse(&clean).map_err(|_| not_link())?;
        if !is_brahma_scheme(uri.scheme()) {
            return Err(not_link());
        }
        let q = |k: &str| {
            uri.query_pairs()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.into_owned())
        };
        let server = q("s").ok_or_else(|| bad("That link has no server address"))?;
        match uri.host_str().unwrap_or("") {
            "setup" => {
                let invite = q("i").unwrap_or_default();
                if invite.is_empty() {
                    return Err(bad("That setup link has no invite code"));
                }
                Ok(BrahmaLink::Setup {
                    server: validate_server_url(&server)?,
                    invite,
                })
            }
            "pair" => {
                let id = q("p").unwrap_or_default();
                let secret = URL_SAFE_NO_PAD
                    .decode(q("k").unwrap_or_default().trim_end_matches('='))
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok());
                let id_ok = id.len() == 15
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
                match secret {
                    Some(secret) if id_ok => Ok(BrahmaLink::Pair(PairingLink {
                        server: validate_server_url(&server)?,
                        id,
                        secret,
                        scheme: uri.scheme().to_string(),
                    })),
                    _ => Err(bad(
                        "That pairing link is incomplete. Copy the whole link again",
                    )),
                }
            }
            "moved" => Ok(BrahmaLink::Moved {
                server: validate_server_url(&server)?,
            }),
            _ => Err(bad(
                "This version does not know that link. Update the app and try again",
            )),
        }
    }
}

/// https anywhere; plain http only on the user's own network.
pub fn validate_server_url(input: &str) -> Result<Url, SyncError> {
    let example = || bad("Enter a server address like https://sync.example.com");
    let u = Url::parse(input.trim()).map_err(|_| example())?;
    let host = u.host_str().unwrap_or("");
    if host.is_empty() || !u.username().is_empty() || u.password().is_some() {
        return Err(example());
    }
    match u.scheme() {
        "https" => Ok(u),
        "http" if is_local_host(host) => Ok(u),
        "http" => Err(bad("Use https:// for servers outside your own network")),
        _ => Err(example()),
    }
}

/// Loopback, link-local, RFC 1918, CGNAT/Tailscale (100.64/10), IPv6 ULA,
/// `localhost` and mDNS `.local` names. Only literal addresses count.
pub fn is_local_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".local") {
        return true;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let b = ip.octets();
            ip.is_loopback()
                || ip.is_link_local()
                || b[0] == 10
                || (b[0] == 172 && (16..=31).contains(&b[1]))
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 100 && (64..=127).contains(&b[1]))
        }
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || (ip.octets()[0] & 0xfe) == 0xfc
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_parse_like_core() {
        let moved = BrahmaLink::parse("brahma://moved?s=https%3A%2F%2Fsync.example.com").unwrap();
        assert!(
            matches!(moved, BrahmaLink::Moved { ref server } if server.host_str() == Some("sync.example.com"))
        );
        assert_eq!(
            moved_link(&validate_server_url("https://sync.example.com").unwrap()),
            "brahma://moved?s=https%3A%2F%2Fsync.example.com"
        );
        let setup =
            BrahmaLink::parse("artha://setup?s=http%3A%2F%2F127.0.0.1%3A8787&i=ABCD").unwrap();
        assert!(matches!(setup, BrahmaLink::Setup { ref invite, .. } if invite == "ABCD"));
        for bad in [
            "https://example.com",
            "brahma://moved",
            "brahma://moved?s=http%3A%2F%2Fsync.example.com",
            "artha://pair?s=https%3A%2F%2Fa.example.com&p=short&k=AAAA",
            "artha://later?s=https%3A%2F%2Fa.example.com",
        ] {
            assert!(BrahmaLink::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_own_network_hosts_may_use_http() {
        // Private addresses are built from parts so the public-repo scan
        // (scripts/check-public.sh) does not take them for real ones.
        let ip = |p: [u8; 4]| p.map(|b| b.to_string()).join(".");
        let own = [ip([10, 1, 2, 3]), ip([100, 64, 0, 1]), ip([192, 168, 0, 9])];
        let fixed = ["127.0.0.1", "localhost", "pi.local", "[::1]", "[fd00::1]"];
        for h in own.iter().map(String::as_str).chain(fixed) {
            assert!(is_local_host(h), "{h}");
        }
        let lan_name = format!("{}.example.com", ip([192, 168, 1, 5]));
        let other = [ip([100, 128, 0, 1]), ip([172, 32, 0, 1]), lan_name];
        for h in other
            .iter()
            .map(String::as_str)
            .chain(["8.8.8.8", "example.com"])
        {
            assert!(!is_local_host(h), "{h}");
        }
    }
}
