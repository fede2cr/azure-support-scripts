//! IPv4 / IPv6 address recognizers. Detection only validates that a candidate
//! parses as an address; subnet-preserving anonymization happens in
//! [`crate::ip`].

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Dotted quad with an optional /NN CIDR suffix. Octet range is validated
    // after matching so we reject things like version strings out of range.
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b").unwrap())
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // A run of hex groups and colons with at least two colons, optional zone
    // (%eth0) and optional /NN. Rust's regex has no look-around, so we match a
    // broad candidate and let `Ipv6Addr` parsing reject false positives
    // (including MAC addresses, which never parse as a valid IPv6).
    RE.get_or_init(|| {
        Regex::new(r"[A-Fa-f0-9]{0,4}(?::[A-Fa-f0-9]{0,4}){2,}(?:%[A-Za-z0-9_.-]+)?(?:/\d{1,3})?")
            .unwrap()
    })
}

/// Split an optional `/NN` CIDR suffix off a candidate; returns `(addr, prefix)`.
pub(crate) fn split_prefix(s: &str) -> (&str, Option<u8>) {
    match s.rsplit_once('/') {
        Some((addr, p)) => (addr, p.parse::<u8>().ok()),
        None => (s, None),
    }
}

/// Strip an optional `%zone` scope id off an IPv6 candidate.
pub(crate) fn split_zone(s: &str) -> &str {
    s.split_once('%').map(|(a, _)| a).unwrap_or(s)
}

/// Whether an IPv4 candidate at byte offset `start` is immediately preceded by a
/// version-context word (`version 2.14.0.1`, `release 1.2.3.4`), so dotted
/// version numbers in free text are treated as versions, not IP addresses.
fn preceded_by_version_word(text: &str, start: usize) -> bool {
    let before = text[..start].trim_end_matches([' ', ':', '=', '\t']);
    let word: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    matches!(word.to_ascii_lowercase().as_str(), "version" | "release")
}

pub struct Ipv4Recognizer;
impl Ipv4Recognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for Ipv4Recognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        for m in ipv4_re().find_iter(text) {
            let (addr, _prefix) = split_prefix(m.as_str());
            if addr.parse::<Ipv4Addr>().is_ok() && !preceded_by_version_word(text, m.start()) {
                out.push(RecognizerResult::new(
                    m.start(),
                    m.end(),
                    EntityType::Ipv4,
                    0.9,
                ));
            }
        }
        out
    }
}

pub struct Ipv6Recognizer;
impl Ipv6Recognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for Ipv6Recognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        for m in ipv6_re().find_iter(text) {
            let (addr, _prefix) = split_prefix(m.as_str());
            let core = split_zone(addr);
            if core.parse::<Ipv6Addr>().is_ok() {
                out.push(RecognizerResult::new(
                    m.start(),
                    m.end(),
                    EntityType::Ipv6,
                    0.9,
                ));
            }
        }
        out
    }
}
