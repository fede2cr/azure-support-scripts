//! Conservative FQDN / hostname recognizer.
//!
//! Free-text hostname detection is inherently heuristic, so this recognizer is
//! deliberately narrow to avoid corrupting diagnostic output:
//!
//! - Only fully-qualified names with at least three labels (two dots) match.
//! - The final label must be a **real TLD** (public or internal), so kernel
//!   sysctl variables (`net.core.somaxconn`, `kernel.sched_migration_cost_ns`)
//!   and dotted filenames (`pacemaker.log-20250101.gz`) are ignored.
//! - Well-known **public / vendor / cloud** domains (e.g. `access.redhat.com`,
//!   `*.blob.storage.azure.net`) are kept verbatim — they are not PII.
//! - Hosts that are the authority of a URL (`https://access.redhat.com/...`)
//!   are skipped so documentation links stay intact.
//!
//! Single-label node names (e.g. `hana01`) cannot be reliably detected without
//! a dictionary and are intentionally out of scope for the free-text pass.

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn fqdn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // >= 3 labels, final label alphabetic (so dotted-quad IPs never match).
    RE.get_or_init(|| {
        Regex::new(
            r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){2,}[A-Za-z]{2,24}\b",
        )
        .unwrap()
    })
}

/// Real TLDs we accept as domain-terminating (common public + private/internal).
/// A candidate whose last label is not here is treated as a non-domain (kernel
/// variable, filename, package name, …) and left untouched.
const TLDS: &[&str] = &[
    // generic / common gTLDs
    "com", "net", "org", "io", "gov", "edu", "mil", "co", "info", "biz", "cloud",
    "dev", "app", "me", "ai", "xyz", "tv", "name", "pro", "site", "online",
    "tech",
    // common ccTLDs
    "us", "uk", "de", "fr", "jp", "cn", "au", "ca", "eu", "in", "br", "ru", "it",
    "es", "nl", "se", "no", "fi", "ch", "at", "be", "dk", "pl", "cz", "ie", "nz",
    "za", "sg", "kr", "tr", "mx",
    // private / internal
    "local", "internal", "intranet", "intra", "lan", "home", "corp",
    "localdomain",
];

/// Public / vendor / cloud domains that are not sensitive and must be kept
/// verbatim (registrable-suffix match). Includes Azure service endpoints, whose
/// hostnames are diagnostic (not PII) per project guidance.
const PUBLIC_DOMAINS: &[&str] = &[
    "redhat.com",
    "microsoft.com",
    "azure.com",
    "azure.net",
    "windows.net",
    "core.windows.net",
    "cloudapp.azure.com",
    "ubuntu.com",
    "canonical.com",
    "suse.com",
    "opensuse.org",
    "kernel.org",
    "github.com",
    "gitlab.com",
    "debian.org",
    "centos.org",
    "rockylinux.org",
    "almalinux.org",
    "oracle.com",
    "google.com",
    "googleapis.com",
    "amazonaws.com",
    "cloudflare.com",
    "letsencrypt.org",
    "docker.com",
    "docker.io",
    "python.org",
    "rust-lang.org",
    "npmjs.com",
    "fedoraproject.org",
    "launchpad.net",
    "nvidia.com",
    "intel.com",
];

fn last_label(host: &str) -> &str {
    host.rsplit('.').next().unwrap_or("")
}

fn is_valid_tld(host: &str) -> bool {
    let t = last_label(host).to_ascii_lowercase();
    TLDS.contains(&t.as_str())
}

fn is_public_domain(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    PUBLIC_DOMAINS
        .iter()
        .any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

pub struct HostnameRecognizer;
impl HostnameRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for HostnameRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        for m in fqdn_re().find_iter(text) {
            let host = m.as_str();
            // Skip URL authorities (e.g. https://access.redhat.com/...): the
            // preceding characters are a scheme separator.
            if text[..m.start()].ends_with("://") {
                continue;
            }
            // Require a real TLD so kernel variables (net.core.somaxconn) and
            // dotted filenames (pacemaker.log-20250101.gz) are ignored.
            if !is_valid_tld(host) {
                continue;
            }
            // Keep well-known public/vendor/cloud domains verbatim.
            if is_public_domain(host) {
                continue;
            }
            // Lower score than the structured recognizers so an FQDN embedded in
            // an email/Azure-ID span loses to the larger, more specific span.
            out.push(RecognizerResult::new(m.start(), m.end(), EntityType::Hostname, 0.5));
        }
        out
    }
}
