//! Built-in allowlist of non-PII, diagnostic addresses that must never be
//! anonymized. These are fixed, public, documented values whose whole purpose
//! is troubleshooting.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::Config;

/// Azure Instance Metadata Service (IMDS) — fixed, public, documented.
const AZURE_IMDS: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
/// Azure "WireServer" / platform DNS — fixed, public, documented.
const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);

/// Returns `true` if `addr` is a diagnostic / non-PII IPv4 address that should
/// be left verbatim.
pub fn is_ipv4_allowlisted(addr: Ipv4Addr, cfg: &Config) -> bool {
    // Loopback 127.0.0.0/8
    if addr.octets()[0] == 127 {
        return true;
    }
    // Unspecified / broadcast — not identifying.
    if addr == Ipv4Addr::UNSPECIFIED || addr == Ipv4Addr::BROADCAST {
        return true;
    }
    // Well-known Azure platform endpoints.
    if addr == AZURE_IMDS || addr == AZURE_WIRESERVER {
        return true;
    }
    // Caller-provided extras.
    cfg.extra_ipv4_allowlist.contains(&addr)
}

/// Returns `true` if `addr` is a diagnostic / non-PII IPv6 address that should
/// be left verbatim.
pub fn is_ipv6_allowlisted(addr: Ipv6Addr) -> bool {
    addr == Ipv6Addr::LOCALHOST || addr == Ipv6Addr::UNSPECIFIED
}
