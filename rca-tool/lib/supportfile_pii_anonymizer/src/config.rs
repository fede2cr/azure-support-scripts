//! Configuration for the [`crate::Anonymizer`].

use std::net::Ipv4Addr;

/// Runtime configuration. Construct via [`Config::default`] (all recognizers on,
/// safe defaults) and adjust with the builder methods.
#[derive(Clone, Debug)]
pub struct Config {
    /// Optional salt. Reserved for future cross-run-stable pseudonym derivation.
    /// When `None` (default), pseudonyms are stable only within a single
    /// [`crate::Anonymizer`] instance (per-run), so nothing about the real
    /// environment survives between reports.
    pub salt: Option<String>,

    /// Default network prefix used to group IPv4 addresses when no CIDR is known
    /// from context. Defaults to `24`.
    pub ipv4_default_prefix: u8,
    /// Default network prefix used to group IPv6 addresses when no CIDR is known
    /// from context. Defaults to `64`.
    pub ipv6_default_prefix: u8,

    /// Enable/disable individual recognizer categories.
    pub enable_ip: bool,
    pub enable_mac: bool,
    pub enable_guid: bool,
    pub enable_email: bool,
    pub enable_hostname: bool,
    pub enable_secret: bool,
    /// Azure-specific recognizers (resource IDs, etc.). Only has effect when the
    /// crate is built with the `azure` feature.
    pub enable_azure: bool,

    /// Additional IPv4 addresses to treat as non-PII (never anonymized), on top
    /// of the built-in allowlist (loopback, IMDS, WireServer, …).
    pub extra_ipv4_allowlist: Vec<Ipv4Addr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            salt: None,
            ipv4_default_prefix: 24,
            ipv6_default_prefix: 64,
            enable_ip: true,
            enable_mac: true,
            enable_guid: true,
            enable_email: true,
            enable_hostname: true,
            enable_secret: true,
            enable_azure: true,
            extra_ipv4_allowlist: Vec::new(),
        }
    }
}

impl Config {
    /// Set the salt used for pseudonym derivation (reserved for cross-run
    /// stability). Pass `None` for per-run-only stability (the default).
    pub fn with_salt(mut self, salt: Option<String>) -> Self {
        self.salt = salt;
        self
    }

    /// Set the default IPv4 grouping prefix (used when no CIDR is known).
    pub fn ipv4_default_prefix(mut self, prefix: u8) -> Self {
        self.ipv4_default_prefix = prefix.min(32);
        self
    }

    /// Set the default IPv6 grouping prefix (used when no CIDR is known).
    pub fn ipv6_default_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_default_prefix = prefix.min(128);
        self
    }

    /// Add an IPv4 address to the non-PII allowlist.
    pub fn allow_ipv4(mut self, addr: Ipv4Addr) -> Self {
        self.extra_ipv4_allowlist.push(addr);
        self
    }
}
