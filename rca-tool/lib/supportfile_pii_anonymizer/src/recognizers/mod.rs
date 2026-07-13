//! Recognizers detect spans of sensitive data in text. This mirrors Presidio's
//! `PatternRecognizer` / `RecognizerResult` model: each recognizer returns the
//! byte ranges it matched together with an [`EntityType`] and a confidence
//! score. The engine resolves overlaps and hands surviving spans to the
//! strategy layer for transformation.

#[cfg(feature = "azure")]
pub mod azure;
pub mod archive_root;
pub mod email;
pub mod guid;
pub mod hostname;
pub mod ip;
pub mod mac;
pub mod secret;

use crate::config::Config;

/// Categories of sensitive data this crate can detect and anonymize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    Ipv4,
    Ipv6,
    Mac,
    Guid,
    Email,
    Hostname,
    AzureResourceId,
    Secret,
}

impl EntityType {
    /// Short stable label used in emitted tokens (e.g. `Guid` -> `GUID`).
    pub fn label(self) -> &'static str {
        match self {
            EntityType::Ipv4 => "IPv4",
            EntityType::Ipv6 => "IPv6",
            EntityType::Mac => "MAC",
            EntityType::Guid => "GUID",
            EntityType::Email => "EMAIL",
            EntityType::Hostname => "HOST",
            EntityType::AzureResourceId => "AZURE_ID",
            EntityType::Secret => "SECRET",
        }
    }
}

/// A single detected span. `start`/`end` are byte offsets into the scanned text
/// (`end` exclusive). `score` is a confidence in `[0.0, 1.0]` used for overlap
/// resolution.
#[derive(Debug, Clone, Copy)]
pub struct RecognizerResult {
    pub start: usize,
    pub end: usize,
    pub entity: EntityType,
    pub score: f32,
}

impl RecognizerResult {
    pub fn new(start: usize, end: usize, entity: EntityType, score: f32) -> Self {
        Self {
            start,
            end,
            entity,
            score,
        }
    }
    pub fn span_len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }
}

/// Common interface for all detectors.
pub trait Recognizer: Send + Sync {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult>;
}

/// Build the active recognizer set from configuration. Order is not significant
/// (the engine resolves overlaps by score/length), but higher-value structural
/// recognizers (secrets, Azure IDs) carry higher scores so they win over the
/// generic ones they may contain.
pub fn build_recognizers(cfg: &Config) -> Vec<Box<dyn Recognizer>> {
    let mut v: Vec<Box<dyn Recognizer>> = Vec::new();

    if cfg.enable_secret {
        v.push(Box::new(secret::SecretRecognizer::new()));
    }
    #[cfg(feature = "azure")]
    if cfg.enable_azure {
        v.push(Box::new(azure::AzureResourceIdRecognizer::new()));
    }
    if cfg.enable_ip {
        v.push(Box::new(ip::Ipv4Recognizer::new()));
        v.push(Box::new(ip::Ipv6Recognizer::new()));
    }
    if cfg.enable_mac {
        v.push(Box::new(mac::MacRecognizer::new()));
    }
    if cfg.enable_guid {
        v.push(Box::new(guid::GuidRecognizer::new()));
    }
    if cfg.enable_email {
        v.push(Box::new(email::EmailRecognizer::new()));
    }
    if cfg.enable_hostname {
        v.push(Box::new(hostname::HostnameRecognizer::new()));
        // Archive-root host detection is part of hostname handling.
        v.push(Box::new(archive_root::ArchiveRootRecognizer::new()));
    }

    v
}
