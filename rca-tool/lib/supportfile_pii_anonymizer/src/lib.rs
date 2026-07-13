//! `pii-anonymizer` — offline, deterministic anonymization of PII and
//! environment-identifying data for Azure & Linux diagnostics
//! (sosreport / supportconfig).
//!
//! Design mirrors Microsoft Presidio's conceptual split — **recognizers**
//! detect spans, **operators/strategies** transform them — but is implemented
//! in pure Rust with no NLP/ML engine, so it compiles to WASM and runs inline
//! on every analysis. See `rca-tool/Developer_PII.md` for the full design.
//!
//! # Key properties
//! - **Deterministic & correlation-preserving:** within one [`Anonymizer`]
//!   instance the same original value always maps to the same token, so
//!   relationships survive (same host → same pseudonym).
//! - **Subnet-preserving IPs:** two addresses on the same subnet map to the
//!   same `net-*` label, so topology stays visible without exposing real
//!   addresses. Loopback and well-known Azure infra addresses are left intact.
//! - **Offline:** no network, no model downloads.
//!
//! # Example
//! ```
//! use supportfile_pii_anonymizer::{Anonymizer, Config};
//!
//! let mut anon = Anonymizer::new(Config::default());
//! let out = anon.scrub_text("node at 10.1.2.34 and 10.1.2.99 talk to 127.0.0.1");
//! // 10.1.2.34 and 10.1.2.99 share a subnet label; 127.0.0.1 is untouched.
//! assert!(out.contains("127.0.0.1"));
//! assert!(!out.contains("10.1.2.34"));
//! ```

mod allowlist;
mod config;
mod engine;
mod ip;
mod recognizers;
mod strategy;

#[cfg(feature = "serde_json")]
mod json;

pub use config::Config;
pub use engine::Anonymizer;
pub use recognizers::archive_root::extract_archive_hostname;
pub use recognizers::{EntityType, RecognizerResult};
