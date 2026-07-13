//! Secret / credential recognizer. High score, fail-safe redaction.
//!
//! Detects `key=value` / `key: value` secrets, `Bearer <token>` authorization
//! values, and PEM private-key blocks. For `key=value` and bearer forms only
//! the **value** span is reported so the key stays visible for debugging
//! (`password=[[SECRET]]`); PEM blocks are reported whole.

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:pass(?:word|wd)?|secret|client[_-]?secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\b\s*[:=]\s*"?(?P<val>[^\s"']+)"#,
        )
        .unwrap()
    })
}

fn bearer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bbearer\s+(?P<val>[A-Za-z0-9._\-]+)").unwrap())
}

fn pem_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
            .unwrap()
    })
}

pub struct SecretRecognizer;
impl SecretRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for SecretRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        for caps in kv_re().captures_iter(text) {
            if let Some(v) = caps.name("val") {
                out.push(RecognizerResult::new(
                    v.start(),
                    v.end(),
                    EntityType::Secret,
                    0.95,
                ));
            }
        }
        for caps in bearer_re().captures_iter(text) {
            if let Some(v) = caps.name("val") {
                out.push(RecognizerResult::new(
                    v.start(),
                    v.end(),
                    EntityType::Secret,
                    0.95,
                ));
            }
        }
        for m in pem_re().find_iter(text) {
            out.push(RecognizerResult::new(
                m.start(),
                m.end(),
                EntityType::Secret,
                0.99,
            ));
        }
        out
    }
}
