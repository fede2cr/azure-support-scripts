//! `serde_json` walker: recursively anonymizes every string leaf in place.
//! Numbers, booleans, and object keys are left untouched (keys carry no PII in
//! our schemas; numeric provenance like `source_line` must be preserved).
//!
//! The walker is **key-aware**: string values under version/release keys (e.g.
//! `agentVersion: "2.14.0.1"`) are left untouched, because dotted version
//! numbers otherwise look like IPv4 addresses to the recognizer.

use serde_json::Value;

use crate::engine::Anonymizer;

pub(crate) fn scrub_value(anon: &mut Anonymizer, value: &mut Value) {
    scrub_with_key(anon, None, value);
}

fn scrub_with_key(anon: &mut Anonymizer, key: Option<&str>, value: &mut Value) {
    match value {
        Value::String(s) => {
            if key.map(is_skip_key).unwrap_or(false) {
                return;
            }
            let cleaned = anon.scrub_text(s);
            *s = cleaned;
        }
        Value::Array(arr) => {
            // Array elements inherit the parent key so `versions: ["1.2.3.4"]`
            // is skipped the same way a scalar version field is.
            for v in arr.iter_mut() {
                scrub_with_key(anon, key, v);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                scrub_with_key(anon, Some(k.as_str()), v);
            }
        }
        _ => {}
    }
}

/// Keys whose values are version/release identifiers (non-PII, and prone to
/// IP-vs-version false positives like a waagent version `2.14.0.1`). Matched by
/// suffix so `agentVersion`, `kernelVersion`, `osRelease`, … are covered while
/// unrelated keys like `conversionHost` are not.
fn is_skip_key(k: &str) -> bool {
    let kl = k.to_ascii_lowercase();
    kl == "version"
        || kl.ends_with("version")
        || kl.ends_with("_version")
        || kl == "release"
        || kl.ends_with("release")
}
