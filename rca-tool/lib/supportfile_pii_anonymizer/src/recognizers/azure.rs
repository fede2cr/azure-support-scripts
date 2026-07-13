//! Azure Resource Manager resource-ID recognizer.
//!
//! Matches an ARM resource id starting at `/subscriptions/<guid>` and running
//! to the next whitespace/quote. The whole id is captured as one high-score
//! span so it wins overlap resolution against the GUID recognizer that would
//! otherwise match the subscription id inside it; the structural scrub in
//! [`crate::strategy`] then keeps the provider/type skeleton while replacing the
//! subscription GUID, resource-group name, and instance names.

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn resource_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:/[^\s"']+)*"#,
        )
        .unwrap()
    })
}

pub struct AzureResourceIdRecognizer;
impl AzureResourceIdRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for AzureResourceIdRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        resource_id_re()
            .find_iter(text)
            .map(|m| RecognizerResult::new(m.start(), m.end(), EntityType::AzureResourceId, 0.9))
            .collect()
    }
}
