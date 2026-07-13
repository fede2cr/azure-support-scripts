//! GUID / UUID recognizer (covers Azure subscription & tenant IDs and any other
//! canonical-form GUID).

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn guid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
        )
        .unwrap()
    })
}

pub struct GuidRecognizer;
impl GuidRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for GuidRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        guid_re()
            .find_iter(text)
            .map(|m| RecognizerResult::new(m.start(), m.end(), EntityType::Guid, 0.85))
            .collect()
    }
}
