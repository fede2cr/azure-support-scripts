//! MAC address recognizer. Matches 6-group colon- or hyphen-separated hex.

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b").unwrap()
    })
}

pub struct MacRecognizer;
impl MacRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for MacRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        mac_re()
            .find_iter(text)
            .map(|m| RecognizerResult::new(m.start(), m.end(), EntityType::Mac, 0.9))
            .collect()
    }
}
