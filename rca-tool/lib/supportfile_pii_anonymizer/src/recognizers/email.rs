//! Email address recognizer.

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()
    })
}

pub struct EmailRecognizer;
impl EmailRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for EmailRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        email_re()
            .find_iter(text)
            .map(|m| RecognizerResult::new(m.start(), m.end(), EntityType::Email, 0.85))
            .collect()
    }
}
