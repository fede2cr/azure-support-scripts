//! Recognizes the hostname embedded in a sosreport / supportconfig archive
//! root directory (or the archive filename) and pseudonymizes it.
//!
//! sosreport directories look like `sosreport-<host>-<caseid>-<date>-<hash>`
//! and supportconfig directories like `scc_<host>_<date>_<time>` /
//! `nts_<host>_<date>_<time>`. That host token otherwise leaks on **every**
//! record's `source_path`, and often in the archive filename, so it is scrubbed
//! wherever it appears — including when the host is an FQDN whose registrable
//! domain is public (the *full* name still identifies the machine, so the
//! public-domain allowlist used by the generic hostname recognizer does not
//! apply here).

use std::sync::OnceLock;

use regex::Regex;

use super::{EntityType, Recognizer, RecognizerResult};

/// Regexes matching a sosreport / supportconfig archive root, each capturing the
/// host in a named `host` group. Anchored on the distinctive `sosreport-` /
/// `scc_` / `nts_` prefix (at a word boundary) so they also match a root
/// directory embedded at the start of a `source_path` or inside a log line.
fn archive_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            // sosreport-<host>-<digit…>  (caseid/date follow the host)
            Regex::new(r"\bsosreport-(?P<host>[A-Za-z0-9][A-Za-z0-9.-]*?)-\d").unwrap(),
            // scc_<host>_<6-8 digit date>  /  nts_<host>_<date>
            Regex::new(r"\b(?:scc|nts)_(?P<host>[A-Za-z0-9][A-Za-z0-9.-]*?)_\d{6,8}").unwrap(),
        ]
    })
}

/// Extract the hostname from a sosreport/supportconfig archive filename or a
/// path whose root directory follows those conventions. Returns `None` when the
/// string does not match a known archive-root pattern.
pub fn extract_archive_hostname(s: &str) -> Option<String> {
    for re in archive_res() {
        if let Some(caps) = re.captures(s) {
            if let Some(h) = caps.name("host") {
                if h.as_str().len() >= 2 {
                    return Some(h.as_str().to_string());
                }
            }
        }
    }
    None
}

pub struct ArchiveRootRecognizer;
impl ArchiveRootRecognizer {
    pub fn new() -> Self {
        Self
    }
}
impl Recognizer for ArchiveRootRecognizer {
    fn recognize(&self, text: &str) -> Vec<RecognizerResult> {
        let mut out = Vec::new();
        for re in archive_res() {
            for caps in re.captures_iter(text) {
                if let Some(h) = caps.name("host") {
                    if h.as_str().len() >= 2 {
                        // Higher score than the generic FQDN recognizer (0.5) so
                        // the host span wins overlap resolution.
                        out.push(RecognizerResult::new(
                            h.start(),
                            h.end(),
                            EntityType::Hostname,
                            0.8,
                        ));
                    }
                }
            }
        }
        out
    }
}
