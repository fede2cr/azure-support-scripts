//! Transform primitives ("operators" in Presidio terms): pure token formatting
//! plus small helpers. All stateful bookkeeping (indices, subnet labels) lives
//! in [`crate::engine`]; these functions only format the final replacement text.

use std::sync::OnceLock;

use regex::Regex;

/// `[[IPv4|net-A|h1]]` (optionally suffixed with the preserved `/NN` prefix).
pub fn ip_token(kind: &str, label_letters: &str, host: usize, prefix: Option<u8>) -> String {
    let mut t = format!("[[{kind}|net-{label_letters}|h{host}]]");
    if let Some(p) = prefix {
        t.push('/');
        t.push_str(&p.to_string());
    }
    t
}

/// `[[MAC|00:0d:3a|dev1]]` — OUI preserved, NIC portion pseudonymized.
pub fn mac_token(oui: &str, device: usize) -> String {
    format!("[[MAC|{oui}|dev{device}]]")
}

/// `[[GUID-A]]`, `[[GUID-B]]`, … — labeled + base-26 letter tag (the same
/// scheme as subnet labels), so distinct values get distinct, correlatable tags
/// while the literal value is hidden. Used for GUID, EMAIL, HOST, and
/// AZURE_NAME pseudonyms.
pub fn lettered_token(label: &str, letters: &str) -> String {
    format!("[[{label}-{letters}]]")
}

/// Full-redaction sentinel for secrets/keys/tokens.
pub const SECRET_TOKEN: &str = "[[SECRET]]";

fn guid_only_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$",
        )
        .unwrap()
    })
}

/// Whether an entire string is a canonical-form GUID.
pub fn is_guid(s: &str) -> bool {
    guid_only_re().is_match(s)
}
