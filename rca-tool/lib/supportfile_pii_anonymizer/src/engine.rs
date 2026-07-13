//! The anonymization engine: recognizer orchestration, overlap resolution, and
//! the run-scoped mapping store that guarantees deterministic,
//! correlation-preserving output.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use regex::Regex;

use crate::allowlist::{is_ipv4_allowlisted, is_ipv6_allowlisted};
use crate::config::Config;
use crate::ip::{ipv4_network, ipv6_network, subnet_letters};
use crate::recognizers::ip::{split_prefix, split_zone};
use crate::recognizers::{build_recognizers, EntityType, Recognizer, RecognizerResult};
use crate::strategy;

/// Run-scoped state ensuring the same original value always maps to the same
/// token (correlation preservation) for the life of one [`Anonymizer`].
#[derive(Default)]
struct MappingStore {
    /// Subnet key (`network`, `prefix`) -> shared label index (0 => "A").
    subnet_v4: HashMap<(u32, u8), usize>,
    subnet_v6: HashMap<(u128, u8), usize>,
    /// Next subnet label index (shared across v4/v6 so labels are globally unique).
    next_subnet: usize,
    /// Per-subnet-label host maps: label index -> (normalized addr -> host index).
    hosts: HashMap<usize, HashMap<String, usize>>,
    /// Explicit prefix hints for specific addresses (from CIDR context / `hint_cidr`).
    ip_prefix_hints: HashMap<String, u8>,
    /// Generic per-entity pseudonym indices: (entity, normalized value) -> index.
    pseudonyms: HashMap<(EntityType, String), usize>,
    /// Per-entity monotonic counters backing `pseudonyms`.
    counters: HashMap<EntityType, usize>,
    /// MAC device indices scoped per OUI: oui -> (normalized mac -> device index).
    mac_devices: HashMap<String, HashMap<String, usize>>,
    /// Azure name indices (resource groups / instance names).
    azure_names: HashMap<String, usize>,
    next_azure_name: usize,
}

impl MappingStore {
    /// Stable 1-based index for `value` under `entity`.
    fn pseudonym(&mut self, entity: EntityType, value: &str) -> usize {
        let key = (entity, value.to_string());
        if let Some(&i) = self.pseudonyms.get(&key) {
            return i;
        }
        let c = self.counters.entry(entity).or_insert(0);
        *c += 1;
        let idx = *c;
        self.pseudonyms.insert(key, idx);
        idx
    }

    /// Shared subnet label index for an IPv4 network.
    fn subnet_label_v4(&mut self, network: u32, prefix: u8) -> usize {
        if let Some(&l) = self.subnet_v4.get(&(network, prefix)) {
            return l;
        }
        let l = self.next_subnet;
        self.next_subnet += 1;
        self.subnet_v4.insert((network, prefix), l);
        l
    }

    /// Shared subnet label index for an IPv6 network.
    fn subnet_label_v6(&mut self, network: u128, prefix: u8) -> usize {
        if let Some(&l) = self.subnet_v6.get(&(network, prefix)) {
            return l;
        }
        let l = self.next_subnet;
        self.next_subnet += 1;
        self.subnet_v6.insert((network, prefix), l);
        l
    }

    /// Stable 1-based host index for `addr` within subnet `label`.
    fn host_index(&mut self, label: usize, addr: &str) -> usize {
        let map = self.hosts.entry(label).or_default();
        let next = map.len() + 1;
        *map.entry(addr.to_string()).or_insert(next)
    }

    /// Stable 1-based device index for `mac` within its `oui`.
    fn mac_index(&mut self, oui: &str, mac: &str) -> usize {
        let map = self.mac_devices.entry(oui.to_string()).or_default();
        let next = map.len() + 1;
        *map.entry(mac.to_string()).or_insert(next)
    }

    /// Stable 1-based index for an Azure resource / resource-group name.
    fn azure_name(&mut self, name: &str) -> usize {
        if let Some(&i) = self.azure_names.get(name) {
            return i;
        }
        self.next_azure_name += 1;
        let idx = self.next_azure_name;
        self.azure_names.insert(name.to_string(), idx);
        idx
    }
}

/// The public anonymizer. Construct with [`Anonymizer::new`], optionally seed
/// known CIDRs with [`Anonymizer::hint_cidr`], then scrub text or JSON.
pub struct Anonymizer {
    cfg: Config,
    recognizers: Vec<Box<dyn Recognizer>>,
    store: MappingStore,
    /// Explicitly registered hostnames (lowercased, longest-first) that must be
    /// scrubbed wherever they appear as whole words — e.g. the host parsed from
    /// the sosreport/supportconfig archive name, which also shows up in log
    /// lines beyond the `source_path` root directory.
    known_hosts: Vec<String>,
    known_host_re: Option<Regex>,
}

impl Anonymizer {
    /// Build an anonymizer with the given configuration.
    pub fn new(cfg: Config) -> Self {
        let recognizers = build_recognizers(&cfg);
        Self {
            cfg,
            recognizers,
            store: MappingStore::default(),
            known_hosts: Vec::new(),
            known_host_re: None,
        }
    }

    /// Register a hostname to scrub wherever it appears as a whole word. Intended
    /// for the host extracted from the archive filename / root directory (see
    /// [`crate::extract_archive_hostname`]). Ignores empty, too-short, purely
    /// numeric, or `localhost` values.
    pub fn add_known_hostname(&mut self, host: &str) {
        let h = host.trim().to_lowercase();
        if h.len() < 2 || h == "localhost" || h.bytes().all(|b| b.is_ascii_digit()) {
            return;
        }
        if self.known_hosts.iter().any(|k| k == &h) {
            return;
        }
        self.known_hosts.push(h);
        // Longest first so an FQDN is preferred over its short label.
        self.known_hosts.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let alt = self
            .known_hosts
            .iter()
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|");
        self.known_host_re = Regex::new(&format!(r"(?i)\b(?:{alt})\b")).ok();
    }

    /// Register the true prefix length for an address so later bare occurrences
    /// of it group into the correct subnet. Ignores unparseable input.
    pub fn hint_cidr(&mut self, ip: &str, prefix: u8) {
        if let Ok(a) = ip.parse::<Ipv4Addr>() {
            self.store.ip_prefix_hints.insert(a.to_string(), prefix.min(32));
        } else if let Ok(a) = ip.parse::<Ipv6Addr>() {
            self.store
                .ip_prefix_hints
                .insert(a.to_string(), prefix.min(128));
        }
    }

    /// Anonymize all recognized entities in `text`, returning a new string.
    pub fn scrub_text(&mut self, text: &str) -> String {
        let spans = resolve_overlaps(self.recognize_all(text));
        if spans.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for s in spans {
            if s.start < cursor {
                continue; // defensive: skip any residual overlap
            }
            out.push_str(&text[cursor..s.start]);
            let matched = &text[s.start..s.end];
            out.push_str(&self.apply(s.entity, matched));
            cursor = s.end;
        }
        out.push_str(&text[cursor..]);
        out
    }

    fn recognize_all(&self, text: &str) -> Vec<RecognizerResult> {
        let mut all = Vec::new();
        for r in &self.recognizers {
            all.extend(r.recognize(text));
        }
        // Registered archive/known hostnames, matched as whole words.
        if let Some(re) = &self.known_host_re {
            for m in re.find_iter(text) {
                all.push(RecognizerResult::new(
                    m.start(),
                    m.end(),
                    EntityType::Hostname,
                    0.8,
                ));
            }
        }
        all
    }

    /// Apply the type-appropriate strategy to one matched span.
    fn apply(&mut self, entity: EntityType, matched: &str) -> String {
        match entity {
            EntityType::Ipv4 => self.anon_ipv4(matched),
            EntityType::Ipv6 => self.anon_ipv6(matched),
            EntityType::Mac => self.anon_mac(matched),
            EntityType::Guid => self.pseudonym_token(EntityType::Guid, "GUID", &matched.to_lowercase()),
            EntityType::Email => {
                self.pseudonym_token(EntityType::Email, "EMAIL", &matched.to_lowercase())
            }
            EntityType::Hostname => {
                self.pseudonym_token(EntityType::Hostname, "HOST", &matched.to_lowercase())
            }
            EntityType::AzureResourceId => self.anon_azure_id(matched),
            EntityType::Secret => strategy::SECRET_TOKEN.to_string(),
        }
    }

    /// Stable, letter-labeled pseudonym token (e.g. `[[GUID-A]]`, `[[HOST-B]]`).
    /// Uses the same base-26 labelling as subnet labels so distinct values stay
    /// distinguishable and correlatable across the document while the literal
    /// value is hidden.
    fn pseudonym_token(&mut self, entity: EntityType, label: &str, value_lower: &str) -> String {
        let idx = self.store.pseudonym(entity, value_lower);
        strategy::lettered_token(label, &subnet_letters(idx - 1))
    }

    /// Letter-labeled token for an Azure resource / resource-group name
    /// (e.g. `[[AZURE_NAME-A]]`). Backed by a dedicated name store.
    fn azure_name_token(&mut self, name_lower: &str) -> String {
        let idx = self.store.azure_name(name_lower);
        strategy::lettered_token("AZURE_NAME", &subnet_letters(idx - 1))
    }

    fn anon_ipv4(&mut self, matched: &str) -> String {
        let (addr_s, prefix_opt) = split_prefix(matched);
        let addr: Ipv4Addr = match addr_s.parse() {
            Ok(a) => a,
            Err(_) => return matched.to_string(),
        };
        if is_ipv4_allowlisted(addr, &self.cfg) {
            return matched.to_string();
        }
        let norm = addr.to_string();
        if let Some(p) = prefix_opt {
            self.store.ip_prefix_hints.insert(norm.clone(), p.min(32));
        }
        let prefix = prefix_opt
            .or_else(|| self.store.ip_prefix_hints.get(&norm).copied())
            .unwrap_or(self.cfg.ipv4_default_prefix)
            .min(32);
        let net = ipv4_network(addr, prefix);
        let label = self.store.subnet_label_v4(net, prefix);
        let host = self.store.host_index(label, &norm);
        strategy::ip_token("IPv4", &subnet_letters(label), host, prefix_opt)
    }

    fn anon_ipv6(&mut self, matched: &str) -> String {
        let (addr_s, prefix_opt) = split_prefix(matched);
        let core = split_zone(addr_s);
        let addr: Ipv6Addr = match core.parse() {
            Ok(a) => a,
            Err(_) => return matched.to_string(),
        };
        if is_ipv6_allowlisted(addr) {
            return matched.to_string();
        }
        let norm = addr.to_string();
        if let Some(p) = prefix_opt {
            self.store.ip_prefix_hints.insert(norm.clone(), p.min(128));
        }
        let prefix = prefix_opt
            .or_else(|| self.store.ip_prefix_hints.get(&norm).copied())
            .unwrap_or(self.cfg.ipv6_default_prefix)
            .min(128);
        let net = ipv6_network(addr, prefix);
        let label = self.store.subnet_label_v6(net, prefix);
        let host = self.store.host_index(label, &norm);
        strategy::ip_token("IPv6", &subnet_letters(label), host, prefix_opt)
    }

    fn anon_mac(&mut self, matched: &str) -> String {
        let sep = if matched.contains(':') { ':' } else { '-' };
        let parts: Vec<&str> = matched.split(sep).collect();
        if parts.len() != 6 {
            return matched.to_string();
        }
        let oui = parts[..3].join(&sep.to_string());
        let idx = self.store.mac_index(&oui.to_lowercase(), &matched.to_lowercase());
        strategy::mac_token(&oui, idx)
    }

    /// Structural scrub of an ARM resource id: keep the provider/type skeleton,
    /// replace the subscription GUID, resource-group name, and instance names.
    fn anon_azure_id(&mut self, matched: &str) -> String {
        let segments: Vec<&str> = matched.split('/').collect();
        let mut out: Vec<String> = Vec::with_capacity(segments.len());
        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                out.push(String::new());
                continue;
            }
            let prev = if i >= 1 { segments[i - 1] } else { "" };
            let prev2 = if i >= 2 { segments[i - 2] } else { "" };
            if strategy::is_guid(seg) {
                out.push(self.pseudonym_token(EntityType::Guid, "GUID", &seg.to_lowercase()));
            } else if prev.eq_ignore_ascii_case("resourceGroups") {
                out.push(self.azure_name_token(&seg.to_lowercase()));
            } else if prev2.contains('.') && !prev.contains('.') {
                // `prev2` is a provider namespace (e.g. Microsoft.Compute),
                // `prev` is the resource type, so `seg` is an instance name.
                out.push(self.azure_name_token(&seg.to_lowercase()));
            } else {
                out.push((*seg).to_string());
            }
        }
        out.join("/")
    }

    /// Recursively anonymize every string leaf of a JSON value in place.
    #[cfg(feature = "serde_json")]
    pub fn scrub_json(&mut self, value: &mut serde_json::Value) {
        crate::json::scrub_value(self, value);
    }
}

/// Resolve overlapping spans: keep the strongest, longest, earliest, dropping
/// any span that overlaps one already chosen.
fn resolve_overlaps(mut spans: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    // Sort by start asc, then longer first, then higher score first.
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.span_len().cmp(&a.span_len()))
            .then(b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
    });
    let mut chosen: Vec<RecognizerResult> = Vec::new();
    let mut last_end = 0usize;
    for s in spans {
        if s.start >= last_end {
            last_end = s.end;
            chosen.push(s);
        }
    }
    chosen
}
