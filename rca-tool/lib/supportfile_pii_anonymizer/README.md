# supportfile_pii_anonymizer

Offline, deterministic anonymization of PII and environment-identifying data for
Azure & Linux diagnostics (sosreport / supportconfig). Pure Rust, WASM-friendly,
no NLP/ML, no network calls.

The design mirrors [Microsoft Presidio](https://github.com/microsoft/presidio)'s
conceptual split — **recognizers** detect spans, **operators/strategies**
transform them — but runs inline in Rust with no spaCy/NER engine.

## Highlights

- **Deterministic & correlation-preserving.** Within one `Anonymizer` instance
  the same original value always maps to the same token, so relationships
  survive (same host → same pseudonym, same GUID → same index).
- **Subnet-preserving IPs.** Two addresses on the same subnet map to the same
  `net-*` label, keeping topology visible without exposing real addresses.
  Loopback and well-known Azure infra addresses (IMDS `169.254.169.254`,
  WireServer `168.63.129.16`) are left intact.
- **Fail-safe secrets.** Passwords/keys/tokens/PEM blocks are fully redacted.

## Usage

```rust
use supportfile_pii_anonymizer::{Anonymizer, Config};

let mut anon = Anonymizer::new(Config::default());

// Optionally seed known CIDRs so bare occurrences group correctly:
anon.hint_cidr("10.1.2.34", 24);

let clean = anon.scrub_text("node hana01 at 10.1.2.34 failed; peer 10.1.2.99");
// -> "... at [[IPv4|net-A|h1]] failed; peer [[IPv4|net-A|h2]]"

// Structured data (feature = "serde_json", on by default):
let mut v = serde_json::json!({ "rawLine": "10.9.0.5 down", "line": 12 });
anon.scrub_json(&mut v); // string leaves scrubbed, numbers untouched
```

## Token formats

| Entity | Token |
|---|---|
| IPv4 / IPv6 | `[[IPv4\|net-A\|h1]]` (optional `/NN` preserved) |
| MAC | `[[MAC\|00:0d:3a\|dev1]]` (OUI preserved) |
| GUID / subscription / tenant | `[[GUID-A]]` |
| Email (local part **and** domain) | `[[EMAIL-A]]` |
| Hostname (FQDN, or archive-root host) | `[[HOST-A]]` |
| Azure resource / RG name | `[[AZURE_NAME-A]]` |
| Secret / key / token | `[[SECRET]]` |

All pseudonyms use the same base-26 letter labelling (`-A`, `-B`, … `-AA`) as the
subnet labels, so distinct values stay distinguishable and correlatable while the
literal value is hidden.

The hostname embedded in a sosreport / supportconfig archive name or root
directory (`sosreport-<host>-…`, `scc_<host>_<date>_…`, `nts_<host>_<date>_…`) is
detected and scrubbed wherever it appears — including every record's
`source_path` and log lines — via `extract_archive_hostname` +
`Anonymizer::add_known_hostname`.

## Features

- `serde_json` (default) — enables `Anonymizer::scrub_json`.
- `azure` (default) — Azure resource-ID recognizer.

Build without them for a minimal core: `default-features = false`.

## License

MIT
