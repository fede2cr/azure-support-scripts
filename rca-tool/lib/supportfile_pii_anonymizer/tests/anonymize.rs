use supportfile_pii_anonymizer::{extract_archive_hostname, Anonymizer, Config};

fn anon() -> Anonymizer {
    Anonymizer::new(Config::default())
}

#[test]
fn ipv4_same_subnet_shares_label_different_subnet_differs() {
    let mut a = anon();
    let out = a.scrub_text("if0 10.1.2.34, if1 10.1.2.99, if2 10.9.0.5");
    // Same /24 -> same net label; different subnet -> different label.
    assert!(out.contains("[[IPv4|net-A|h1]]"), "{out}");
    assert!(out.contains("[[IPv4|net-A|h2]]"), "{out}");
    assert!(out.contains("[[IPv4|net-B|h1]]"), "{out}");
    assert!(!out.contains("10.1.2.34"), "{out}");
    assert!(!out.contains("10.9.0.5"), "{out}");
}

#[test]
fn ipv4_loopback_and_azure_infra_preserved() {
    let mut a = anon();
    let out = a.scrub_text("lo 127.0.0.1 imds 169.254.169.254 wire 168.63.129.16");
    assert!(out.contains("127.0.0.1"), "{out}");
    assert!(out.contains("169.254.169.254"), "{out}");
    assert!(out.contains("168.63.129.16"), "{out}");
}

#[test]
fn ipv4_preserves_cidr_suffix() {
    let mut a = anon();
    let out = a.scrub_text("addr 10.1.2.34/24");
    assert!(out.contains("[[IPv4|net-A|h1]]/24"), "{out}");
}

#[test]
fn ipv6_groups_by_64_and_preserves_loopback() {
    let mut a = anon();
    let out = a.scrub_text("a fe80::1ff:fe23:4567:890a b fe80::1ff:fe23:4567:890b lo ::1");
    assert!(out.contains("[[IPv6|net-A|h1]]"), "{out}");
    assert!(out.contains("[[IPv6|net-A|h2]]"), "{out}");
    assert!(out.contains("::1"), "{out}");
    assert!(!out.contains("890a"), "{out}");
}

#[test]
fn mac_preserves_oui() {
    let mut a = anon();
    let out = a.scrub_text("link 00:0d:3a:1b:2c:3d up");
    assert!(out.contains("[[MAC|00:0d:3a|dev1]]"), "{out}");
    assert!(!out.contains("1b:2c:3d"), "{out}");
}

#[test]
fn guid_is_indexed_and_correlated() {
    let mut a = anon();
    let g = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    let out = a.scrub_text(&format!("id {g} again {g} other 00000000-0000-0000-0000-000000000abc"));
    assert!(out.contains("[[GUID-A]]"), "{out}");
    assert!(out.contains("[[GUID-B]]"), "{out}");
    assert!(!out.contains(g), "{out}");
    // Same GUID twice -> same label.
    assert_eq!(out.matches("[[GUID-A]]").count(), 2, "{out}");
}

#[test]
fn email_is_replaced_including_domain() {
    let mut a = anon();
    let out = a.scrub_text("contact jane.doe@contoso.com now");
    assert!(out.contains("[[EMAIL-A]]"), "{out}");
    assert!(!out.contains("jane.doe@contoso.com"), "{out}");
    // The domain must be removed too — no fragment of the address survives.
    assert!(!out.contains("contoso.com"), "{out}");
    assert!(!out.contains("jane.doe"), "{out}");
}

#[test]
fn secret_value_is_redacted_key_kept() {
    let mut a = anon();
    let out = a.scrub_text("password=Sup3rSecret token: abc123XYZ");
    assert!(out.contains("password=[[SECRET]]"), "{out}");
    assert!(out.contains("token: [[SECRET]]"), "{out}");
    assert!(!out.contains("Sup3rSecret"), "{out}");
}

#[test]
fn azure_resource_id_keeps_skeleton() {
    let mut a = anon();
    let id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-sap/providers/Microsoft.Compute/virtualMachines/hana01";
    let out = a.scrub_text(id);
    assert!(out.contains("/subscriptions/[[GUID-A]]"), "{out}");
    assert!(out.contains("/resourceGroups/[[AZURE_NAME-A]]"), "{out}");
    assert!(out.contains("Microsoft.Compute/virtualMachines/[[AZURE_NAME-B]]"), "{out}");
    assert!(!out.contains("rg-sap"), "{out}");
    assert!(!out.contains("hana01"), "{out}");
}

#[test]
fn hostname_fqdn_is_pseudonymized_and_correlated() {
    let mut a = anon();
    let out = a.scrub_text("node web.contoso.com talks to web.contoso.com");
    assert_eq!(out.matches("[[HOST-A]]").count(), 2, "{out}");
    assert!(!out.contains("web.contoso.com"), "{out}");
}

#[test]
fn kernel_sysctl_variables_are_not_treated_as_hostnames() {
    let mut a = anon();
    // A representative slice of `sysctl -a` output. None of these are domains
    // and none must be altered by the hostname recognizer.
    let input = "net.core.somaxconn = 4096\n\
                 net.ipv4.tcp_congestion_control = bbr\n\
                 net.core.default_qdisc = fq\n\
                 net.ipv4.tcp_timestamps = 1\n\
                 kernel.pid_max = 32768\n\
                 kernel.sched_migration_cost_ns = 500000\n\
                 vm.swappiness = 10\n\
                 fs.file-max = 100000";
    let out = a.scrub_text(input);
    assert_eq!(out, input, "kernel variables must be untouched:\n{out}");
}

#[test]
fn filenames_public_domains_and_urls_are_kept() {
    let mut a = anon();
    // Dotted filename, an Azure storage service endpoint, and a documentation
    // URL — all diagnostic, none PII; must be preserved verbatim.
    let keep = [
        "pacemaker.log-20250101.gz",
        "md-testaccount.z45.blob.storage.azure.net",
        "https://access.redhat.com/solutions/878023",
    ];
    for k in keep {
        let out = a.scrub_text(k);
        assert_eq!(out, k, "must be kept verbatim: {out}");
    }
}

#[test]
fn internal_fqdn_is_still_scrubbed() {
    let mut a = anon();
    let out = a.scrub_text("peer db01.cluster.local is down");
    assert!(out.contains("[[HOST-A]]"), "{out}");
    assert!(!out.contains("db01.cluster.local"), "{out}");
}

#[test]
fn extract_archive_hostname_parses_sos_and_scc_names() {
    assert_eq!(
        extract_archive_hostname("sosreport-myhost-12345-2024-01-01-abcdef.tar.xz").as_deref(),
        Some("myhost")
    );
    assert_eq!(
        extract_archive_hostname("scc_db01_240101_1200").as_deref(),
        Some("db01")
    );
    assert_eq!(
        extract_archive_hostname("nts_web-fe.corp.com_240101_1200/etc/hosts").as_deref(),
        Some("web-fe.corp.com")
    );
    // No date component -> not a real archive root -> not extracted.
    assert_eq!(extract_archive_hostname("scc_test-pii/network.txt"), None);
}

#[test]
fn archive_root_hostname_is_scrubbed_in_paths_and_logs() {
    let mut a = anon();
    // The engine registers the host parsed from the archive filename.
    a.add_known_hostname("myhost");
    let out = a.scrub_text(
        "sosreport-myhost-2024-01-01/sos_commands/host/hostname; myhost kernel: booted",
    );
    assert!(!out.contains("myhost"), "{out}");
    assert!(out.contains("[[HOST-A]]"), "{out}");
    // Structural remnants of the archive dir stay (only the host is hidden).
    assert!(out.contains("sosreport-[[HOST-A]]-2024-01-01/"), "{out}");
}

#[test]
fn archive_root_recognizer_scrubs_host_without_registration() {
    let mut a = anon();
    // Even without add_known_hostname, the recognizer scrubs the host in a
    // supportconfig-style root directory embedded in a source path.
    let out = a.scrub_text("scc_secretbox_240101_1200/network.txt");
    assert!(!out.contains("secretbox"), "{out}");
    assert!(out.contains("[[HOST-A]]"), "{out}");
}

#[test]
fn version_strings_are_not_treated_as_ips() {
    let mut a = anon();
    // Free-text: a version word before the dotted number.
    let ft = "Azure Linux Agent version 2.14.0.1 started";
    assert_eq!(a.scrub_text(ft), ft, "free-text version must be kept");

    // Structured: a value under a version/release key is left untouched, while a
    // real IP under a normal key is still anonymized.
    let mut v = serde_json::json!({
        "agentVersion": "2.14.0.1",
        "kernelRelease": "5.14.0.1",
        "peerIp": "10.0.0.4"
    });
    a.scrub_json(&mut v);
    assert_eq!(v["agentVersion"], "2.14.0.1");
    assert_eq!(v["kernelRelease"], "5.14.0.1");
    assert_ne!(v["peerIp"], "10.0.0.4", "real IP must still be scrubbed");
}

#[test]
fn hint_cidr_groups_bare_ip_occurrences() {
    let mut a = anon();
    a.hint_cidr("10.5.0.10", 16);
    a.hint_cidr("10.5.9.20", 16);
    let out = a.scrub_text("x 10.5.0.10 y 10.5.9.20");
    // Both in 10.5.0.0/16 -> same net label.
    assert!(out.contains("[[IPv4|net-A|h1]]"), "{out}");
    assert!(out.contains("[[IPv4|net-A|h2]]"), "{out}");
}

#[cfg(feature = "serde_json")]
#[test]
fn scrub_json_walks_string_leaves_only() {
    let mut a = anon();
    let mut v = serde_json::json!({
        "sourceLine": 42,
        "rawLine": "node at 10.1.2.34 failed",
        "nested": { "ip": "10.1.2.99", "count": 3 },
        "list": ["10.9.0.5", 7]
    });
    a.scrub_json(&mut v);
    // Numbers and non-string leaves are preserved.
    assert_eq!(v["sourceLine"], 42);
    assert_eq!(v["nested"]["count"], 3);
    assert_eq!(v["list"][1], 7);

    // Every IP string is anonymized (object iteration order is not significant).
    let raw = v["rawLine"].as_str().unwrap();
    let nip = v["nested"]["ip"].as_str().unwrap();
    let lip = v["list"][0].as_str().unwrap();
    assert!(!raw.contains("10.1.2.34"), "{raw}");
    assert!(!nip.contains("10.1.2.99"), "{nip}");
    assert!(!lip.contains("10.9.0.5"), "{lip}");

    // The two 10.1.2.x addresses share a subnet label; 10.9.0.5 differs.
    let net = |s: &str| -> String {
        let i = s.find("net-").unwrap();
        s[i..s[i..].find('|').map(|j| i + j).unwrap()].to_string()
    };
    assert_eq!(net(raw), net(nip), "raw={raw} nip={nip}");
    assert_ne!(net(raw), net(lip), "raw={raw} lip={lip}");
}
