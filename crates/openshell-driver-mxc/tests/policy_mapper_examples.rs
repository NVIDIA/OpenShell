// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Parity/invariant tests for the embedded coarse map over the repository's
//! example policies.
//!
//! Windows-only: the embedded mapper API is gated on `target_os = "windows"`,
//! so this whole file compiles to nothing elsewhere and runs in full on a
//! Windows test lane.
//!
//! Byte-for-byte parity with the previous raw-YAML mapper is intentionally
//! *not* asserted: routing through the canonical typed `SandboxPolicy`
//! normalizes ports and uses an unordered proto map (we sort keys). Instead we
//! assert the substantive invariants — filesystem fidelity, the host allowlist,
//! deny-by-default, and that broadening features are flagged as losses.

#![cfg(target_os = "windows")]

use std::path::{Path, PathBuf};

use openshell_driver_mxc::{MxcMappingOptions, map_to_mxc, split_policy};
use openshell_policy::{parse_sandbox_policy, serialize_sandbox_policy, validate_sandbox_policy};
use serde_json::Value;

fn examples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn discover(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            discover(&path, out);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && name.contains("policy")
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("yaml"))
        {
            out.push(path);
        }
    }
}

fn str_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn proxy_addr() -> std::net::SocketAddr {
    "127.0.0.1:18080".parse().unwrap()
}

#[test]
fn all_example_policies_map_with_invariants() {
    let root = examples_root();
    let mut policies = Vec::new();
    discover(&root, &mut policies);
    policies.sort();
    assert!(
        !policies.is_empty(),
        "no example policies found under {}",
        root.display()
    );

    for path in &policies {
        let yaml = std::fs::read_to_string(path).expect("read policy");
        let policy = parse_sandbox_policy(&yaml)
            .unwrap_or_else(|e| panic!("parse {} failed: {e}", path.display()));

        let result = map_to_mxc(&policy, &MxcMappingOptions::default());
        let cfg = &result.config;

        // Deny-by-default network posture is always emitted.
        assert_eq!(
            cfg["network"]["defaultPolicy"],
            "block",
            "{} must emit defaultPolicy=block",
            path.display()
        );

        // Filesystem fidelity: read_write / read_only copied exactly.
        if let Some(fs) = &policy.filesystem {
            assert_eq!(
                str_list(&cfg["filesystem"]["readwritePaths"]),
                fs.read_write,
                "readwrite mismatch for {}",
                path.display()
            );
            assert_eq!(
                str_list(&cfg["filesystem"]["readonlyPaths"]),
                fs.read_only,
                "readonly mismatch for {}",
                path.display()
            );
        }

        // Every non-wildcard endpoint host appears in allowedHosts.
        let allowed = str_list(&cfg["network"]["allowedHosts"]);
        for rule in policy.network_policies.values() {
            for ep in &rule.endpoints {
                if !ep.host.is_empty() && !ep.host.contains('*') {
                    assert!(
                        allowed.contains(&ep.host),
                        "{} missing host {} in allowedHosts",
                        path.display(),
                        ep.host
                    );
                }
            }
        }

        // allowedHosts is deduplicated.
        let mut sorted = allowed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            allowed.len(),
            "duplicate hosts for {}",
            path.display()
        );

        // Deterministic: mapping twice yields identical config.
        let again = map_to_mxc(&policy, &MxcMappingOptions::default());
        assert_eq!(
            result.config,
            again.config,
            "non-deterministic for {}",
            path.display()
        );
    }
}

#[test]
fn all_example_policies_split_with_lossless_invariants() {
    let root = examples_root();
    let mut policies = Vec::new();
    discover(&root, &mut policies);
    policies.sort();
    assert!(
        !policies.is_empty(),
        "no example policies found under {}",
        root.display()
    );

    for path in &policies {
        let yaml = std::fs::read_to_string(path).expect("read policy");
        let policy = parse_sandbox_policy(&yaml)
            .unwrap_or_else(|e| panic!("parse {} failed: {e}", path.display()));
        let opts = MxcMappingOptions {
            containment: "processcontainer".to_owned(),
            proxy_redirect: Some(proxy_addr()),
            ..Default::default()
        };
        let result = split_policy(&policy, &opts)
            .unwrap_or_else(|| panic!("split returned None for {}", path.display()));
        let cfg = &result.mxc_config;

        assert_eq!(
            result.proxy_policy.network_policies,
            policy.network_policies,
            "proxy_policy must carry network rules verbatim for {}",
            path.display()
        );
        assert_eq!(
            result.proxy_policy.version,
            policy.version,
            "proxy_policy must preserve version for {}",
            path.display()
        );
        validate_sandbox_policy(&result.proxy_policy).unwrap_or_else(|e| {
            panic!("trimmed policy must validate for {}: {e:?}", path.display())
        });
        let serialized = serialize_sandbox_policy(&result.proxy_policy)
            .unwrap_or_else(|e| panic!("serialize trimmed policy for {}: {e}", path.display()));
        let round_trip = parse_sandbox_policy(&serialized)
            .unwrap_or_else(|e| panic!("parse trimmed round-trip for {}: {e}", path.display()));
        assert_eq!(
            round_trip,
            result.proxy_policy,
            "trimmed policy must round-trip for {}",
            path.display()
        );

        if let Some(fs) = &policy.filesystem {
            assert_eq!(
                str_list(&cfg["filesystem"]["readwritePaths"]),
                fs.read_write,
                "split readwrite mismatch for {}",
                path.display()
            );
            assert_eq!(
                str_list(&cfg["filesystem"]["readonlyPaths"]),
                fs.read_only,
                "split readonly mismatch for {}",
                path.display()
            );
        } else {
            assert!(str_list(&cfg["filesystem"]["readwritePaths"]).is_empty());
            assert!(str_list(&cfg["filesystem"]["readonlyPaths"]).is_empty());
        }

        assert_eq!(cfg["network"]["defaultPolicy"], "block");
        assert!(str_list(&cfg["network"]["allowedHosts"]).is_empty());
        // MXC 0.6.0-alpha accepts only {"proxy": {"localhost": N}}.
        assert_eq!(cfg["network"]["proxy"]["localhost"], 18080);
        assert!(cfg["network"]["proxy"].get("host").is_none());
        assert!(cfg["network"]["proxy"].get("port").is_none());
        assert!(
            result.loss.iter().all(|i| i.severity != "error"),
            "processcontainer split must not emit error losses for {}: {:?}",
            path.display(),
            result.loss
        );
    }
}

#[test]
fn quickstart_coarse_mapping() {
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");
    let result = map_to_mxc(&policy, &MxcMappingOptions::default());
    let cfg = &result.config;

    assert_eq!(
        str_list(&cfg["network"]["allowedHosts"]),
        vec!["api.github.com".to_owned()]
    );
    assert_eq!(
        str_list(&cfg["filesystem"]["readwritePaths"]),
        vec!["/sandbox", "/tmp", "/dev/null"]
    );
    assert_eq!(cfg["containment"], "bubblewrap");

    // The github_api endpoint loses port, protocol, access, and binary scope.
    let has = |severity: &str, needle: &str| {
        result
            .loss
            .iter()
            .any(|i| i.severity == severity && i.path.contains(needle))
    };
    assert!(has("error", "endpoints[0].port"), "expected port loss");
    assert!(
        has("error", "endpoints[0].protocol"),
        "expected protocol loss"
    );
    assert!(
        has("error", "endpoints[0].access"),
        "expected access preset loss"
    );
    assert!(
        has("error", "binaries[0].path"),
        "expected binary-scope loss"
    );
}

#[test]
fn split_policy_routes_network_to_proxy() {
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");

    let opts = MxcMappingOptions {
        containment: "processcontainer".to_owned(),
        proxy_redirect: Some("127.0.0.2:8080".parse().unwrap()),
        ..Default::default()
    };
    let result = split_policy(&policy, &opts).expect("split_policy returns Some when addr is set");
    let cfg = &result.mxc_config;

    // Proxy redirect is emitted. 127.0.0.2 is not the loopback 127.0.0.1 so
    // the mapper records an error loss and omits the proxy block entirely.
    // (MXC 0.6.0-alpha can only encode {"localhost": N}; non-127.0.0.1 is
    // not representable.)
    assert!(
        cfg["network"].get("proxy").is_none() || cfg["network"]["proxy"].is_null(),
        "non-127.0.0.1 redirect must NOT produce a proxy block: {:?}",
        cfg["network"].get("proxy")
    );
    let has_proxy_loss = result
        .loss
        .iter()
        .any(|i| i.path == "network.proxy" && i.severity == "error");
    assert!(
        has_proxy_loss,
        "non-127.0.0.1 redirect must produce an error loss item"
    );

    // Direct egress is blocked; allowedHosts is empty (proxy enforces the list).
    assert_eq!(cfg["network"]["defaultPolicy"], "block");
    assert!(
        str_list(&cfg["network"]["allowedHosts"]).is_empty(),
        "split path must not populate allowedHosts"
    );

    // Filesystem grants are preserved unchanged.
    assert_eq!(
        str_list(&cfg["filesystem"]["readwritePaths"]),
        policy.filesystem.as_ref().unwrap().read_write
    );

    // Network policy is returned verbatim for the proxy.
    assert_eq!(
        result.proxy_policy.network_policies, policy.network_policies,
        "proxy_policy must carry all network rules verbatim"
    );
    assert_eq!(result.proxy_policy.version, policy.version);
    assert!(
        result.proxy_policy.filesystem.is_none(),
        "proxy_policy must not carry filesystem rules"
    );

    // No binary-scope, port, or protocol losses — those are delegated to the proxy.
    let net_losses: Vec<_> = result
        .loss
        .iter()
        .filter(|i| i.path.starts_with("network_policies") && i.severity != "info")
        .collect();
    assert!(
        net_losses.is_empty(),
        "split path must not generate lossy network items: {net_losses:?}"
    );
    assert!(result.loss.iter().any(|i| {
        i.path == "network_policies" && i.severity == "info" && i.message.contains("delegated")
    }));
}

#[test]
fn split_policy_returns_none_without_proxy_addr() {
    let opts = MxcMappingOptions::default();
    let policy = parse_sandbox_policy("").unwrap_or_default();
    assert!(
        split_policy(&policy, &opts).is_none(),
        "split_policy must return None when proxy_redirect is not set"
    );
}

#[test]
fn split_policy_deterministic() {
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");
    let opts = MxcMappingOptions {
        containment: "processcontainer".to_owned(),
        proxy_redirect: Some("127.0.0.1:9999".parse().unwrap()),
        ..Default::default()
    };
    let a = split_policy(&policy, &opts).unwrap();
    let b = split_policy(&policy, &opts).unwrap();
    assert_eq!(
        a.mxc_config, b.mxc_config,
        "split_policy must be deterministic"
    );
}

#[test]
fn split_policy_rejects_proxy_redirect_on_isolation_session() {
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");
    let opts = MxcMappingOptions {
        containment: "isolation_session".to_owned(),
        proxy_redirect: Some(proxy_addr()),
        ..Default::default()
    };
    let result = split_policy(&policy, &opts).unwrap();
    let errors: Vec<_> = result
        .loss
        .iter()
        .filter(|i| i.severity == "error")
        .collect();
    assert_eq!(
        errors.len(),
        1,
        "expected one containment error: {errors:?}"
    );
    assert_eq!(errors[0].path, "containment");
    assert!(errors[0].message.contains("MXC M1"));
    assert!(result.mxc_config["network"].get("proxy").is_none());
}

#[test]
fn network_only_policy_has_empty_filesystem() {
    // policy-advisor is a network-only seed (no filesystem_policy).
    let path = examples_root().join("policy-advisor/sandbox-policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read policy-advisor");
    let policy = parse_sandbox_policy(&yaml).expect("parse policy-advisor");
    let result = map_to_mxc(&policy, &MxcMappingOptions::default());
    let cfg = &result.config;

    assert!(str_list(&cfg["filesystem"]["readwritePaths"]).is_empty());
    assert!(str_list(&cfg["filesystem"]["readonlyPaths"]).is_empty());
    assert_eq!(
        str_list(&cfg["network"]["allowedHosts"]),
        vec!["api.anthropic.com".to_owned()]
    );
}

// ── New tests: proxy JSON shape and non-127.0.0.1 guard ──────────────────────

#[test]
fn split_with_loopback_addr_emits_localhost_port_shape() {
    // MXC 0.6.0-alpha accepts ONLY {"proxy": {"localhost": N}}.
    // Verified against the real wxc-exec 0.6.0-alpha binary via --dry-run.
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");

    let opts = MxcMappingOptions {
        containment: "processcontainer".to_owned(),
        proxy_redirect: Some("127.0.0.1:18080".parse().unwrap()),
        ..Default::default()
    };
    let result = split_policy(&policy, &opts).expect("split returns Some");
    let cfg = &result.mxc_config;

    assert_eq!(
        cfg["network"]["proxy"]["localhost"], 18080,
        "proxy must use {{\"localhost\": N}} shape"
    );
    assert!(
        cfg["network"]["proxy"].get("host").is_none(),
        "proxy must not contain 'host' key"
    );
    assert!(
        cfg["network"]["proxy"].get("port").is_none(),
        "proxy must not contain 'port' key"
    );
    // No error losses — 127.0.0.1 is representable.
    assert!(
        result.loss.iter().all(|i| i.severity != "error"),
        "127.0.0.1 proxy must not emit error losses: {:?}",
        result
            .loss
            .iter()
            .filter(|i| i.severity == "error")
            .collect::<Vec<_>>()
    );
}

#[test]
fn split_with_non_loopback_addr_emits_error_loss_and_no_proxy_block() {
    // Non-127.0.0.1 redirect addresses are not representable in MXC 0.6.0-alpha.
    // The mapper must record an error loss and omit the proxy block.
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");

    let opts = MxcMappingOptions {
        containment: "processcontainer".to_owned(),
        proxy_redirect: Some("127.0.0.5:18080".parse().unwrap()),
        ..Default::default()
    };
    let result = split_policy(&policy, &opts).expect("split returns Some");
    let cfg = &result.mxc_config;

    // Proxy block must be absent.
    assert!(
        cfg["network"].get("proxy").is_none() || cfg["network"]["proxy"].is_null(),
        "non-127.0.0.1 redirect must not produce a proxy block: {:?}",
        cfg["network"].get("proxy")
    );

    // An error loss for "network.proxy" must be present.
    let proxy_loss = result
        .loss
        .iter()
        .find(|i| i.path == "network.proxy" && i.severity == "error");
    assert!(
        proxy_loss.is_some(),
        "non-127.0.0.1 redirect must produce an error loss item on network.proxy: {:?}",
        result.loss
    );
    let loss = proxy_loss.unwrap();
    assert_eq!(loss.openshell_feature, "per-sandbox egress attribution");
    assert!(
        loss.message.contains("localhost"),
        "loss message should mention 'localhost': {}",
        loss.message
    );
}
