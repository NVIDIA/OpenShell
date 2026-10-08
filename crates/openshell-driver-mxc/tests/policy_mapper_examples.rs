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
//! assert the substantive invariants — filesystem fidelity, MXC 1.0 directional
//! networking, deny-by-default, and explicit losses for proxy-only behavior.

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

fn allowed_cidrs(config: &Value) -> Vec<String> {
    config["network"]["egress"]["allow"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|rule| rule["to"].as_array())
        .flatten()
        .filter_map(|peer| peer["cidr"].as_str().map(str::to_owned))
        .collect()
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

        // Stable MXC 1.0 directional deny-by-default posture is always emitted.
        assert_eq!(cfg["version"], "1.0.0", "{} schema", path.display());
        assert_eq!(cfg["network"]["egress"]["default"], "deny");
        assert_eq!(cfg["network"]["ingress"]["default"], "deny");
        assert_eq!(cfg["network"]["ingress"]["hostLoopback"], "deny");
        assert!(cfg["network"].get("defaultPolicy").is_none());
        assert!(cfg["network"].get("allowedHosts").is_none());
        assert!(cfg["network"].get("enforcementMode").is_none());

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

        // Hostname policies stay fail-closed and require governed egress; the
        // coarse artifact contains only numeric CIDRs.
        let allowed = allowed_cidrs(cfg);
        for rule in policy.network_policies.values() {
            for ep in &rule.endpoints {
                if !ep.host.is_empty() && ep.host.parse::<std::net::IpAddr>().is_err() {
                    assert!(
                        result.loss.iter().any(|item| {
                            item.severity == "error"
                                && item.path.contains(".host")
                                && item.message.contains(&ep.host)
                        }),
                        "{} missing DNS/glob loss for {}",
                        path.display(),
                        ep.host
                    );
                }
            }
        }

        // Directional destination CIDRs are deduplicated.
        let mut sorted = allowed.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            allowed.len(),
            "duplicate CIDRs for {}",
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
fn all_example_policies_split_with_expected_invariants() {
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

        assert_eq!(cfg["version"], "1.0.0");
        assert_eq!(cfg["network"]["egress"]["default"], "deny");
        assert_eq!(
            cfg["network"]["egress"]["allow"][0]["to"][0]["cidr"],
            "127.0.0.1/32"
        );
        assert_eq!(cfg["network"]["ingress"]["hostLoopback"], "allow");
        assert!(cfg.get("runtimeConfig").is_none());
        assert!(cfg["network"].get("proxy").is_none());
        let errors: Vec<_> = result
            .loss
            .iter()
            .filter(|item| item.severity == "error")
            .collect();
        if policy.network_middlewares.is_empty() {
            assert!(
                errors.is_empty(),
                "processcontainer split must not emit error losses for {}: {:?}",
                path.display(),
                result.loss
            );
        } else {
            assert_eq!(
                errors.len(),
                1,
                "middleware policy must have one fail-closed loss for {}: {:?}",
                path.display(),
                result.loss
            );
            assert_eq!(errors[0].path, "network_middlewares");
        }
    }
}

#[test]
fn quickstart_coarse_mapping() {
    let path = examples_root().join("sandbox-policy-quickstart/policy.yaml");
    let yaml = std::fs::read_to_string(&path).expect("read quickstart");
    let policy = parse_sandbox_policy(&yaml).expect("parse quickstart");
    let result = map_to_mxc(&policy, &MxcMappingOptions::default());
    let cfg = &result.config;

    assert!(allowed_cidrs(cfg).is_empty());
    assert_eq!(
        str_list(&cfg["filesystem"]["readwritePaths"]),
        vec!["/sandbox", "/tmp", "/dev/null"]
    );
    assert_eq!(cfg["containment"], "bubblewrap");

    // DNS, protocol, access, and binary scope require governed egress. The port
    // itself is representable but no directional rule is emitted without a CIDR.
    let has = |severity: &str, needle: &str| {
        result
            .loss
            .iter()
            .any(|i| i.severity == severity && i.path.contains(needle))
    };
    assert!(has("error", "endpoints[0].host"), "expected DNS host loss");
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

    // 127.0.0.2 is not the supported 127.0.0.1 host-proxy address, so the
    // mapper records an error loss and keeps the MXC config fail-closed.
    assert!(
        cfg.get("runtimeConfig").is_none() || cfg["runtimeConfig"].is_null(),
        "non-127.0.0.1 redirect must NOT produce runtimeConfig: {:?}",
        cfg.get("runtimeConfig")
    );
    let has_proxy_loss = result
        .loss
        .iter()
        .any(|i| i.path == "proxy_redirect" && i.severity == "error");
    assert!(
        has_proxy_loss,
        "non-127.0.0.1 redirect must produce an error loss item"
    );

    // Direct egress is denied; the host proxy enforces the list.
    assert_eq!(cfg["network"]["egress"]["default"], "deny");

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
        2,
        "expected filesystem and containment errors: {errors:?}"
    );
    let filesystem = errors
        .iter()
        .find(|item| item.path == "filesystem_policy.grants")
        .expect("isolation_session filesystem error");
    assert!(filesystem.message.contains("cannot enforce"));
    let containment = errors
        .iter()
        .find(|item| item.path == "containment")
        .expect("isolation_session proxy-containment error");
    assert!(containment.message.contains("processcontainer"));
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
    assert!(allowed_cidrs(cfg).is_empty());
    assert!(result.loss.iter().any(|item| {
        item.severity == "error"
            && item.path.contains(".host")
            && item.message.contains("api.anthropic.com")
    }));
}

// ── New tests: proxy JSON shape and non-127.0.0.1 guard ──────────────────────

#[test]
fn split_with_loopback_addr_emits_loopback_only_1_0_shape() {
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

    assert_eq!(cfg["version"], "1.0.0");
    assert_eq!(cfg["network"]["egress"]["default"], "deny");
    assert_eq!(
        cfg["network"]["egress"]["allow"][0]["to"][0]["cidr"],
        "127.0.0.1/32"
    );
    assert_eq!(cfg["network"]["ingress"]["hostLoopback"], "allow");
    assert!(cfg.get("runtimeConfig").is_none());
    assert!(cfg["network"].get("proxy").is_none());
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
fn split_with_non_loopback_addr_emits_error_loss_and_no_runtime_proxy() {
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

    // A runtime proxy block is never emitted; proxy-aware clients receive
    // environment variables from the driver after this mapping step.
    assert!(
        cfg.get("runtimeConfig").is_none() || cfg["runtimeConfig"].is_null(),
        "non-127.0.0.1 redirect must not produce runtimeConfig: {:?}",
        cfg.get("runtimeConfig")
    );

    // An error loss for the unusable redirect must be present.
    let proxy_loss = result
        .loss
        .iter()
        .find(|i| i.path == "proxy_redirect" && i.severity == "error");
    assert!(
        proxy_loss.is_some(),
        "non-127.0.0.1 redirect must produce a proxy_redirect error loss item: {:?}",
        result.loss
    );
    let loss = proxy_loss.unwrap();
    assert_eq!(loss.openshell_feature, "per-sandbox egress attribution");
    assert!(
        loss.message.contains("127.0.0.1"),
        "loss message should mention '127.0.0.1': {}",
        loss.message
    );
}
