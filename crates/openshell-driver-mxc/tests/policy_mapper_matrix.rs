// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tier-0 coverage matrix + schema drift guard for the OpenShell→MXC policy mapper.
//!
//! Three quadrants:
//!   A — mappable fields (`OpenShell` ∩ MXC): assert exact MXC output.
//!   B — OpenShell-only features MXC cannot express: assert one loss item per
//!       field with the documented severity.
//!   C — MXC restrictive defaults ("default deny posture"): empty policy maps
//!       to the most-restrictive possible MXC config.
//!
//! Plus: `handled_fields_inventory` — the schema drift guard that fails when
//! `openshell-policy` gains a serialized field the mapper does not account for.

#![cfg(target_os = "windows")]
#![allow(
    clippy::doc_link_with_quotes,
    clippy::doc_markdown,
    clippy::needless_collect,
    clippy::uninlined_format_args
)]

use openshell_core::proto::{
    FilesystemPolicy, GraphqlOperation, L7Allow, L7DenyRule, L7Rule, LandlockPolicy,
    MiddlewareEndpointSelector, NetworkBinary, NetworkEndpoint, NetworkMiddlewareConfig,
    NetworkPolicyRule, ProcessPolicy, SandboxPolicy,
};
use openshell_driver_mxc::{
    EmbeddedPolicyMapper, MapCtx, MapError, MxcMappingOptions, PolicyMapper, map_to_mxc,
    split_policy,
};
use openshell_policy::{serialize_sandbox_policy, validate_sandbox_policy};
use serde_json::Value;

// ─── helpers ────────────────────────────────────────────────────────────────

fn middleware_config() -> NetworkMiddlewareConfig {
    NetworkMiddlewareConfig {
        name: "redactor".into(),
        middleware: "openshell/regex".into(),
        config: None,
        on_error: "fail_closed".into(),
        endpoints: Some(MiddlewareEndpointSelector {
            include: vec!["api.example.com".into()],
            exclude: Vec::new(),
        }),
        order: 0,
    }
}

fn str_list(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn default_opts() -> MxcMappingOptions {
    MxcMappingOptions::default() // bubblewrap containment
}

fn bubblewrap_opts() -> MxcMappingOptions {
    MxcMappingOptions {
        containment: "bubblewrap".to_owned(),
        ..Default::default()
    }
}

fn proxy_addr() -> std::net::SocketAddr {
    "127.0.0.1:18080".parse().unwrap()
}

fn pc_split_opts() -> MxcMappingOptions {
    MxcMappingOptions {
        containment: "processcontainer".to_owned(),
        proxy_redirect: Some(proxy_addr()),
        ..Default::default()
    }
}

/// Build a minimal policy with one network rule whose endpoints carry a single
/// endpoint set up by the caller.
fn net_policy(key: &str, ep: NetworkEndpoint) -> SandboxPolicy {
    let mut p = SandboxPolicy::default();
    p.network_policies.insert(
        key.to_owned(),
        NetworkPolicyRule {
            name: key.to_owned(),
            endpoints: vec![ep],
            binaries: Vec::new(),
        },
    );
    p
}

/// Assert exactly one loss item whose `path` contains `needle` and whose
/// `severity` equals `want_severity`.
fn assert_single_loss(
    loss: &[openshell_driver_mxc::LossItem],
    needle: &str,
    want_severity: &str,
    context: &str,
) {
    let matching: Vec<_> = loss
        .iter()
        .filter(|i| i.path.contains(needle) && i.severity == want_severity)
        .collect();
    assert!(
        !matching.is_empty(),
        "{context}: expected a '{want_severity}' loss with path containing '{needle}', got: {loss:?}"
    );
    // There should not be more than one item with a DIFFERENT severity for the same path.
    let other_severity: Vec<_> = loss
        .iter()
        .filter(|i| i.path.contains(needle) && i.severity != want_severity)
        .collect();
    assert!(
        other_severity.is_empty(),
        "{context}: unexpected additional loss item(s) for '{needle}' with wrong severity: {other_severity:?}"
    );
}

// ─── QUADRANT A: mappable fields, assert exact MXC output ───────────────────

/// filesystem.read_write → readwritePaths verbatim, order preserved.
#[test]
fn a_rw_paths_verbatim() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            read_write: vec!["/work".into(), "/tmp".into(), "/data".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts());
    assert_eq!(
        str_list(&r.config["filesystem"]["readwritePaths"]),
        vec!["/work", "/tmp", "/data"],
        "readwritePaths must be verbatim, in order"
    );
}

/// filesystem.read_only → readonlyPaths verbatim, order preserved.
#[test]
fn a_ro_paths_verbatim() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            read_only: vec!["/usr".into(), "/lib".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts());
    assert_eq!(
        str_list(&r.config["filesystem"]["readonlyPaths"]),
        vec!["/usr", "/lib"],
        "readonlyPaths must be verbatim, in order"
    );
}

/// include_workdir=true + opts.cwd set → cwd appended (unique) to readwritePaths.
#[test]
fn a_include_workdir_with_cwd_appended_unique() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_write: vec!["/work".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let opts = MxcMappingOptions {
        cwd: Some("/work".to_owned()), // already present — must not duplicate
        ..default_opts()
    };
    let r = map_to_mxc(&policy, &opts);
    let rw = str_list(&r.config["filesystem"]["readwritePaths"]);
    assert!(
        rw.contains(&"/work".to_owned()),
        "cwd must appear in readwritePaths"
    );
    let count = rw.iter().filter(|p| p.as_str() == "/work").count();
    assert_eq!(count, 1, "cwd must not be duplicated");

    // Also test where cwd is new.
    let opts2 = MxcMappingOptions {
        cwd: Some("/newcwd".to_owned()),
        ..default_opts()
    };
    let policy2 = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_write: vec!["/work".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let r2 = map_to_mxc(&policy2, &opts2);
    let rw2 = str_list(&r2.config["filesystem"]["readwritePaths"]);
    assert!(
        rw2.contains(&"/newcwd".to_owned()),
        "new cwd must be appended to readwritePaths"
    );
}

/// include_workdir=true, no cwd → an "info" loss item, no extra path added.
#[test]
fn a_include_workdir_no_cwd_emits_info_loss() {
    let policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            include_workdir: true,
            read_write: vec!["/work".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts()); // cwd is None
    let has_info = r
        .loss
        .iter()
        .any(|i| i.severity == "info" && i.path.contains("include_workdir"));
    assert!(
        has_info,
        "expected info loss for include_workdir without cwd; got: {:?}",
        r.loss
    );
    // The path list must not have grown beyond the source list.
    let rw = str_list(&r.config["filesystem"]["readwritePaths"]);
    assert_eq!(rw, vec!["/work"]);
}

/// Plain endpoint host → appears in allowedHosts.
#[test]
fn a_plain_host_in_allowed_hosts() {
    let policy = net_policy(
        "api",
        NetworkEndpoint {
            host: "api.example.com".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let hosts = str_list(&r.config["network"]["allowedHosts"]);
    assert!(
        hosts.contains(&"api.example.com".to_owned()),
        "host must appear in allowedHosts; got: {hosts:?}"
    );
}

/// endpoint.allowed_ips → each IP appended to allowedHosts + a "warning" loss.
#[test]
fn a_allowed_ips_appended_with_warning() {
    let policy = net_policy(
        "api",
        NetworkEndpoint {
            host: "db.internal".into(),
            allowed_ips: vec!["10.0.0.1".into(), "10.0.0.2".into()],
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let hosts = str_list(&r.config["network"]["allowedHosts"]);
    assert!(
        hosts.contains(&"10.0.0.1".to_owned()),
        "IP 10.0.0.1 must be in allowedHosts"
    );
    assert!(
        hosts.contains(&"10.0.0.2".to_owned()),
        "IP 10.0.0.2 must be in allowedHosts"
    );
    let warnings: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "warning" && i.path.contains("allowed_ips"))
        .collect();
    assert!(
        !warnings.is_empty(),
        "expected warning loss for allowed_ips; got: {:?}",
        r.loss
    );
}

/// Duplicate hosts across rules → deduplicated in allowedHosts.
#[test]
fn a_duplicate_hosts_deduplicated() {
    let mut policy = SandboxPolicy::default();
    let ep_a = NetworkEndpoint {
        host: "shared.example.com".into(),
        ..Default::default()
    };
    let ep_b = NetworkEndpoint {
        host: "shared.example.com".into(),
        ..Default::default()
    };
    policy.network_policies.insert(
        "rule_a".to_owned(),
        NetworkPolicyRule {
            name: "rule_a".to_owned(),
            endpoints: vec![ep_a],
            binaries: Vec::new(),
        },
    );
    policy.network_policies.insert(
        "rule_b".to_owned(),
        NetworkPolicyRule {
            name: "rule_b".to_owned(),
            endpoints: vec![ep_b],
            binaries: Vec::new(),
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let hosts = str_list(&r.config["network"]["allowedHosts"]);
    let count = hosts
        .iter()
        .filter(|h| h.as_str() == "shared.example.com")
        .count();
    assert_eq!(
        count, 1,
        "duplicate hosts must be deduplicated; got: {hosts:?}"
    );
}

/// Determinism: a policy with 3+ network rules (unordered map) maps twice → identical config JSON.
#[test]
fn a_deterministic_with_multiple_rules() {
    let mut policy = SandboxPolicy::default();
    for (key, host) in &[
        ("rule_z", "z.example.com"),
        ("rule_a", "a.example.com"),
        ("rule_m", "m.example.com"),
        ("rule_b", "b.example.com"),
    ] {
        policy.network_policies.insert(
            key.to_string(),
            NetworkPolicyRule {
                name: key.to_string(),
                endpoints: vec![NetworkEndpoint {
                    host: host.to_string(),
                    ..Default::default()
                }],
                binaries: Vec::new(),
            },
        );
    }
    let r1 = map_to_mxc(&policy, &bubblewrap_opts());
    let r2 = map_to_mxc(&policy, &bubblewrap_opts());
    assert_eq!(
        r1.config, r2.config,
        "map_to_mxc must be deterministic across two calls"
    );
}

/// split path: proxy_policy.network_policies == source's, proxy_policy.version preserved.
#[test]
fn a_split_network_verbatim_and_version_preserved() {
    let mut policy = SandboxPolicy {
        version: 42,
        ..Default::default()
    };
    policy.network_policies.insert(
        "api".to_owned(),
        NetworkPolicyRule {
            name: "api".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".into(),
                ports: vec![443],
                ..Default::default()
            }],
            binaries: Vec::new(),
        },
    );
    let result = split_policy(&policy, &pc_split_opts()).expect("split must return Some");
    assert_eq!(
        result.proxy_policy.network_policies, policy.network_policies,
        "split: proxy_policy.network_policies must equal source"
    );
    assert_eq!(
        result.proxy_policy.version, 42,
        "split: proxy_policy.version must equal source"
    );
}

/// split path: mxc_config["network"]["proxy"]["localhost"] == port (new schema).
#[test]
fn a_split_proxy_localhost_port() {
    let policy = SandboxPolicy::default();
    let result = split_policy(&policy, &pc_split_opts()).expect("split must return Some");
    assert_eq!(
        result.mxc_config["network"]["proxy"]["localhost"], 18080,
        "split must emit network.proxy.localhost == port"
    );
    // allowedHosts stays empty on the split path.
    assert!(
        str_list(&result.mxc_config["network"]["allowedHosts"]).is_empty(),
        "split path must have empty allowedHosts"
    );
}

// ─── QUADRANT B: OpenShell features MXC cannot express ──────────────────────
//
// For each field: build a minimal policy setting only that field (plus the
// minimum needed to reach the code path), map with default bubblewrap
// containment, assert exactly one loss item with the documented path fragment
// and severity.

/// endpoint.ports → "error" (path contains ".port").
#[test]
fn b_ports_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            ports: vec![443],
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".port", "error", "endpoint.ports");
}

/// endpoint.protocol → "error".
#[test]
fn b_protocol_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            protocol: "rest".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".protocol", "error", "endpoint.protocol");
}

/// endpoint.tls = "skip" → "warning".
#[test]
fn b_tls_skip_warning() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            tls: "skip".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".tls", "warning", "endpoint.tls=skip");
}

/// endpoint.tls = "full" (any non-skip) → "error".
#[test]
fn b_tls_non_skip_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            tls: "terminate".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".tls", "error", "endpoint.tls=terminate");
}

/// endpoint.enforcement = "audit" → "error".
#[test]
fn b_enforcement_audit_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            enforcement: "audit".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".enforcement",
        "error",
        "endpoint.enforcement=audit",
    );
}

/// endpoint.enforcement = "enforce" (non-audit) → "warning".
#[test]
fn b_enforcement_non_audit_warning() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            enforcement: "enforce".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".enforcement",
        "warning",
        "endpoint.enforcement=enforce",
    );
}

/// endpoint.access → "error".
#[test]
fn b_access_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            access: "read-only".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".access", "error", "endpoint.access");
}

/// endpoint.rules (one allow rule) → "error".
#[test]
fn b_rules_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "GET".into(),
                    path: "/api".into(),
                    ..Default::default()
                }),
            }],
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".rules", "error", "endpoint.rules");
}

/// endpoint.deny_rules → "error".
#[test]
fn b_deny_rules_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            deny_rules: vec![L7DenyRule {
                method: "POST".into(),
                path: "/admin".into(),
                ..Default::default()
            }],
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".deny_rules", "error", "endpoint.deny_rules");
}

/// endpoint.allow_encoded_slash=true → "error".
#[test]
fn b_allow_encoded_slash_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            allow_encoded_slash: true,
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".allow_encoded_slash",
        "error",
        "allow_encoded_slash",
    );
}

/// endpoint.websocket_credential_rewrite=true → "error".
#[test]
fn b_websocket_credential_rewrite_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            websocket_credential_rewrite: true,
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".websocket_credential_rewrite",
        "error",
        "websocket_credential_rewrite",
    );
}

/// endpoint.request_body_credential_rewrite=true → "error".
#[test]
fn b_request_body_credential_rewrite_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            request_body_credential_rewrite: true,
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".request_body_credential_rewrite",
        "error",
        "request_body_credential_rewrite",
    );
}

/// endpoint.persisted_queries → "error".
#[test]
fn b_persisted_queries_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            persisted_queries: "deny".into(),
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(&r.loss, ".persisted_queries", "error", "persisted_queries");
}

/// endpoint.graphql_persisted_queries → "error".
#[test]
fn b_graphql_persisted_queries_error() {
    let mut ep = NetworkEndpoint {
        host: "api.example.com".into(),
        ..Default::default()
    };
    ep.graphql_persisted_queries.insert(
        "abc".to_owned(),
        GraphqlOperation {
            operation_type: "query".into(),
            ..Default::default()
        },
    );
    let policy = net_policy("r", ep);
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".graphql_persisted_queries",
        "error",
        "graphql_persisted_queries",
    );
}

/// endpoint.graphql_max_body_bytes > 0 → "error".
#[test]
fn b_graphql_max_body_bytes_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "api.example.com".into(),
            graphql_max_body_bytes: 65536,
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    assert_single_loss(
        &r.loss,
        ".graphql_max_body_bytes",
        "error",
        "graphql_max_body_bytes",
    );
}

/// Wildcard host ("*.example.com") with allow_wildcards=false → "error", host NOT in allowedHosts.
#[test]
fn b_wildcard_host_deny_wildcards_error_host_absent() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "*.example.com".into(),
            ..Default::default()
        },
    );
    let opts = MxcMappingOptions {
        allow_wildcards: false,
        containment: "bubblewrap".to_owned(),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &opts);
    // Must have an "error" loss for the wildcard host.
    let err_loss: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains(".host"))
        .collect();
    assert!(
        !err_loss.is_empty(),
        "expected error loss for wildcard host; got: {:?}",
        r.loss
    );
    // Host must NOT be in allowedHosts when allow_wildcards=false.
    let hosts = str_list(&r.config["network"]["allowedHosts"]);
    assert!(
        !hosts.contains(&"*.example.com".to_owned()),
        "wildcard host must be absent from allowedHosts when allow_wildcards=false; got: {hosts:?}"
    );
}

/// Wildcard host with allow_wildcards=true → "error" (semantics warning), host IS in allowedHosts.
#[test]
fn b_wildcard_host_allow_wildcards_error_host_present() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: "*.example.com".into(),
            ..Default::default()
        },
    );
    let opts = MxcMappingOptions {
        allow_wildcards: true,
        containment: "bubblewrap".to_owned(),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &opts);
    // Still an "error" loss (MXC semantics warning), even though we emitted the host.
    let err_loss: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains(".host"))
        .collect();
    assert!(
        !err_loss.is_empty(),
        "expected error loss for wildcard host even with allow_wildcards=true; got: {:?}",
        r.loss
    );
    // Host IS in allowedHosts when allow_wildcards=true.
    let hosts = str_list(&r.config["network"]["allowedHosts"]);
    assert!(
        hosts.contains(&"*.example.com".to_owned()),
        "wildcard host must appear in allowedHosts when allow_wildcards=true; got: {hosts:?}"
    );
}

/// rule.binaries non-empty → "error" per binary.
#[test]
fn b_binaries_error_per_binary() {
    let mut policy = SandboxPolicy::default();
    policy.network_policies.insert(
        "r".to_owned(),
        NetworkPolicyRule {
            name: "r".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".into(),
                ..Default::default()
            }],
            binaries: vec![
                NetworkBinary {
                    path: "/usr/bin/curl".into(),
                    ..Default::default()
                },
                NetworkBinary {
                    path: "/usr/bin/wget".into(),
                    ..Default::default()
                },
            ],
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let binary_errors: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains("binaries["))
        .collect();
    assert_eq!(
        binary_errors.len(),
        2,
        "expected one error loss per binary; got: {:?}",
        r.loss
    );
}

/// rule with empty endpoints → "error".
#[test]
fn b_empty_endpoints_error() {
    let mut policy = SandboxPolicy::default();
    policy.network_policies.insert(
        "r".to_owned(),
        NetworkPolicyRule {
            name: "r".to_owned(),
            endpoints: Vec::new(), // empty
            binaries: Vec::new(),
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let endpoint_errors: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains(".endpoints"))
        .collect();
    assert!(
        !endpoint_errors.is_empty(),
        "expected error loss for empty endpoints; got: {:?}",
        r.loss
    );
}

/// endpoint with empty host → "error".
#[test]
fn b_empty_host_error() {
    let policy = net_policy(
        "r",
        NetworkEndpoint {
            host: String::new(), // empty
            ..Default::default()
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let host_errors: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains(".host"))
        .collect();
    assert!(
        !host_errors.is_empty(),
        "expected error loss for empty host; got: {:?}",
        r.loss
    );
}

/// rule with empty binaries → "error".
#[test]
fn b_empty_binaries_error() {
    let mut policy = SandboxPolicy::default();
    policy.network_policies.insert(
        "r".to_owned(),
        NetworkPolicyRule {
            name: "r".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".into(),
                ..Default::default()
            }],
            binaries: Vec::new(), // empty
        },
    );
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let bin_errors: Vec<_> = r
        .loss
        .iter()
        .filter(|i| i.severity == "error" && i.path.contains(".binaries"))
        .collect();
    assert!(
        !bin_errors.is_empty(),
        "expected error loss for empty binaries; got: {:?}",
        r.loss
    );
}

/// policy.landlock = Some(default) → "warning".
#[test]
fn b_landlock_warning() {
    let policy = SandboxPolicy {
        landlock: Some(LandlockPolicy {
            compatibility: "best_effort".into(),
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts());
    assert_single_loss(&r.loss, "landlock", "warning", "landlock");
}

/// process.run_as_user non-empty → "warning".
#[test]
fn b_run_as_user_warning() {
    let policy = SandboxPolicy {
        process: Some(ProcessPolicy {
            run_as_user: "sandbox".into(),
            run_as_group: String::new(),
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts());
    assert_single_loss(&r.loss, "run_as_user", "warning", "process.run_as_user");
}

/// process.run_as_group non-empty → "warning".
#[test]
fn b_run_as_group_warning() {
    let policy = SandboxPolicy {
        process: Some(ProcessPolicy {
            run_as_user: String::new(),
            run_as_group: "sandboxers".into(),
        }),
        ..Default::default()
    };
    let r = map_to_mxc(&policy, &default_opts());
    assert_single_loss(&r.loss, "run_as_group", "warning", "process.run_as_group");
}

/// Seam-level: EmbeddedPolicyMapper.map over a policy with one error-class field
/// (a port) via MapCtx{egress: None} returns Err(MapError::Unsupported(_)).
#[test]
fn b_seam_returns_unsupported_on_error_field() {
    let mapper = EmbeddedPolicyMapper;
    // isolation_session containment + network policy → error loss from add_backend_specific_config.
    let mut policy = SandboxPolicy {
        filesystem: Some(FilesystemPolicy {
            read_write: vec!["C:/work".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    policy.network_policies.insert(
        "api".to_owned(),
        NetworkPolicyRule {
            name: "api".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".into(),
                ports: vec![443],
                ..Default::default()
            }],
            binaries: Vec::new(),
        },
    );
    let ctx = MapCtx {
        sandbox_id: "sb-test".into(),
        egress: None, // coarse path → isolation_session → network policy errors
    };
    let err = mapper.map(Some(&policy), &ctx).unwrap_err();
    assert!(
        matches!(err, MapError::Unsupported(_)),
        "seam must return MapError::Unsupported for error-class losses; got: {err:?}"
    );
}

// ─── QUADRANT C: restrictive defaults ("default deny posture") ───────────────

/// Empty SandboxPolicy (all None/empty) with default options produces the most
/// restrictive possible MXC config.
#[test]
fn c_empty_policy_default_deny_posture() {
    let policy = SandboxPolicy::default();
    let r = map_to_mxc(&policy, &bubblewrap_opts());
    let cfg = &r.config;

    // Network: default deny, no allowed/blocked hosts.
    assert_eq!(
        cfg["network"]["defaultPolicy"], "block",
        "defaultPolicy must be 'block' on empty policy"
    );
    assert!(
        str_list(&cfg["network"]["allowedHosts"]).is_empty(),
        "allowedHosts must be [] on empty policy"
    );
    assert!(
        str_list(&cfg["network"]["blockedHosts"]).is_empty(),
        "blockedHosts must be [] on empty policy"
    );

    // UI: fully locked down.
    assert_eq!(cfg["ui"]["disable"], true, "ui.disable must be true");
    assert_eq!(
        cfg["ui"]["clipboard"], "none",
        "ui.clipboard must be 'none'"
    );
    assert_eq!(cfg["ui"]["injection"], false, "ui.injection must be false");

    // Lifecycle: destroyOnExit + no policy preservation.
    assert_eq!(
        cfg["lifecycle"]["destroyOnExit"], true,
        "lifecycle.destroyOnExit must be true"
    );
    assert_eq!(
        cfg["lifecycle"]["preservePolicy"], false,
        "lifecycle.preservePolicy must be false"
    );

    // Filesystem: all lists empty, deniedPaths empty.
    assert!(
        str_list(&cfg["filesystem"]["readwritePaths"]).is_empty(),
        "readwritePaths must be [] on empty policy"
    );
    assert!(
        str_list(&cfg["filesystem"]["readonlyPaths"]).is_empty(),
        "readonlyPaths must be [] on empty policy"
    );
    assert!(
        str_list(&cfg["filesystem"]["deniedPaths"]).is_empty(),
        "deniedPaths must be [] on empty policy"
    );

    // No processContainer key when no hosts are granted.
    assert!(
        cfg.get("processContainer").is_none(),
        "processContainer must be absent when no hosts are mapped"
    );

    // No enforcementMode key when allowedHosts is empty.
    assert!(
        cfg["network"].get("enforcementMode").is_none(),
        "enforcementMode must be absent when allowedHosts is empty"
    );
}

/// Split path with network rules present: allowedHosts stays empty.
#[test]
fn c_split_empty_allowed_hosts_with_network_rules() {
    let mut policy = SandboxPolicy::default();
    policy.network_policies.insert(
        "api".to_owned(),
        NetworkPolicyRule {
            name: "api".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: "api.example.com".into(),
                ..Default::default()
            }],
            binaries: Vec::new(),
        },
    );
    let result = split_policy(&policy, &pc_split_opts()).expect("split must return Some");
    assert!(
        str_list(&result.mxc_config["network"]["allowedHosts"]).is_empty(),
        "split path allowedHosts must be empty even with network rules; got: {:?}",
        result.mxc_config["network"]["allowedHosts"]
    );
    // But proxy redirect is present.
    assert_eq!(
        result.mxc_config["network"]["proxy"]["localhost"], 18080,
        "split must emit network.proxy.localhost"
    );
}

// ─── DRIFT GUARD ─────────────────────────────────────────────────────────────
//
// Serialize policies via openshell_policy::serialize_sandbox_policy, collect
// YAML keys, compare against HANDLED_* const slices. Fails when a new field
// is added to the schema without updating the mapper.

/// Top-level fields of the YAML policy schema that the mapper handles today.
/// Derived from what map.rs and build_split_mxc_config actually read.
///
/// "version"              — emitted into mxc_config["version"] (not a loss)
/// "filesystem_policy"    — mapped via map_filesystem
/// "landlock"             — loss item emitted in add_static_policy_loss
/// "process"              — loss items for run_as_user / run_as_group
/// "network_policies"     — mapped via map_network / delegated in split
const HANDLED_TOPLEVEL: &[&str] = &[
    "version",
    "filesystem_policy",
    "landlock",
    "process",
    "network_policies",
    "network_middlewares",
];

/// Per-rule keys under each network_policies entry that the mapper handles.
const HANDLED_RULE_KEYS: &[&str] = &["name", "endpoints", "binaries"];

/// Per-endpoint keys that the mapper accounts for (mapping or loss item).
///
/// "host"                          — mapped to allowedHosts (or loss if wildcard/empty)
/// "port"                          — normalized to ports at parse; covered by ports loss
/// "ports"                         — error loss
/// "protocol"                      — error loss
/// "tls"                           — warning (skip) or error loss
/// "enforcement"                   — error (audit) or warning (other) loss
/// "access"                        — error loss
/// "rules"                         — error loss
/// "allowed_ips"                   — appended to allowedHosts + warning loss
/// "deny_rules"                    — error loss
/// "allow_encoded_slash"           — error loss
/// "websocket_credential_rewrite"  — error loss
/// "request_body_credential_rewrite" — error loss
/// "persisted_queries"             — error loss
/// "graphql_persisted_queries"     — error loss
/// "graphql_max_body_bytes"        — error loss
/// "path"                          — not currently read by the mapper (no loss emitted);
///                                   included here so the drift guard does not trip on
///                                   existing schema fields the mapper silently ignores.
///                                   If the mapper needs to enforce path-scoped routing,
///                                   remove this entry and add an explicit loss item.
const HANDLED_ENDPOINT_KEYS: &[&str] = &[
    "host",
    "port",
    "ports",
    "protocol",
    "tls",
    "enforcement",
    "access",
    "rules",
    "allowed_ips",
    "deny_rules",
    "allow_encoded_slash",
    "websocket_credential_rewrite",
    "request_body_credential_rewrite",
    "persisted_queries",
    "graphql_persisted_queries",
    "graphql_max_body_bytes",
    "path",
];

#[test]
fn handled_fields_inventory() {
    use std::collections::BTreeSet;

    // ── (1) Top-level keys: serialize a SandboxPolicy with every section
    // present-but-minimal, then collect YAML keys. ──────────────────────────
    let full_toplevel_policy = SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: vec!["/usr".into()],
            read_write: vec!["/work".into()],
        }),
        landlock: Some(LandlockPolicy {
            compatibility: "best_effort".into(),
        }),
        process: Some(ProcessPolicy {
            run_as_user: "sandbox".into(),
            run_as_group: "sandbox".into(),
        }),
        network_policies: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "rule".to_owned(),
                NetworkPolicyRule {
                    name: "rule".to_owned(),
                    endpoints: vec![NetworkEndpoint {
                        host: "api.example.com".into(),
                        port: 443,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );
            m
        },
        network_middlewares: {
            let mut m = std::collections::HashMap::new();
            m.insert("redactor".to_owned(), middleware_config());
            m
        },
    };

    // Validate so the test itself doesn't carry a bad policy.
    validate_sandbox_policy(&full_toplevel_policy).expect("test policy must be valid");

    let yaml_toplevel =
        serialize_sandbox_policy(&full_toplevel_policy).expect("serialize full_toplevel_policy");
    let top_value: Value =
        serde_yml::from_str::<Value>(&yaml_toplevel).expect("re-parse as JSON value");
    let top_obj = top_value
        .as_object()
        .expect("top-level must be a JSON object");
    let observed_toplevel: BTreeSet<&str> = top_obj.keys().map(String::as_str).collect();
    let expected_toplevel: BTreeSet<&str> = HANDLED_TOPLEVEL.iter().copied().collect();

    let unhandled_top: Vec<&&str> = observed_toplevel
        .iter()
        .filter(|k| !expected_toplevel.contains(**k))
        .collect();
    assert!(
        unhandled_top.is_empty(),
        "openshell-policy gained top-level field(s) {:?} that the policy mapper does not handle \
         — map it, delegate it, or add a loss item, then update HANDLED_TOPLEVEL in this test.",
        unhandled_top
    );

    let missing_top: Vec<&&str> = expected_toplevel
        .iter()
        .filter(|k| !observed_toplevel.contains(**k))
        .collect();
    assert!(
        missing_top.is_empty(),
        "HANDLED_TOPLEVEL lists field(s) {:?} that are no longer emitted by \
         serialize_sandbox_policy — remove them from HANDLED_TOPLEVEL.",
        missing_top
    );

    // ── (2) Per-rule and per-endpoint keys: serialize a policy with one fully-
    // populated NetworkPolicyRule / NetworkEndpoint. ─────────────────────────
    //
    // Note: `port` (scalar) and `ports` (array) are mutually exclusive in the
    // serialized form — single port emits `port`; multiple ports emit `ports`.
    // To cover both variants we use TWO endpoints: the first with multi-port
    // (triggers `ports` key), the second with single-port (triggers `port`).
    // The drift guard collects the UNION of all endpoint keys observed.
    let mut full_ep = NetworkEndpoint {
        host: "api.example.com".into(),
        path: "/graphql".into(),
        // Two ports → serializes as `ports: [80, 443]` (array form).
        ports: vec![80, 443],
        protocol: "graphql".into(),
        tls: "skip".into(),
        enforcement: "enforce".into(),
        access: "full".into(),
        allowed_ips: vec!["10.0.0.1".into()],
        allow_encoded_slash: true,
        websocket_credential_rewrite: true,
        request_body_credential_rewrite: true,
        persisted_queries: "deny".into(),
        graphql_max_body_bytes: 65536,
        rules: vec![L7Rule {
            allow: Some(L7Allow {
                method: "GET".into(),
                path: "/foo".into(),
                ..Default::default()
            }),
        }],
        deny_rules: vec![L7DenyRule {
            method: "POST".into(),
            path: "/bar".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    full_ep.graphql_persisted_queries.insert(
        "abc".to_owned(),
        GraphqlOperation {
            operation_type: "query".into(),
            ..Default::default()
        },
    );
    // Second endpoint: single port → serializes as `port: 443` (scalar form).
    let single_port_ep = NetworkEndpoint {
        host: "other.example.com".into(),
        ports: vec![443],
        ..Default::default()
    };

    let full_rule_policy = SandboxPolicy {
        version: 1,
        network_policies: {
            let mut m = std::collections::HashMap::new();
            m.insert(
                "rule".to_owned(),
                NetworkPolicyRule {
                    name: "rule".to_owned(),
                    endpoints: vec![full_ep, single_port_ep],
                    binaries: vec![NetworkBinary {
                        path: "/usr/bin/curl".into(),
                        ..Default::default()
                    }],
                },
            );
            m
        },
        ..Default::default()
    };

    let yaml_rule =
        serialize_sandbox_policy(&full_rule_policy).expect("serialize full_rule_policy");
    let rule_value: Value =
        serde_yml::from_str::<Value>(&yaml_rule).expect("re-parse rule policy as JSON value");

    // Collect per-rule keys.
    let network_policies_obj = rule_value["network_policies"]
        .as_object()
        .expect("network_policies must be an object");
    let first_rule = network_policies_obj
        .values()
        .next()
        .expect("at least one rule")
        .as_object()
        .expect("rule must be an object");
    let observed_rule_keys: BTreeSet<&str> = first_rule.keys().map(String::as_str).collect();
    let expected_rule_keys: BTreeSet<&str> = HANDLED_RULE_KEYS.iter().copied().collect();

    let unhandled_rule: Vec<&&str> = observed_rule_keys
        .iter()
        .filter(|k| !expected_rule_keys.contains(**k))
        .collect();
    assert!(
        unhandled_rule.is_empty(),
        "openshell-policy gained network rule field(s) {:?} that the policy mapper does not handle \
         — map it, delegate it, or add a loss item, then update HANDLED_RULE_KEYS in this test.",
        unhandled_rule
    );

    let missing_rule: Vec<&&str> = expected_rule_keys
        .iter()
        .filter(|k| !observed_rule_keys.contains(**k))
        .collect();
    assert!(
        missing_rule.is_empty(),
        "HANDLED_RULE_KEYS lists field(s) {:?} that are no longer emitted — remove them.",
        missing_rule
    );

    // Collect per-endpoint keys: union across ALL endpoints so that mutually-
    // exclusive fields like `port` (single-port form) and `ports` (multi-port
    // form) are both captured.
    let endpoints_arr = first_rule["endpoints"]
        .as_array()
        .expect("endpoints must be an array");
    let observed_ep_keys: BTreeSet<&str> = endpoints_arr
        .iter()
        .filter_map(|ep| ep.as_object())
        .flat_map(|obj| obj.keys().map(String::as_str))
        .collect();
    let expected_ep_keys: BTreeSet<&str> = HANDLED_ENDPOINT_KEYS.iter().copied().collect();

    let unhandled_ep: Vec<&&str> = observed_ep_keys
        .iter()
        .filter(|k| !expected_ep_keys.contains(**k))
        .collect();
    assert!(
        unhandled_ep.is_empty(),
        "openshell-policy gained endpoint field(s) {:?} that the policy mapper does not handle \
         — map it, delegate it, or add a loss item, then update HANDLED_ENDPOINT_KEYS in this test.",
        unhandled_ep
    );

    let missing_ep: Vec<&&str> = expected_ep_keys
        .iter()
        .filter(|k| !observed_ep_keys.contains(**k))
        .collect();
    assert!(
        missing_ep.is_empty(),
        "HANDLED_ENDPOINT_KEYS lists field(s) {:?} that are no longer emitted — remove them.",
        missing_ep
    );
}
