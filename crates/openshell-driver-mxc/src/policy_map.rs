// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// vendored from gburachas/msft-mxc@a66cc35 (branch `policy_mapper`,
// policy_mapper/rust_policy_mapper/src/main.rs).
//
//! Embedded OpenShell-policy → MXC `ContainerConfig` mapping logic.
//!
//! This module is **vendored** from Giedrius's `rust_policy_mapper` CLI tool
//! (team decision: embed as a module, NOT a separate crate). Only the **pure**
//! mapping functions are lifted; the CLI shell (`clap`/`Args`/`main`), file
//! discovery, and output writing (`convert_policy`/`load_yaml`/`write_outputs`/
//! `render_readme`/`build_loss_report`) are dropped, along with the `clap`,
//! `anyhow`, and `regex` dependencies they pulled in.
//!
//! Giedrius's `validate_schema` + the `jsonschema` dependency are intentionally
//! **omitted** here (per the embed plan: "not needed at runtime"). Re-add behind
//! a `schema-validation` feature if parity-validation is ever wanted in-crate.
//!
//! This module is pure `serde` and is **NOT** `#[cfg(target_os = "windows")]`
//! gated, so its parity tests run on Linux CI even though the rest of the driver
//! is Windows-only.
//!
//! **Sync plan:** Giedrius's repo stays the source of truth. Re-vendor when he
//! updates `rust_policy_mapper`; bump the `@a66cc35` marker above. The Python
//! reference for behavior is
//! `msft-mxc-gburachas/policy_mapper/python_policy_mapper/openshell_policy_to_mxc.py`.

// Vendored module: the full mapping surface (network/L7 loss reporting, loss
// summaries) is carried for parity with Giedrius's source and Stage-2 egress,
// but the June 15 filesystem-only demo does not exercise all of it. The module
// is also compiled-but-unused on non-Windows targets (only its tests use it
// there). Both are by design, so suppress dead-code noise crate-wide here.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use serde_yaml::{Mapping, Value as YamlValue};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_COMMAND: &str =
    "sh -lc \"echo OpenShell policy mapped to MXC; replace process.commandLine before running a real workload\"";
const DEFAULT_MXC_VERSION: &str = "0.7.0-alpha";

const OPEN_SHELL_SUPERSET_GAPS: &[&str] = &[
    "MXC UI policy has no OpenShell policy equivalent: ui.disable, ui.clipboard, and ui.injection.",
    "MXC lifecycle fields have no OpenShell policy equivalent: destroyOnExit, preservePolicy, phase, and sandboxId.",
    "MXC backend selection and backend-specific blocks are outside OpenShell policy YAML.",
    "MXC process command, cwd, env, and timeout are runtime config fields, not OpenShell policy fields.",
    "MXC explicit deniedPaths are not expressible in current OpenShell policy YAML, which relies on default-deny filesystem behavior instead.",
    "MXC fallback.allowDaclMutation (host DACL mutation consent) has no OpenShell policy equivalent.",
    "MXC network.allowLocalNetwork (inbound bind/listen permission) has no OpenShell policy equivalent.",
    "MXC network.proxy configuration has no OpenShell policy equivalent.",
    "MXC experimental backend blocks (windows_sandbox, wslc, seatbelt, isolation_session) are outside OpenShell policy YAML.",
];

// ---------------------------------------------------------------------------
// Mapping options (clone-friendly runtime config)
// ---------------------------------------------------------------------------

/// Runtime knobs for the mapper. The driver constructs these with
/// [`MappingOptions::for_isolation_session`]; the upstream CLI `Args`/`build_options`
/// path is dropped.
#[derive(Clone, Debug)]
pub struct MappingOptions {
    pub mxc_version: String,
    pub containment: String,
    pub command: String,
    pub container_id: String,
    pub cwd: Option<String>,
    pub env: Vec<String>,
    pub timeout_ms: u64,
    pub strict: bool,
    pub allow_wildcards: bool,
}

impl MappingOptions {
    /// Demo/driver defaults: target the MXC `isolation_session` backend.
    pub fn for_isolation_session(container_id: impl Into<String>) -> Self {
        Self {
            mxc_version: DEFAULT_MXC_VERSION.to_owned(),
            containment: "isolation_session".to_owned(),
            command: DEFAULT_COMMAND.to_owned(),
            container_id: container_id.into(),
            cwd: None,
            env: Vec::new(),
            timeout_ms: 0,
            strict: false,
            allow_wildcards: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Loss item
// ---------------------------------------------------------------------------

/// A single OpenShell→MXC mapping loss/diagnostic. `severity` is one of
/// `"info"`, `"warning"`, `"error"`. The driver rejects a `CreateSandbox`
/// when any `"error"` item is present.
#[derive(Clone, Debug, Serialize)]
pub struct LossItem {
    pub path: String,
    pub severity: String,
    pub message: String,
    pub openshell_feature: String,
    pub mxc_impact: String,
}

fn add_loss(
    items: &mut Vec<LossItem>,
    path: &str,
    severity: &str,
    message: &str,
    openshell_feature: &str,
    mxc_impact: &str,
) {
    items.push(LossItem {
        path: path.to_owned(),
        severity: severity.to_owned(),
        message: message.to_owned(),
        openshell_feature: openshell_feature.to_owned(),
        mxc_impact: mxc_impact.to_owned(),
    });
}

// ---------------------------------------------------------------------------
// MXC config builder (pure entry point lifted from Giedrius's mapper)
// ---------------------------------------------------------------------------

/// Translate an OpenShell policy (as a `serde_yaml::Value`) into an MXC
/// `ContainerConfig` JSON value, appending any mapping losses to `items`.
///
/// Top-level YAML keys consumed: `filesystem_policy`, `network_policies`,
/// `landlock`, `process`.
pub fn build_mxc_config(
    policy: &YamlValue,
    options: &MappingOptions,
    items: &mut Vec<LossItem>,
) -> JsonValue {
    let mut process = json!({
        "commandLine": options.command,
        "timeout": options.timeout_ms,
    });
    if let Some(cwd) = &options.cwd {
        process["cwd"] = json!(cwd);
    }
    if !options.env.is_empty() {
        process["env"] = json!(options.env);
    }

    let filesystem = map_filesystem(policy, options, items);
    let allowed_hosts = map_network(policy, options, items);

    let mut network = json!({
        "defaultPolicy": "block",
        "allowedHosts": allowed_hosts,
        "blockedHosts": [],
    });
    if let Some(mode) = default_enforcement_mode(&options.containment, &allowed_hosts) {
        network["enforcementMode"] = json!(mode);
    }

    let mut config = json!({
        "version": options.mxc_version,
        "containerId": options.container_id,
        "containment": options.containment,
        "lifecycle": {
            "destroyOnExit": true,
            "preservePolicy": false,
        },
        "process": process,
        "filesystem": filesystem,
        "network": network,
        "ui": {
            "disable": true,
            "clipboard": "none",
            "injection": false,
        },
    });

    add_backend_specific_config(&mut config, &options.containment, &allowed_hosts, items);
    add_static_policy_loss(policy, options, items);
    config
}

// ---------------------------------------------------------------------------
// Filesystem mapping
// ---------------------------------------------------------------------------

fn map_filesystem(policy: &YamlValue, options: &MappingOptions, items: &mut Vec<LossItem>) -> JsonValue {
    let raw_fs = policy.get("filesystem_policy");

    // Python: fs_policy = policy.get("filesystem_policy") or {}
    // Falsy values (None/null/empty dict) collapse to empty dict.
    enum FsResult<'a> {
        Map(&'a Mapping),
        EmptyOrAbsent,
        TypeError,
    }

    let fs_result = match raw_fs {
        None | Some(YamlValue::Null) => FsResult::EmptyOrAbsent,
        Some(YamlValue::Mapping(m)) if m.is_empty() => FsResult::EmptyOrAbsent,
        Some(YamlValue::Mapping(m)) => FsResult::Map(m),
        Some(_) => FsResult::TypeError,
    };

    if matches!(fs_result, FsResult::TypeError) {
        add_loss(
            items,
            "filesystem_policy",
            "error",
            "Expected filesystem_policy to be an object.",
            "filesystem policy",
            "No filesystem grants could be mapped.",
        );
    }

    let mut readwrite: Vec<String> = Vec::new();
    let mut readonly: Vec<String> = Vec::new();

    if let FsResult::Map(fs) = &fs_result {
        readwrite = stable_list(fs.get("read_write"));
        readonly = stable_list(fs.get("read_only"));

        let include_workdir = fs
            .get("include_workdir")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if include_workdir {
            if let Some(cwd) = &options.cwd {
                append_unique(&mut readwrite, cwd.clone());
            } else {
                add_loss(
                    items,
                    "filesystem_policy.include_workdir",
                    "info",
                    "OpenShell includes the runtime workdir, but no cwd was supplied.",
                    "include_workdir",
                    "The generated MXC config cannot add the workdir path grant.",
                );
            }
        }
    }

    // Python: `if not fs_policy:` fires when dict is empty/absent (all non-Map cases).
    if !matches!(fs_result, FsResult::Map(_)) {
        add_loss(
            items,
            "filesystem_policy",
            "warning",
            "No OpenShell filesystem_policy was present.",
            "default filesystem policy",
            "MXC receives empty filesystem lists; backend defaults determine visibility.",
        );
    }

    add_loss(
        items,
        "filesystem_policy",
        "warning",
        &filesystem_default_deny_message(&options.containment),
        "OpenShell Landlock/default-deny filesystem model",
        "MXC filesystem default-deny parity is backend-specific.",
    );

    json!({
        "readwritePaths": readwrite,
        "readonlyPaths": readonly,
        "deniedPaths": [],
    })
}

fn filesystem_default_deny_message(containment: &str) -> String {
    match containment {
        "bubblewrap" => "Bubblewrap policy is not strict OpenShell filesystem parity: MXC \
            may bind host root read-only and overlay policy mounts."
            .to_owned(),
        "lxc" => "LXC exposes the container rootfs and bind-mounts selected host \
            paths; this is not identical to OpenShell Landlock."
            .to_owned(),
        "wslc" => "WSLC mounts selected Windows paths, but default-deny behavior is \
            runner/backend specific."
            .to_owned(),
        "seatbelt" => "Seatbelt starts from a deny-default profile with baseline system \
            allowances, not OpenShell Landlock."
            .to_owned(),
        _ => "MXC filesystem behavior is backend-specific and not equivalent to \
            OpenShell Landlock by construction."
            .to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Network mapping
// ---------------------------------------------------------------------------

fn map_network(policy: &YamlValue, options: &MappingOptions, items: &mut Vec<LossItem>) -> Vec<String> {
    let raw_net = policy.get("network_policies");

    let net_map = match raw_net {
        None | Some(YamlValue::Null) => {
            add_backend_network_loss(policy, &options.containment, items);
            return vec![];
        }
        Some(YamlValue::Mapping(m)) if m.is_empty() => {
            add_backend_network_loss(policy, &options.containment, items);
            return vec![];
        }
        Some(YamlValue::Mapping(m)) => m,
        Some(_) => {
            add_loss(
                items,
                "network_policies",
                "error",
                "Expected network_policies to be a map.",
                "network policies",
                "No network allowlist could be mapped.",
            );
            add_backend_network_loss(policy, &options.containment, items);
            return vec![];
        }
    };

    let mut allowed_hosts: Vec<String> = Vec::new();

    for (key_val, rule_val) in net_map.iter() {
        let rule_key = yaml_as_str(key_val).unwrap_or_default();
        let rule_path = format!("network_policies.{}", rule_key);

        let rule = match rule_val.as_mapping() {
            Some(m) => m,
            None => {
                add_loss(
                    items,
                    &rule_path,
                    "error",
                    "Expected network policy entry to be an object.",
                    "network policy entry",
                    "Entry was skipped.",
                );
                continue;
            }
        };

        let endpoints: Vec<&YamlValue> = match rule.get("endpoints") {
            None | Some(YamlValue::Null) => vec![],
            Some(YamlValue::Sequence(seq)) => seq.iter().collect(),
            Some(other) => vec![other],
        };

        if endpoints.is_empty() {
            add_loss(
                items,
                &format!("{}.endpoints", rule_path),
                "error",
                "OpenShell policy entry has no endpoints.",
                "network endpoints",
                "No MXC host allowlist entries were produced for this policy.",
            );
        }

        for (index, endpoint) in endpoints.iter().enumerate() {
            let endpoint_path = format!("{}.endpoints[{}]", rule_path, index);
            match endpoint.as_mapping() {
                None => {
                    add_loss(
                        items,
                        &endpoint_path,
                        "error",
                        "Expected endpoint to be an object.",
                        "network endpoint",
                        "Endpoint was skipped.",
                    );
                }
                Some(ep) => {
                    map_endpoint(ep, &endpoint_path, &mut allowed_hosts, options, items);
                }
            }
        }

        // binaries
        let binaries: Vec<&YamlValue> = match rule.get("binaries") {
            None | Some(YamlValue::Null) => vec![],
            Some(YamlValue::Sequence(seq)) => seq.iter().collect(),
            Some(other) => vec![other],
        };

        if binaries.is_empty() {
            add_loss(
                items,
                &format!("{}.binaries", rule_path),
                "error",
                "OpenShell requires binary-scoped network grants; this entry has no binaries.",
                "binary-scoped network policy",
                "MXC cannot represent per-binary grants and scopes network to the sandbox.",
            );
        } else {
            for (index, binary) in binaries.iter().enumerate() {
                let binary_path = match binary.as_mapping().and_then(|m| m.get("path")) {
                    Some(YamlValue::String(s)) => Some(s.as_str()),
                    _ => None,
                };
                let repr = match binary_path {
                    Some(p) => format!("'{}'", p),
                    None => python_repr_yaml(binary),
                };
                add_loss(
                    items,
                    &format!("{}.binaries[{}].path", rule_path, index),
                    "error",
                    &format!("Binary scope is not representable in MXC: {}.", repr),
                    "binary-scoped network policy",
                    "Dropping this would broaden access from one executable to the whole sandbox.",
                );
            }
        }
    }

    add_backend_network_loss(policy, &options.containment, items);
    allowed_hosts
}

fn map_endpoint(
    endpoint: &Mapping,
    path: &str,
    allowed_hosts: &mut Vec<String>,
    options: &MappingOptions,
    items: &mut Vec<LossItem>,
) {
    // host
    match endpoint.get("host") {
        None | Some(YamlValue::Null) => {
            add_loss(
                items,
                &format!("{}.host", path),
                "error",
                "Endpoint has no host.",
                "network endpoint host",
                "Endpoint was not added to MXC allowedHosts.",
            );
        }
        Some(host_val) => {
            let host_str = yaml_to_string(host_val);
            if contains_wildcard(&host_str) {
                let (message, impact) = if options.allow_wildcards {
                    append_unique(allowed_hosts, host_str.clone());
                    (
                        format!(
                            "Wildcard host emitted despite non-portable MXC semantics: {}.",
                            host_str
                        ),
                        "Backend behavior is not portable and may fail or broaden access.",
                    )
                } else {
                    (
                        format!(
                            "Wildcard host omitted because MXC has no portable syntax: {}.",
                            host_str
                        ),
                        "Generated MXC config is more restrictive for this endpoint.",
                    )
                };
                add_loss(
                    items,
                    &format!("{}.host", path),
                    "error",
                    &message,
                    "OpenShell wildcard host matching",
                    impact,
                );
            } else {
                append_unique(allowed_hosts, host_str);
            }
        }
    }

    // port / ports
    for field in &["port", "ports"] {
        if let Some(val) = endpoint.get(*field) {
            if !matches!(val, YamlValue::Null) {
                let repr = yaml_repr_value(val);
                add_loss(
                    items,
                    &format!("{}.{}", path, field),
                    "error",
                    &format!("MXC allowedHosts cannot encode port constraint {}.", repr),
                    "port-scoped outbound policy",
                    "MXC allows or blocks the host as a whole.",
                );
            }
        }
    }

    // allowed_ips
    let ips = stable_list(endpoint.get("allowed_ips"));
    let host_for_msg = endpoint.get("host").map(yaml_to_string).unwrap_or_default();
    for ip in ips {
        append_unique(allowed_hosts, ip.clone());
        add_loss(
            items,
            &format!("{}.allowed_ips", path),
            "warning",
            &format!(
                "MXC can carry CIDR/IP '{}', but cannot bind it to DNS for '{}'.",
                ip, host_for_msg
            ),
            "DNS result pinning / SSRF override",
            "The CIDR/IP becomes a standalone allowed destination.",
        );
    }

    report_endpoint_l7_losses(endpoint, path, items);
}

fn report_endpoint_l7_losses(endpoint: &Mapping, path: &str, items: &mut Vec<LossItem>) {
    if let Some(protocol) = endpoint.get("protocol").and_then(|v| v.as_str()) {
        add_loss(
            items,
            &format!("{}.protocol", path),
            "error",
            &format!("MXC has no protocol-aware policy equivalent for '{}'.", protocol),
            "protocol-aware proxy policy",
            "MXC host filtering cannot enforce REST/WebSocket/GraphQL semantics.",
        );
    }

    if let Some(tls) = endpoint.get("tls").and_then(|v| v.as_str()) {
        let severity = if tls == "skip" { "warning" } else { "error" };
        add_loss(
            items,
            &format!("{}.tls", path),
            severity,
            &format!("MXC has no OpenShell TLS inspection mode equivalent for '{}'.", tls),
            "TLS inspection mode",
            "MXC network policy is host-level only.",
        );
    }

    if let Some(enforcement) = endpoint.get("enforcement").and_then(|v| v.as_str()) {
        if enforcement == "audit" {
            add_loss(
                items,
                &format!("{}.enforcement", path),
                "error",
                "MXC has no audit-only network policy mode.",
                "audit-mode endpoint",
                "Generated MXC config enforces host-level default block instead.",
            );
        } else {
            add_loss(
                items,
                &format!("{}.enforcement", path),
                "warning",
                "MXC enforcementMode is backend-wide, not per endpoint.",
                "per-endpoint enforcement",
                "The mapper chooses a backend-level enforcement mode.",
            );
        }
    }

    if let Some(access) = endpoint.get("access").and_then(|v| v.as_str()) {
        add_loss(
            items,
            &format!("{}.access", path),
            "error",
            &format!("MXC has no access preset equivalent for '{}'.", access),
            "REST/WebSocket/GraphQL access preset",
            "MXC cannot enforce method or operation-level access.",
        );
    }

    if endpoint.get("rules").is_some_and(|v| !matches!(v, YamlValue::Null)) {
        add_loss(
            items,
            &format!("{}.rules", path),
            "error",
            "MXC has no L7 allow-rule equivalent.",
            "REST/WebSocket/GraphQL allow rules",
            "Method/path/query/operation restrictions are lost.",
        );
    }

    if endpoint
        .get("deny_rules")
        .is_some_and(|v| !matches!(v, YamlValue::Null))
    {
        add_loss(
            items,
            &format!("{}.deny_rules", path),
            "error",
            "MXC has no L7 deny-rule equivalent.",
            "L7 deny rules",
            "Deny precedence over broad allows is lost.",
        );
    }

    // boolean L7 losses
    let bool_losses: &[(&str, &str)] = &[
        ("allow_encoded_slash", "encoded slash handling"),
        ("websocket_credential_rewrite", "WebSocket credential rewrite"),
        ("request_body_credential_rewrite", "request-body credential rewrite"),
    ];
    for (field, feature) in bool_losses {
        if endpoint.get(*field).and_then(|v| v.as_bool()).unwrap_or(false) {
            add_loss(
                items,
                &format!("{}.{}", path, field),
                "error",
                &format!("MXC has no equivalent for {}.", feature),
                feature,
                "Generated config cannot preserve this proxy behavior.",
            );
        }
    }

    // GraphQL losses
    let graphql_fields: &[&str] = &[
        "persisted_queries",
        "graphql_persisted_queries",
        "graphql_max_body_bytes",
    ];
    for field in graphql_fields {
        if endpoint.get(*field).is_some_and(|v| !matches!(v, YamlValue::Null)) {
            add_loss(
                items,
                &format!("{}.{}", path, field),
                "error",
                &format!("MXC has no GraphQL policy equivalent for {}.", field),
                "GraphQL operation policy",
                "GraphQL inspection and persisted-query behavior is lost.",
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Static policy losses (landlock, process identity)
// ---------------------------------------------------------------------------

fn add_static_policy_loss(policy: &YamlValue, options: &MappingOptions, items: &mut Vec<LossItem>) {
    if let Some(ll) = policy.get("landlock") {
        if !matches!(ll, YamlValue::Null) {
            add_loss(
                items,
                "landlock",
                "warning",
                "MXC has no Landlock compatibility mode field.",
                "Landlock LSM enforcement",
                "Backend filesystem controls may not fail like OpenShell best_effort/hard_requirement.",
            );
        }
    }

    if let Some(process) = policy.get("process").and_then(|v| v.as_mapping()) {
        for field in &["run_as_user", "run_as_group"] {
            if process.get(*field).is_some_and(|v| !matches!(v, YamlValue::Null)) {
                add_loss(
                    items,
                    &format!("process.{}", field),
                    "warning",
                    &format!("MXC has no portable equivalent for OpenShell {}.", field),
                    "process identity",
                    "MXC backend identity is selected outside this policy mapping.",
                );
            }
        }
    }

    if options.containment == "processcontainer" {
        let fs = policy.get("filesystem_policy").and_then(|v| v.as_mapping());
        if let Some(fs_map) = fs {
            let linux_paths: Vec<String> = stable_list(fs_map.get("read_only"))
                .into_iter()
                .chain(stable_list(fs_map.get("read_write")))
                .collect();
            if linux_paths.iter().any(|p| p.starts_with('/')) {
                add_loss(
                    items,
                    "filesystem_policy",
                    "warning",
                    "OpenShell example paths are Linux paths; Windows ProcessContainer expects Windows paths.",
                    "filesystem path syntax",
                    "Run with path translation or target a Linux-like MXC backend.",
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Backend-specific config additions
// ---------------------------------------------------------------------------

fn add_backend_specific_config(
    config: &mut JsonValue,
    containment: &str,
    allowed_hosts: &[String],
    items: &mut Vec<LossItem>,
) {
    match containment {
        "processcontainer" | "process" => {
            if !allowed_hosts.is_empty() {
                config["processContainer"] = json!({"capabilities": ["internetClient"]});
            }
        }
        "lxc" => {
            config["lxc"] = json!({"distribution": "alpine", "release": "3.20"});
        }
        c @ ("windows_sandbox" | "isolation_session" | "vm") if !allowed_hosts.is_empty() => {
            add_loss(
                items,
                "containment",
                "error",
                &format!("{} is not a v0 target for OpenShell network policy mapping.", c),
                "OpenShell network policy",
                "MXC network behavior is unsupported or unknown for this backend.",
            );
        }
        "microvm" if !allowed_hosts.is_empty() => {
            add_loss(
                items,
                "containment",
                "error",
                "microvm network policy enforcement is not defined for this mapper.",
                "OpenShell network policy",
                "MXC network behavior is unsupported or unknown for microvm.",
            );
        }
        _ => {}
    }
}

fn add_backend_network_loss(policy: &YamlValue, containment: &str, items: &mut Vec<LossItem>) {
    // Only fire when network_policies is present and non-empty
    let has_net = policy
        .get("network_policies")
        .is_some_and(|v| matches!(v, YamlValue::Mapping(m) if !m.is_empty()));
    if !has_net {
        return;
    }

    match containment {
        "seatbelt" => {
            add_loss(
                items,
                "network_policies",
                "error",
                "MXC Seatbelt cannot faithfully enforce arbitrary allowedHosts.",
                "host allowlist",
                "Seatbelt allowlists can broaden to allow-all outbound.",
            );
        }
        "processcontainer" | "process" => {
            add_loss(
                items,
                "network_policies",
                "warning",
                "Windows ProcessContainer host allowlists are possible but fragile.",
                "host allowlist",
                "Review firewall/capability behavior before treating this as parity.",
            );
        }
        "wslc" => {
            add_loss(
                items,
                "network_policies",
                "warning",
                "WSLC host filtering relies on bridged networking plus in-container iptables.",
                "host allowlist",
                "Backend privileges and runner behavior determine parity.",
            );
        }
        "vm" | "windows_sandbox" => {
            add_loss(
                items,
                "network_policies",
                "error",
                "MXC Windows Sandbox / vm cannot faithfully enforce arbitrary allowedHosts.",
                "host allowlist",
                "Network policy enforcement is unsupported or unknown for this backend.",
            );
        }
        _ => {}
    }
}

fn default_enforcement_mode(containment: &str, allowed_hosts: &[String]) -> Option<&'static str> {
    if allowed_hosts.is_empty() {
        return None;
    }
    match containment {
        "lxc" | "bubblewrap" | "hyperlight" => Some("firewall"),
        "processcontainer" | "process" => Some("both"),
        "wslc" | "seatbelt" | "microvm" | "vm" | "windows_sandbox" => None,
        _ => Some("firewall"),
    }
}

// ---------------------------------------------------------------------------
// Loss summary helpers
// ---------------------------------------------------------------------------

/// Distinct OpenShell features that could not be represented (error/warning).
pub fn summarize_missing_mxc(items: &[LossItem]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut summary: Vec<String> = Vec::new();
    for item in items {
        if (item.severity == "error" || item.severity == "warning")
            && !seen.contains(&item.openshell_feature)
        {
            seen.insert(item.openshell_feature.clone());
            summary.push(item.openshell_feature.clone());
        }
    }
    summary
}

/// Static MXC features that have no OpenShell-policy equivalent.
pub fn open_shell_superset_gaps() -> &'static [&'static str] {
    OPEN_SHELL_SUPERSET_GAPS
}

// ---------------------------------------------------------------------------
// YAML utilities
// ---------------------------------------------------------------------------

/// Convert a YAML value to a Vec<String> following Python's `stable_list`.
/// None/null → []; sequence → flattened strings; scalar → [scalar].
fn stable_list(v: Option<&YamlValue>) -> Vec<String> {
    match v {
        None | Some(YamlValue::Null) => vec![],
        Some(YamlValue::Sequence(seq)) => seq.iter().map(yaml_to_string).collect(),
        Some(other) => vec![yaml_to_string(other)],
    }
}

fn yaml_to_string(v: &YamlValue) -> String {
    match v {
        YamlValue::String(s) => s.clone(),
        YamlValue::Number(n) => n.to_string(),
        YamlValue::Bool(b) => b.to_string(),
        YamlValue::Null => String::new(),
        _ => format!("{:?}", v),
    }
}

fn yaml_as_str(v: &YamlValue) -> Option<&str> {
    v.as_str()
}

/// Python repr-style formatting of a YAML scalar.
fn yaml_repr_value(v: &YamlValue) -> String {
    match v {
        YamlValue::Number(n) => n.to_string(),
        YamlValue::String(s) => format!("'{}'", s),
        YamlValue::Bool(b) => b.to_string(),
        YamlValue::Null => "None".to_string(),
        _ => format!("{:?}", v),
    }
}

/// Python repr for an arbitrary YAML value (used for binary path fallback).
fn python_repr_yaml(v: &YamlValue) -> String {
    match v {
        YamlValue::String(s) => format!("'{}'", s),
        YamlValue::Number(n) => n.to_string(),
        YamlValue::Bool(b) => b.to_string(),
        YamlValue::Null => "None".to_string(),
        YamlValue::Mapping(_) => "{...}".to_string(),
        YamlValue::Sequence(_) => "[...]".to_string(),
        _ => format!("{:?}", v),
    }
}

fn append_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn contains_wildcard(host: &str) -> bool {
    host.contains('*')
}

// ---------------------------------------------------------------------------
// Tests — parity against Giedrius's mapper behavior (run on Linux CI too)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fs_policy_yaml(rw: &[&str], ro: &[&str]) -> YamlValue {
        let rw_seq: Vec<&str> = rw.to_vec();
        let ro_seq: Vec<&str> = ro.to_vec();
        serde_yaml::from_str(&format!(
            "filesystem_policy:\n  read_write: {:?}\n  read_only: {:?}\n",
            rw_seq, ro_seq
        ))
        .unwrap()
    }

    #[test]
    fn filesystem_read_write_maps_to_readwrite_paths() {
        let policy = fs_policy_yaml(&["C:\\work\\demo"], &[]);
        let opts = MappingOptions::for_isolation_session("demo");
        let mut items = Vec::new();
        let config = build_mxc_config(&policy, &opts, &mut items);
        assert_eq!(config["filesystem"]["readwritePaths"][0], "C:\\work\\demo");
        assert_eq!(
            config["filesystem"]["readonlyPaths"]
                .as_array()
                .map(|a| a.len()),
            Some(0)
        );
        // Filesystem-only policy: only warnings/info, no errors → not rejected.
        assert_eq!(items.iter().filter(|i| i.severity == "error").count(), 0);
    }

    #[test]
    fn read_only_paths_map_through() {
        let policy = fs_policy_yaml(&[], &["C:\\tools"]);
        let opts = MappingOptions::for_isolation_session("demo");
        let mut items = Vec::new();
        let config = build_mxc_config(&policy, &opts, &mut items);
        assert_eq!(config["filesystem"]["readonlyPaths"][0], "C:\\tools");
    }

    #[test]
    fn network_policy_on_isolation_session_is_an_error_loss() {
        // A network policy with an endpoint host produces an allowedHosts entry,
        // which on isolation_session is an error (rejected by the driver).
        let policy: YamlValue = serde_yaml::from_str(
            "filesystem_policy:\n  read_write: []\n  read_only: []\nnetwork_policies:\n  api:\n    endpoints:\n      - host: example.com\n    binaries:\n      - path: /usr/bin/curl\n",
        )
        .unwrap();
        let opts = MappingOptions::for_isolation_session("demo");
        let mut items = Vec::new();
        let _ = build_mxc_config(&policy, &opts, &mut items);
        assert!(items.iter().any(|i| i.severity == "error"));
    }

    #[test]
    fn type_error_filesystem_is_an_error_loss() {
        let policy: YamlValue = serde_yaml::from_str("filesystem_policy: \"not-a-map\"\n").unwrap();
        let opts = MappingOptions::for_isolation_session("demo");
        let mut items = Vec::new();
        let _ = build_mxc_config(&policy, &opts, &mut items);
        assert!(items.iter().any(|i| i.severity == "error"));
    }
}
