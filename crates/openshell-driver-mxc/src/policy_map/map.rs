// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Coarse OpenShell-policy → MXC `ContainerConfig` mapping.
//!
//! Operates on the typed [`SandboxPolicy`] (parse it with
//! `openshell_policy::parse_sandbox_policy`). Network policy is flattened into
//! an MXC host allowlist; everything MXC cannot express is recorded as a loss
//! item. The top-level `network_policies` map is iterated in sorted key order
//! so the output is deterministic (the proto map is unordered).

use std::net::SocketAddr;

use openshell_core::proto::{NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};
use serde_json::{Value, json};

use super::config::{
    DEFAULT_COMMAND, DEFAULT_CONTAINMENT, DEFAULT_MXC_VERSION, add_backend_network_loss,
    add_backend_specific_config, default_enforcement_mode, filesystem_default_deny_message,
};
use super::loss::{LossItem, add_loss};

/// Options controlling the generated MXC config. Fields not relevant to the
/// coarse map (e.g. `proxy_redirect`) are reserved for the lossless split.
#[derive(Clone, Debug)]
pub struct MxcMappingOptions {
    /// MXC schema version written into `version`.
    pub mxc_version: String,
    /// MXC containment backend.
    pub containment: String,
    /// `process.commandLine` value.
    pub command: String,
    /// Resolved `containerId`.
    pub container_id: String,
    /// Working directory; resolves `filesystem_policy.include_workdir`.
    pub cwd: Option<String>,
    /// `KEY=VALUE` entries added to `process.env`.
    pub env: Vec<String>,
    /// `process.timeout`.
    pub timeout_ms: u64,
    /// Emit `OpenShell` wildcard hosts into `allowedHosts` despite lossiness.
    pub allow_wildcards: bool,
    /// Governed-egress redirect address (used by the lossless split, not the
    /// coarse map).
    pub proxy_redirect: Option<SocketAddr>,
}

impl Default for MxcMappingOptions {
    fn default() -> Self {
        Self {
            mxc_version: DEFAULT_MXC_VERSION.to_owned(),
            containment: DEFAULT_CONTAINMENT.to_owned(),
            command: DEFAULT_COMMAND.to_owned(),
            container_id: "openshell-policy".to_owned(),
            cwd: None,
            env: Vec::new(),
            timeout_ms: 0,
            allow_wildcards: false,
            proxy_redirect: None,
        }
    }
}

/// Result of a coarse mapping: the MXC config plus the loss items.
#[derive(Clone, Debug)]
pub struct MxcMappingResult {
    pub config: Value,
    pub loss: Vec<LossItem>,
}

/// Result of the lossless split: the MXC config carries filesystem grants and a
/// proxy redirect; the full network policy is returned unchanged for the
/// `OpenShell` CONNECT proxy to enforce.
#[derive(Clone, Debug)]
pub struct SplitPolicyResult {
    /// MXC `ContainerConfig` with filesystem grants and `network.proxy` redirect.
    ///
    /// `network.allowedHosts` is empty — direct egress is blocked at the MXC
    /// layer. All outbound connections flow through the proxy; the proxy enforces
    /// the full `OpenShell` network policy.
    pub mxc_config: Value,
    /// Full `OpenShell` network policy preserved verbatim for the host CONNECT
    /// proxy. Only `network_policies` is populated; the proxy does not enforce
    /// filesystem rules.
    pub proxy_policy: SandboxPolicy,
    /// Loss items from the filesystem side only. Network rules produce no losses
    /// here — they are delegated to the proxy rather than approximated.
    pub loss: Vec<LossItem>,
}

/// Map an `OpenShell` policy to a coarse MXC `ContainerConfig`.
pub fn map_to_mxc(policy: &SandboxPolicy, opts: &MxcMappingOptions) -> MxcMappingResult {
    let mut loss = Vec::new();
    let config = build_mxc_config(policy, opts, &mut loss);
    MxcMappingResult { config, loss }
}

/// Lossless split: map filesystem + containment to MXC, delegate network to the
/// `OpenShell` CONNECT proxy.
///
/// The returned [`SplitPolicyResult::mxc_config`] sets `network.proxy` to
/// `opts.proxy_redirect` and leaves `allowedHosts` empty — direct
/// egress is blocked at the MXC layer and all outbound connections flow through
/// the proxy. [`SplitPolicyResult::proxy_policy`] carries the original
/// `network_policies` verbatim; no binary-scope, port, protocol, or wildcard
/// loss items are generated for the network side.
///
/// Returns `None` if `opts.proxy_redirect` is not set. Use [`map_to_mxc`]
/// for the standalone coarse path when no proxy is in the loop.
pub fn split_policy(policy: &SandboxPolicy, opts: &MxcMappingOptions) -> Option<SplitPolicyResult> {
    let proxy_addr = opts.proxy_redirect?;
    let mut loss = Vec::new();
    let mxc_config = build_split_mxc_config(policy, opts, proxy_addr, &mut loss);
    let proxy_policy = SandboxPolicy {
        version: policy.version,
        network_policies: policy.network_policies.clone(),
        network_middlewares: policy.network_middlewares.clone(),
        ..Default::default()
    };
    Some(SplitPolicyResult {
        mxc_config,
        proxy_policy,
        loss,
    })
}

fn build_split_mxc_config(
    policy: &SandboxPolicy,
    opts: &MxcMappingOptions,
    proxy_addr: SocketAddr,
    items: &mut Vec<LossItem>,
) -> Value {
    let mut process = json!({
        "commandLine": opts.command,
        "timeout": opts.timeout_ms,
    });
    if let Some(cwd) = &opts.cwd {
        process["cwd"] = json!(cwd);
    }
    if !opts.env.is_empty() {
        process["env"] = json!(opts.env);
    }

    let filesystem = map_filesystem(policy, opts, items);

    let proxy_supported = matches!(opts.containment.as_str(), "processcontainer" | "process");
    if !proxy_supported {
        add_loss(
            items,
            "containment",
            "error",
            &format!(
                "`network.proxy` is not supported on `{}`; governed egress requires processcontainer until MXC M1 lands.",
                opts.containment
            ),
            "governed egress proxy redirect",
            "The generated MXC config omits network.proxy for this backend.",
        );
    }
    if !policy.network_policies.is_empty() {
        add_loss(
            items,
            "network_policies",
            "info",
            &format!(
                "{} network rule(s) delegated to the OpenShell host CONNECT proxy.",
                policy.network_policies.len()
            ),
            "governed egress",
            "The host proxy receives the trimmed policy and enforces network rules.",
        );
    }

    // Direct egress is blocked; all outbound flows through the OpenShell proxy.
    // allowedHosts is intentionally empty — the proxy enforces the full policy.
    //
    // MXC 0.6.0-alpha schema accepts ONLY {"proxy": {"localhost": <port>}}.
    // {"host": ..., "port": ...} and every other shape is rejected — verified
    // empirically against the real wxc-exec 0.6.0-alpha binary via --dry-run.
    if proxy_supported && proxy_addr.ip() != std::net::IpAddr::from([127, 0, 0, 1]) {
        add_loss(
            items,
            "network.proxy",
            "error",
            &format!(
                "MXC schema 0.6.0-alpha can only express a localhost port \
                 ({{\"localhost\": N}}); non-127.0.0.1 redirect address \
                 {proxy_addr} is not representable."
            ),
            "per-sandbox egress attribution",
            "The redirect cannot be emitted; use a 127.0.0.1:PORT address.",
        );
    }
    let mut network = json!({
        "defaultPolicy": "block",
        "allowedHosts": [],
        "blockedHosts": [],
    });
    if proxy_supported && proxy_addr.ip() == std::net::IpAddr::from([127, 0, 0, 1]) {
        network["proxy"] = json!({ "localhost": proxy_addr.port() });
    }

    let mut config = json!({
        "version": opts.mxc_version,
        "containerId": opts.container_id,
        "containment": opts.containment,
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

    // No network hosts, so backend-specific network blocks (processContainer
    // internetClient, etc.) are not added — correct for the proxy path.
    add_backend_specific_config(&mut config, &opts.containment, &[], items);
    add_static_policy_loss(policy, opts, items);
    config
}

fn build_mxc_config(
    policy: &SandboxPolicy,
    opts: &MxcMappingOptions,
    items: &mut Vec<LossItem>,
) -> Value {
    let mut process = json!({
        "commandLine": opts.command,
        "timeout": opts.timeout_ms,
    });
    if let Some(cwd) = &opts.cwd {
        process["cwd"] = json!(cwd);
    }
    if !opts.env.is_empty() {
        process["env"] = json!(opts.env);
    }

    let filesystem = map_filesystem(policy, opts, items);
    let allowed_hosts = map_network(policy, opts, items);

    let mut network = json!({
        "defaultPolicy": "block",
        "allowedHosts": allowed_hosts,
        "blockedHosts": [],
    });
    if let Some(mode) = default_enforcement_mode(&opts.containment, &allowed_hosts) {
        network["enforcementMode"] = json!(mode);
    }

    let mut config = json!({
        "version": opts.mxc_version,
        "containerId": opts.container_id,
        "containment": opts.containment,
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

    add_backend_specific_config(&mut config, &opts.containment, &allowed_hosts, items);
    add_static_policy_loss(policy, opts, items);
    config
}

fn map_filesystem(
    policy: &SandboxPolicy,
    opts: &MxcMappingOptions,
    items: &mut Vec<LossItem>,
) -> Value {
    let mut readwrite: Vec<String> = Vec::new();
    let mut readonly: Vec<String> = Vec::new();

    match &policy.filesystem {
        Some(fs) => {
            readwrite.clone_from(&fs.read_write);
            readonly.clone_from(&fs.read_only);
            if fs.include_workdir {
                if let Some(cwd) = &opts.cwd {
                    append_unique(&mut readwrite, cwd.clone());
                } else {
                    add_loss(
                        items,
                        "filesystem_policy.include_workdir",
                        "info",
                        "OpenShell includes the runtime workdir, but no --cwd was supplied.",
                        "include_workdir",
                        "The generated MXC config cannot add the workdir path grant.",
                    );
                }
            }
        }
        None => add_loss(
            items,
            "filesystem_policy",
            "warning",
            "No OpenShell filesystem_policy was present.",
            "default filesystem policy",
            "MXC receives empty filesystem lists; backend defaults determine visibility.",
        ),
    }

    add_loss(
        items,
        "filesystem_policy",
        "warning",
        &filesystem_default_deny_message(&opts.containment),
        "OpenShell Landlock/default-deny filesystem model",
        "MXC filesystem default-deny parity is backend-specific.",
    );

    json!({
        "readwritePaths": readwrite,
        "readonlyPaths": readonly,
        "deniedPaths": [],
    })
}

fn map_network(
    policy: &SandboxPolicy,
    opts: &MxcMappingOptions,
    items: &mut Vec<LossItem>,
) -> Vec<String> {
    if !policy.network_middlewares.is_empty() {
        add_loss(
            items,
            "network_middlewares",
            "error",
            &format!(
                "{} network middleware config(s) require the OpenShell host proxy and cannot be enforced by MXC directly.",
                policy.network_middlewares.len()
            ),
            "network egress middleware",
            "Middleware transformations and failure behavior would not be applied on the coarse MXC path.",
        );
    }

    if policy.network_policies.is_empty() {
        add_backend_network_loss(policy, &opts.containment, items);
        return Vec::new();
    }

    // The proto map is unordered; sort by rule key for deterministic output.
    let mut rules: Vec<(&String, &NetworkPolicyRule)> = policy.network_policies.iter().collect();
    rules.sort_by(|a, b| a.0.cmp(b.0));

    let mut allowed_hosts: Vec<String> = Vec::new();

    for (key, rule) in rules {
        let rule_path = format!("network_policies.{key}");

        if rule.endpoints.is_empty() {
            add_loss(
                items,
                &format!("{rule_path}.endpoints"),
                "error",
                "OpenShell policy entry has no endpoints.",
                "network endpoints",
                "No MXC host allowlist entries were produced for this policy.",
            );
        }
        for (index, endpoint) in rule.endpoints.iter().enumerate() {
            let endpoint_path = format!("{rule_path}.endpoints[{index}]");
            map_endpoint(endpoint, &endpoint_path, &mut allowed_hosts, opts, items);
        }

        if rule.binaries.is_empty() {
            add_loss(
                items,
                &format!("{rule_path}.binaries"),
                "error",
                "OpenShell requires binary-scoped network grants; this entry has no binaries.",
                "binary-scoped network policy",
                "MXC cannot represent per-binary grants and scopes network to the sandbox.",
            );
        } else {
            for (index, binary) in rule.binaries.iter().enumerate() {
                add_loss(
                    items,
                    &format!("{rule_path}.binaries[{index}].path"),
                    "error",
                    &format!(
                        "Binary scope is not representable in MXC: '{}'.",
                        binary.path
                    ),
                    "binary-scoped network policy",
                    "Dropping this would broaden access from one executable to the whole sandbox.",
                );
            }
        }
    }

    add_backend_network_loss(policy, &opts.containment, items);
    allowed_hosts
}

fn map_endpoint(
    endpoint: &NetworkEndpoint,
    path: &str,
    allowed_hosts: &mut Vec<String>,
    opts: &MxcMappingOptions,
    items: &mut Vec<LossItem>,
) {
    // host
    if endpoint.host.is_empty() {
        add_loss(
            items,
            &format!("{path}.host"),
            "error",
            "Endpoint has no host.",
            "network endpoint host",
            "Endpoint was not added to MXC allowedHosts.",
        );
    } else if contains_wildcard(&endpoint.host) {
        let (message, impact) = if opts.allow_wildcards {
            append_unique(allowed_hosts, endpoint.host.clone());
            (
                format!(
                    "Wildcard host emitted despite non-portable MXC semantics: {}.",
                    endpoint.host
                ),
                "Backend behavior is not portable and may fail or broaden access.",
            )
        } else {
            (
                format!(
                    "Wildcard host omitted because MXC has no portable syntax: {}.",
                    endpoint.host
                ),
                "Generated MXC config is more restrictive for this endpoint.",
            )
        };
        add_loss(
            items,
            &format!("{path}.host"),
            "error",
            &message,
            "OpenShell wildcard host matching",
            impact,
        );
    } else {
        append_unique(allowed_hosts, endpoint.host.clone());
    }

    // port / ports (the proto normalizes a single port into `ports`)
    if !endpoint.ports.is_empty() {
        let (field, repr) = if endpoint.ports.len() == 1 {
            ("port", endpoint.ports[0].to_string())
        } else {
            ("ports", format!("{:?}", endpoint.ports))
        };
        add_loss(
            items,
            &format!("{path}.{field}"),
            "error",
            &format!("MXC allowedHosts cannot encode port constraint {repr}."),
            "port-scoped outbound policy",
            "MXC allows or blocks the host as a whole.",
        );
    }

    // allowed_ips
    for ip in &endpoint.allowed_ips {
        append_unique(allowed_hosts, ip.clone());
        add_loss(
            items,
            &format!("{path}.allowed_ips"),
            "warning",
            &format!(
                "MXC can carry CIDR/IP '{ip}', but cannot bind it to DNS for '{}'.",
                endpoint.host
            ),
            "DNS result pinning / SSRF override",
            "The CIDR/IP becomes a standalone allowed destination.",
        );
    }

    report_endpoint_l7_losses(endpoint, path, items);
}

fn report_endpoint_l7_losses(endpoint: &NetworkEndpoint, path: &str, items: &mut Vec<LossItem>) {
    if !endpoint.protocol.is_empty() {
        add_loss(
            items,
            &format!("{path}.protocol"),
            "error",
            &format!(
                "MXC has no protocol-aware policy equivalent for '{}'.",
                endpoint.protocol
            ),
            "protocol-aware proxy policy",
            "MXC host filtering cannot enforce REST/WebSocket/GraphQL semantics.",
        );
    }

    if !endpoint.tls.is_empty() {
        let severity = if endpoint.tls == "skip" {
            "warning"
        } else {
            "error"
        };
        add_loss(
            items,
            &format!("{path}.tls"),
            severity,
            &format!(
                "MXC has no OpenShell TLS inspection mode equivalent for '{}'.",
                endpoint.tls
            ),
            "TLS inspection mode",
            "MXC network policy is host-level only.",
        );
    }

    if !endpoint.enforcement.is_empty() {
        if endpoint.enforcement == "audit" {
            add_loss(
                items,
                &format!("{path}.enforcement"),
                "error",
                "MXC has no audit-only network policy mode.",
                "audit-mode endpoint",
                "Generated MXC config enforces host-level default block instead.",
            );
        } else {
            add_loss(
                items,
                &format!("{path}.enforcement"),
                "warning",
                "MXC enforcementMode is backend-wide, not per endpoint.",
                "per-endpoint enforcement",
                "The mapper chooses a backend-level enforcement mode.",
            );
        }
    }

    if !endpoint.access.is_empty() {
        add_loss(
            items,
            &format!("{path}.access"),
            "error",
            &format!(
                "MXC has no access preset equivalent for '{}'.",
                endpoint.access
            ),
            "REST/WebSocket/GraphQL access preset",
            "MXC cannot enforce method or operation-level access.",
        );
    }

    if !endpoint.rules.is_empty() {
        add_loss(
            items,
            &format!("{path}.rules"),
            "error",
            "MXC has no L7 allow-rule equivalent.",
            "REST/WebSocket/GraphQL allow rules",
            "Method/path/query/operation restrictions are lost.",
        );
    }

    if !endpoint.deny_rules.is_empty() {
        add_loss(
            items,
            &format!("{path}.deny_rules"),
            "error",
            "MXC has no L7 deny-rule equivalent.",
            "L7 deny rules",
            "Deny precedence over broad allows is lost.",
        );
    }

    let bool_losses: &[(bool, &str, &str)] = &[
        (
            endpoint.allow_encoded_slash,
            "allow_encoded_slash",
            "encoded slash handling",
        ),
        (
            endpoint.websocket_credential_rewrite,
            "websocket_credential_rewrite",
            "WebSocket credential rewrite",
        ),
        (
            endpoint.request_body_credential_rewrite,
            "request_body_credential_rewrite",
            "request-body credential rewrite",
        ),
    ];
    for (set, field, feature) in bool_losses {
        if *set {
            add_loss(
                items,
                &format!("{path}.{field}"),
                "error",
                &format!("MXC has no equivalent for {feature}."),
                feature,
                "Generated config cannot preserve this proxy behavior.",
            );
        }
    }

    // GraphQL
    if !endpoint.persisted_queries.is_empty() {
        add_graphql_loss(items, path, "persisted_queries");
    }
    if !endpoint.graphql_persisted_queries.is_empty() {
        add_graphql_loss(items, path, "graphql_persisted_queries");
    }
    if endpoint.graphql_max_body_bytes > 0 {
        add_graphql_loss(items, path, "graphql_max_body_bytes");
    }
}

fn add_graphql_loss(items: &mut Vec<LossItem>, path: &str, field: &str) {
    add_loss(
        items,
        &format!("{path}.{field}"),
        "error",
        &format!("MXC has no GraphQL policy equivalent for {field}."),
        "GraphQL operation policy",
        "GraphQL inspection and persisted-query behavior is lost.",
    );
}

fn add_static_policy_loss(
    policy: &SandboxPolicy,
    opts: &MxcMappingOptions,
    items: &mut Vec<LossItem>,
) {
    if policy.landlock.is_some() {
        add_loss(
            items,
            "landlock",
            "warning",
            "MXC has no Landlock compatibility mode field.",
            "Landlock LSM enforcement",
            "Backend filesystem controls may not fail like OpenShell best_effort/hard_requirement.",
        );
    }

    if let Some(process) = &policy.process {
        if !process.run_as_user.is_empty() {
            add_process_identity_loss(items, "run_as_user");
        }
        if !process.run_as_group.is_empty() {
            add_process_identity_loss(items, "run_as_group");
        }
    }

    if opts.containment == "processcontainer"
        && let Some(fs) = &policy.filesystem
    {
        let any_linux_path = fs
            .read_only
            .iter()
            .chain(fs.read_write.iter())
            .any(|p| p.starts_with('/'));
        if any_linux_path {
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

fn add_process_identity_loss(items: &mut Vec<LossItem>, field: &str) {
    add_loss(
        items,
        &format!("process.{field}"),
        "warning",
        &format!("MXC has no portable equivalent for OpenShell {field}."),
        "process identity",
        "MXC backend identity is selected outside this policy mapping.",
    );
}

fn append_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn contains_wildcard(host: &str) -> bool {
    host.contains('*')
}
