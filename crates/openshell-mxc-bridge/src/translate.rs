// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure translation from OpenShell policy types to MXC `ContainerConfig`.
//!
//! Mirrors the upstream `mxc-aegis` SDK's `createConfigFromPolicy()`
//! (`sdk/src/sandbox.ts:143–206`) with the OpenShell type system as the
//! input shape (proto [`SandboxPolicy`] baseline +
//! [`EnvelopePolicy`] per-task envelope) and either the alpha or dev MXC
//! schema as the output shape.
//!
//! Composition rule: when an envelope is supplied, it is composed against
//! the baseline via [`openshell_policy::compose_envelope`] and the resulting
//! `EffectiveEnvelope` drives the path/network/timeout fields. When no
//! envelope is supplied, the baseline alone determines those fields and a
//! best-effort default of "deny everything not explicitly allowed" is used.
//!
//! No I/O. No filesystem reads. No process spawns. Driver crates own
//! execution; this module just builds the JSON.

use std::collections::BTreeSet;

use openshell_core::proto::SandboxPolicy;
use openshell_policy::{EffectiveEnvelope, EnvelopePolicy, compose_envelope};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::invoke::Schema;
use crate::{schema_alpha, schema_dev};

/// Output container configuration. Wraps the per-schema strongly typed
/// configs so callers can serialise either variant uniformly via
/// [`ContainerConfig::to_json`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ContainerConfig {
    Alpha(Box<schema_alpha::ContainerConfig>),
    Dev(Box<schema_dev::ContainerConfig>),
}

impl ContainerConfig {
    /// Serialise to a compact JSON string suitable for `--config-base64`.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Schema discriminant for this config.
    #[must_use]
    pub const fn schema(&self) -> Schema {
        match self {
            Self::Alpha(_) => Schema::AlphaProcess,
            Self::Dev(_) => Schema::DevIsolationSession,
        }
    }

    /// Borrow the alpha variant if this is an alpha config.
    #[must_use]
    pub fn as_alpha(&self) -> Option<&schema_alpha::ContainerConfig> {
        match self {
            Self::Alpha(cfg) => Some(cfg.as_ref()),
            Self::Dev(_) => None,
        }
    }

    /// Borrow the dev variant if this is a dev config.
    #[must_use]
    pub fn as_dev(&self) -> Option<&schema_dev::ContainerConfig> {
        match self {
            Self::Dev(cfg) => Some(cfg.as_ref()),
            Self::Alpha(_) => None,
        }
    }
}

/// Translation options that don't fit the policy/envelope inputs.
#[derive(Debug, Clone, Default)]
pub struct TranslateOptions {
    /// Target schema (alpha AppContainer vs. dev IsolationSession).
    pub schema: Schema,
    /// Container identifier to embed in `containerId`. Callers are
    /// expected to provide one — this crate is pure and will not generate
    /// random identifiers (driver crates own that policy).
    pub container_id: Option<String>,
    /// AppContainer profile name (alpha schema only). When `None` the
    /// `appContainer.name` field is set to `container_id` if available,
    /// matching the SDK's `containerName` parameter.
    pub app_container_name: Option<String>,
    /// Pre-registered configuration identifier for the IsolationSession
    /// broker (dev schema only). When `None`, the experimental block omits
    /// the field.
    pub isolation_session_configuration_id: Option<String>,
    /// Whether the deployment target is Linux. The upstream SDK rejects
    /// `proxy` on Linux; this crate honours that rule.
    pub is_linux_target: bool,
    /// Optional baseline override for the SDK's `clearPolicyOnExit` flag.
    /// `None` (the common case) preserves the SDK default of `true`,
    /// producing `lifecycle.preservePolicy = false`.
    pub clear_policy_on_exit: Option<bool>,
    /// Optional UI policy. Defaults to most-restrictive when `None`.
    pub ui: Option<UiPolicy>,
    /// Optional proxy configuration. Mirrors the SDK's `network.proxy`.
    pub proxy: Option<schema_alpha::Proxy>,
}

/// Cross-platform UI policy (mirrors the SDK's `SandboxPolicy.ui`).
///
/// OpenShell's proto `SandboxPolicy` has no UI surface; callers wishing to
/// loosen the most-restrictive default must supply this explicitly.
#[derive(Debug, Clone, Default)]
pub struct UiPolicy {
    /// Whether the sandbox may create visible windows.
    pub allow_windows: bool,
    /// Clipboard access level.
    pub clipboard: schema_alpha::ClipboardPolicy,
    /// Whether the sandbox may inject keyboard/mouse input.
    pub allow_input_injection: bool,
}

/// Errors returned by [`translate`].
#[derive(Debug, Error)]
pub enum TranslateError {
    /// `allowedHosts` / `blockedHosts` were configured but the envelope
    /// disabled outbound network access. Mirrors the upstream SDK rule.
    #[error(
        "allowedHosts/blockedHosts require outbound network access (envelope.network_enabled = true)"
    )]
    HostsRequireOutbound,

    /// Proxy configuration is not supported on Linux.
    #[error("proxy configuration is not supported on Linux")]
    ProxyOnLinux,

    /// The selected schema does not support a feature requested via options
    /// (e.g. AppContainer-specific naming on the dev schema).
    #[error("invalid option for schema {schema:?}: {message}")]
    InvalidOptionForSchema { schema: Schema, message: String },
}

/// Translate baseline policy + optional envelope into a `ContainerConfig`
/// matching `opts.schema`.
///
/// # Errors
///
/// Returns a [`TranslateError`] when validation rules are violated; see
/// the variants for the specific conditions.
pub fn translate(
    policy: &SandboxPolicy,
    envelope: Option<&EnvelopePolicy>,
    opts: &TranslateOptions,
) -> Result<ContainerConfig, TranslateError> {
    match opts.schema {
        Schema::AlphaProcess => {
            translate_alpha(policy, envelope, opts).map(|cfg| ContainerConfig::Alpha(Box::new(cfg)))
        }
        Schema::DevIsolationSession => {
            translate_dev(policy, envelope, opts).map(|cfg| ContainerConfig::Dev(Box::new(cfg)))
        }
    }
}

/// Translate to a `0.5.0-alpha` AppContainer config.
///
/// # Errors
///
/// See [`translate`].
pub fn translate_alpha(
    policy: &SandboxPolicy,
    envelope: Option<&EnvelopePolicy>,
    opts: &TranslateOptions,
) -> Result<schema_alpha::ContainerConfig, TranslateError> {
    let composed = compose_or_baseline(policy, envelope);
    let allowed_hosts = collect_allowed_hosts(policy);

    validate_network(&composed, &allowed_hosts, opts)?;

    let lifecycle = build_lifecycle(opts);
    let process = build_process(&composed);
    let filesystem = build_filesystem(&composed);
    let network = build_network(&composed, allowed_hosts, opts.proxy.clone());
    let ui = Some(build_ui(opts));

    let app_container = Some(build_app_container(
        opts,
        composed.network_enabled,
        composed.allow_local_network,
    ));

    // Mirror upstream: when network is configured, force enforcementMode = "both".
    let network = network.map(|mut n| {
        n.enforcement_mode = Some(schema_alpha::EnforcementMode::Both);
        n
    });

    Ok(schema_alpha::ContainerConfig {
        version: schema_alpha::SCHEMA_VERSION.to_owned(),
        container_id: opts.container_id.clone(),
        lifecycle: Some(lifecycle),
        process: Some(process),
        app_container,
        filesystem: Some(filesystem),
        network,
        ui,
    })
}

/// Translate to a `0.6.0-dev` IsolationSession config.
///
/// # Errors
///
/// See [`translate`].
pub fn translate_dev(
    policy: &SandboxPolicy,
    envelope: Option<&EnvelopePolicy>,
    opts: &TranslateOptions,
) -> Result<schema_dev::ContainerConfig, TranslateError> {
    if opts.app_container_name.is_some() {
        return Err(TranslateError::InvalidOptionForSchema {
            schema: Schema::DevIsolationSession,
            message: "app_container_name has no effect on the IsolationSession schema".to_owned(),
        });
    }

    let composed = compose_or_baseline(policy, envelope);
    let allowed_hosts = collect_allowed_hosts(policy);

    validate_network(&composed, &allowed_hosts, opts)?;

    let lifecycle = build_lifecycle(opts);
    let process = build_process(&composed);
    let filesystem = build_filesystem(&composed);
    let network = build_network(&composed, allowed_hosts, opts.proxy.clone());
    let ui = Some(build_ui(opts));

    let experimental = schema_dev::Experimental {
        isolation_session: Some(schema_dev::IsolationSessionConfig {
            configuration_id: opts.isolation_session_configuration_id.clone(),
        }),
    };

    Ok(schema_dev::ContainerConfig {
        version: schema_dev::SCHEMA_VERSION.to_owned(),
        container_id: opts.container_id.clone(),
        containment: schema_dev::Containment::IsolationSession,
        lifecycle: Some(lifecycle),
        process: Some(process),
        filesystem: Some(filesystem),
        network,
        ui,
        experimental,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn compose_or_baseline(
    policy: &SandboxPolicy,
    envelope: Option<&EnvelopePolicy>,
) -> EffectiveEnvelope {
    if let Some(env) = envelope {
        return compose_envelope(policy, env);
    }

    // No envelope: derive a baseline-only "effective" view. Path lists come
    // straight from the baseline filesystem block; network is allowed only
    // when the baseline carries at least one named network policy (matches
    // the heuristic in `compose_envelope`).
    let (read_only, read_write) = policy.filesystem.as_ref().map_or_else(
        || (Vec::new(), Vec::new()),
        |fs| (fs.read_only.clone(), fs.read_write.clone()),
    );
    let baseline_allows_network = !policy.network_policies.is_empty();

    EffectiveEnvelope {
        readwrite_paths: read_write,
        readonly_paths: read_only,
        denied_paths: Vec::new(),
        network_enabled: baseline_allows_network,
        // ASSUMPTION: baseline can't currently express local-network access;
        // default to false to match the most-restrictive policy posture
        // unless the envelope says otherwise.
        allow_local_network: false,
        timeout_ms: 0,
        sandbox_profile: String::new(),
    }
}

fn collect_allowed_hosts(policy: &SandboxPolicy) -> Vec<String> {
    let mut hosts: BTreeSet<&str> = BTreeSet::new();
    for rule in policy.network_policies.values() {
        for endpoint in &rule.endpoints {
            if !endpoint.host.is_empty() {
                hosts.insert(endpoint.host.as_str());
            }
        }
    }
    hosts.into_iter().map(str::to_owned).collect()
}

fn validate_network(
    composed: &EffectiveEnvelope,
    allowed_hosts: &[String],
    opts: &TranslateOptions,
) -> Result<(), TranslateError> {
    if !composed.network_enabled && !allowed_hosts.is_empty() {
        return Err(TranslateError::HostsRequireOutbound);
    }

    if opts.proxy.is_some() && opts.is_linux_target {
        return Err(TranslateError::ProxyOnLinux);
    }

    Ok(())
}

fn build_lifecycle(opts: &TranslateOptions) -> schema_alpha::LifecycleConfig {
    // SDK default: clearPolicyOnExit = true → preservePolicy = false.
    let clear_policy = opts.clear_policy_on_exit.unwrap_or(true);
    schema_alpha::LifecycleConfig {
        destroy_on_exit: Some(true),
        preserve_policy: Some(!clear_policy),
    }
}

fn build_process(composed: &EffectiveEnvelope) -> schema_alpha::ProcessConfig {
    schema_alpha::ProcessConfig {
        // Driver crates fill commandLine before invoking wxc-exec.
        command_line: String::new(),
        cwd: None,
        env: Vec::new(),
        timeout: if composed.timeout_ms == 0 {
            None
        } else {
            Some(composed.timeout_ms)
        },
    }
}

fn build_filesystem(composed: &EffectiveEnvelope) -> schema_alpha::FilesystemConfig {
    schema_alpha::FilesystemConfig {
        readwrite_paths: composed.readwrite_paths.clone(),
        readonly_paths: composed.readonly_paths.clone(),
        denied_paths: composed.denied_paths.clone(),
    }
}

fn build_network(
    composed: &EffectiveEnvelope,
    allowed_hosts: Vec<String>,
    proxy: Option<schema_alpha::Proxy>,
) -> Option<schema_alpha::NetworkConfig> {
    // Match the SDK: only emit a network block when the baseline has
    // *something* network-shaped to say. Either outbound is enabled, hosts
    // are listed, or a proxy is configured.
    if !composed.network_enabled && allowed_hosts.is_empty() && proxy.is_none() {
        return None;
    }

    Some(schema_alpha::NetworkConfig {
        enforcement_mode: None, // alpha-translator overwrites to Both below
        default_policy: Some(if composed.network_enabled {
            schema_alpha::DefaultNetworkPolicy::Allow
        } else {
            schema_alpha::DefaultNetworkPolicy::Block
        }),
        allowed_hosts,
        blocked_hosts: Vec::new(),
        proxy,
    })
}

fn build_ui(opts: &TranslateOptions) -> schema_alpha::UiConfig {
    opts.ui
        .as_ref()
        .map_or_else(schema_alpha::UiConfig::default, |u| {
            schema_alpha::UiConfig {
                disable: !u.allow_windows,
                clipboard: u.clipboard,
                injection: u.allow_input_injection,
            }
        })
}

fn build_app_container(
    opts: &TranslateOptions,
    network_enabled: bool,
    allow_local_network: bool,
) -> schema_alpha::AppContainerConfig {
    let mut capabilities: Vec<String> = Vec::new();
    if network_enabled {
        capabilities.push("internetClient".to_owned());
    }
    if allow_local_network {
        capabilities.push("privateNetworkClientServer".to_owned());
    }

    let name = opts
        .app_container_name
        .clone()
        .or_else(|| opts.container_id.clone());

    schema_alpha::AppContainerConfig {
        name,
        least_privilege: Some(false),
        capabilities,
        ui: Some(schema_alpha::BaseProcessUiConfig::default()),
    }
}
