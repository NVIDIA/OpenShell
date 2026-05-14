// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the policy → MXC `ContainerConfig` translator.
//!
//! These cover the validation rules ported verbatim from
//! `mxc-aegis/sdk/src/sandbox.ts:143–206` plus the OpenShell-specific
//! envelope composition behaviour.

use std::collections::HashMap;
use std::path::PathBuf;

use openshell_core::proto::{FilesystemPolicy, NetworkEndpoint, NetworkPolicyRule, SandboxPolicy};
use openshell_mxc_bridge::schema_alpha::{
    ClipboardPolicy, DefaultNetworkPolicy, EnforcementMode, Proxy, UiConfig,
};
use openshell_mxc_bridge::{
    Schema, TranslateError, TranslateOptions, build_invocation, schema_dev, translate,
    translate_alpha, translate_dev,
};
use openshell_policy::EnvelopePolicy;

fn baseline_with_fs(read_only: Vec<&str>, read_write: Vec<&str>) -> SandboxPolicy {
    SandboxPolicy {
        version: 1,
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: read_only.into_iter().map(str::to_owned).collect(),
            read_write: read_write.into_iter().map(str::to_owned).collect(),
        }),
        landlock: None,
        process: None,
        network_policies: HashMap::new(),
    }
}

fn baseline_with_network(host: &str) -> SandboxPolicy {
    let mut policy = baseline_with_fs(vec![], vec![]);
    policy.network_policies.insert(
        "rule".to_owned(),
        NetworkPolicyRule {
            name: "rule".to_owned(),
            endpoints: vec![NetworkEndpoint {
                host: host.to_owned(),
                port: 443,
                ..NetworkEndpoint::default()
            }],
            binaries: vec![],
        },
    );
    policy
}

#[test]
fn round_trip_minimal_policy_alpha_schema() {
    let baseline = baseline_with_fs(vec!["/usr"], vec!["/tmp"]);
    let envelope = EnvelopePolicy {
        readwrite_paths: vec!["/tmp".to_owned()],
        readonly_paths: vec!["/usr".to_owned()],
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        container_id: Some("box-1".to_owned()),
        ..TranslateOptions::default()
    };

    let cfg = translate(&baseline, Some(&envelope), &opts).expect("translates");
    let alpha = cfg.as_alpha().expect("alpha variant");

    assert_eq!(alpha.version, "0.5.0-alpha");
    assert_eq!(alpha.container_id.as_deref(), Some("box-1"));
    assert_eq!(
        alpha.filesystem.as_ref().expect("fs").readwrite_paths,
        vec!["/tmp".to_owned()]
    );
    assert!(
        alpha
            .filesystem
            .as_ref()
            .expect("fs")
            .readonly_paths
            .contains(&"/usr".to_owned())
    );

    // No baseline network rule + envelope.network_enabled=false => no network block.
    assert!(alpha.network.is_none());

    // AppContainer block always present, with no network capabilities.
    let app = alpha.app_container.as_ref().expect("appContainer");
    assert!(app.capabilities.is_empty());
    assert_eq!(app.name.as_deref(), Some("box-1"));

    // Default lifecycle: clearPolicyOnExit=true => preservePolicy=false.
    let lc = alpha.lifecycle.as_ref().expect("lifecycle");
    assert_eq!(lc.preserve_policy, Some(false));
    assert_eq!(lc.destroy_on_exit, Some(true));

    // Default UI = most-restrictive.
    let ui = alpha.ui.as_ref().expect("ui");
    assert!(ui.disable);
    assert!(matches!(ui.clipboard, ClipboardPolicy::None));
    assert!(!ui.injection);

    // Round-trips through JSON.
    let json = cfg.to_json().expect("serialises");
    assert!(json.contains("\"version\":\"0.5.0-alpha\""));
    assert!(json.contains("\"appContainer\""));
}

#[test]
fn allowed_hosts_without_outbound_returns_error() {
    let baseline = baseline_with_network("api.example.com");
    let envelope = EnvelopePolicy {
        network_enabled: false,
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ..TranslateOptions::default()
    };

    let err = translate_alpha(&baseline, Some(&envelope), &opts).unwrap_err();
    assert!(matches!(err, TranslateError::HostsRequireOutbound));
}

#[test]
fn baseline_network_with_envelope_outbound_allowed() {
    let baseline = baseline_with_network("api.example.com");
    let envelope = EnvelopePolicy {
        network_enabled: true,
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        container_id: Some("box".to_owned()),
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, Some(&envelope), &opts).expect("translates");
    let net = cfg.network.expect("network block");
    assert!(matches!(
        net.default_policy,
        Some(DefaultNetworkPolicy::Allow)
    ));
    assert!(matches!(net.enforcement_mode, Some(EnforcementMode::Both)));
    assert_eq!(net.allowed_hosts, vec!["api.example.com".to_owned()]);

    let app = cfg.app_container.expect("appContainer");
    assert!(app.capabilities.iter().any(|c| c == "internetClient"));
    assert!(
        !app.capabilities
            .iter()
            .any(|c| c == "privateNetworkClientServer")
    );
}

#[test]
fn allow_local_network_adds_private_network_capability() {
    let baseline = baseline_with_network("api.example.com");
    let envelope = EnvelopePolicy {
        network_enabled: true,
        allow_local_network: true,
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, Some(&envelope), &opts).expect("translates");
    let app = cfg.app_container.expect("appContainer");
    assert!(app.capabilities.iter().any(|c| c == "internetClient"));
    assert!(
        app.capabilities
            .iter()
            .any(|c| c == "privateNetworkClientServer")
    );
}

#[test]
fn proxy_on_linux_target_rejected() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        is_linux_target: true,
        proxy: Some(Proxy::Localhost { localhost: 8080 }),
        ..TranslateOptions::default()
    };

    let err = translate_alpha(&baseline, None, &opts).unwrap_err();
    assert!(matches!(err, TranslateError::ProxyOnLinux));
}

#[test]
fn proxy_on_windows_target_passes_through() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        is_linux_target: false,
        proxy: Some(Proxy::Localhost { localhost: 9090 }),
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, None, &opts).expect("translates");
    let net = cfg.network.expect("network block (proxy forces it)");
    assert!(matches!(
        net.proxy,
        Some(Proxy::Localhost { localhost: 9090 })
    ));
}

#[test]
fn clear_policy_on_exit_explicit_false_preserves_policy() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        clear_policy_on_exit: Some(false),
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, None, &opts).expect("translates");
    assert_eq!(
        cfg.lifecycle.expect("lifecycle").preserve_policy,
        Some(true)
    );
}

#[test]
fn clear_policy_on_exit_default_true_clears_policy() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        clear_policy_on_exit: None,
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, None, &opts).expect("translates");
    assert_eq!(
        cfg.lifecycle.expect("lifecycle").preserve_policy,
        Some(false)
    );
}

#[test]
fn timeout_propagates_from_envelope() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let envelope = EnvelopePolicy {
        timeout_ms: 5_000,
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, Some(&envelope), &opts).expect("translates");
    assert_eq!(cfg.process.expect("process").timeout, Some(5_000));
}

#[test]
fn ui_policy_overrides_default() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ui: Some(openshell_mxc_bridge::UiPolicy {
            allow_windows: true,
            clipboard: ClipboardPolicy::Read,
            allow_input_injection: true,
        }),
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, None, &opts).expect("translates");
    let ui: UiConfig = cfg.ui.expect("ui");
    assert!(!ui.disable);
    assert!(matches!(ui.clipboard, ClipboardPolicy::Read));
    assert!(ui.injection);
}

#[test]
fn dev_schema_sets_isolation_session_containment() {
    let baseline = baseline_with_fs(vec!["/usr"], vec!["/tmp"]);
    let opts = TranslateOptions {
        schema: Schema::DevIsolationSession,
        container_id: Some("iso-1".to_owned()),
        isolation_session_configuration_id: Some("profile-prod".to_owned()),
        ..TranslateOptions::default()
    };

    let cfg = translate_dev(&baseline, None, &opts).expect("translates");
    assert_eq!(cfg.version, "0.6.0-dev");
    assert!(matches!(
        cfg.containment,
        schema_dev::Containment::IsolationSession
    ));
    let iso = cfg
        .experimental
        .isolation_session
        .as_ref()
        .expect("iso config");
    assert_eq!(iso.configuration_id.as_deref(), Some("profile-prod"));

    let wrapped = translate(&baseline, None, &opts).expect("wrapped translates");
    let json = wrapped.to_json().expect("serialises");
    assert!(json.contains("\"containment\":\"isolation_session\""));
    assert!(json.contains("\"experimental\""));
    assert!(json.contains("\"configurationId\":\"profile-prod\""));
}

#[test]
fn dev_schema_rejects_app_container_name_option() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::DevIsolationSession,
        app_container_name: Some("nope".to_owned()),
        ..TranslateOptions::default()
    };

    let err = translate(&baseline, None, &opts).unwrap_err();
    assert!(matches!(err, TranslateError::InvalidOptionForSchema { .. }));
}

#[test]
fn dev_schema_dispatches_experimental_flag_via_invoke() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::DevIsolationSession,
        ..TranslateOptions::default()
    };
    let cfg = translate(&baseline, None, &opts).expect("translates");
    let json = cfg.to_json().expect("serialises");

    let inv = build_invocation(&PathBuf::from("wxc-exec.exe"), cfg.schema(), &json, false);
    assert!(inv.args.iter().any(|a| a == "--experimental"));
}

#[test]
fn alpha_schema_does_not_add_experimental_via_invoke() {
    let baseline = baseline_with_fs(vec![], vec![]);
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ..TranslateOptions::default()
    };
    let cfg = translate(&baseline, None, &opts).expect("translates");
    let json = cfg.to_json().expect("serialises");

    let inv = build_invocation(&PathBuf::from("wxc-exec.exe"), cfg.schema(), &json, false);
    assert!(!inv.args.iter().any(|a| a == "--experimental"));
}

#[test]
fn envelope_intersects_baseline_paths() {
    let baseline = baseline_with_fs(vec!["/usr", "/etc"], vec!["/tmp", "/sandbox"]);
    let envelope = EnvelopePolicy {
        readwrite_paths: vec!["/tmp".to_owned(), "/forbidden".to_owned()],
        readonly_paths: vec!["/etc".to_owned()],
        ..EnvelopePolicy::default()
    };
    let opts = TranslateOptions {
        schema: Schema::AlphaProcess,
        ..TranslateOptions::default()
    };

    let cfg = translate_alpha(&baseline, Some(&envelope), &opts).expect("translates");
    let fs = cfg.filesystem.expect("filesystem");
    assert_eq!(fs.readwrite_paths, vec!["/tmp".to_owned()]);
    assert!(fs.readonly_paths.iter().any(|p| p == "/etc"));
    assert!(!fs.readonly_paths.iter().any(|p| p == "/forbidden"));
}
