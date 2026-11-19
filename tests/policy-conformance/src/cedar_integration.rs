// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::policy_types::{EndpointConfig, NetworkInput};
use openshell_core::policy_identity::deterministic_policy_hash;
use openshell_policy_cedar_runtime::CedarOnlyEngine;

fn route(engine: &CedarOnlyEngine, host: &str, path: &str) -> EndpointConfig {
    engine
        .authorize_egress(&NetworkInput {
            host: host.into(),
            port: 443,
            binary_path: "/usr/bin/curl".into(),
            binary_sha256: String::new(),
            ancestors: vec![],
            cmdline_paths: vec![],
        })
        .unwrap()
        .endpoint_configs
        .into_iter()
        .filter(|config| openshell_core::endpoint_path::matches(&config.path, path))
        .max_by_key(|config| openshell_core::endpoint_path::path_specificity(&config.path))
        .expect("configured route")
}

#[tokio::test]
async fn cedar_mcp_routes_observe_the_configured_inventory_identity() {
    use openshell_core::endpoint_status::{
        EndpointConfigVersion, EndpointInventoryEntry, EndpointResult, endpoint_id,
        endpoint_status_channel,
    };
    use openshell_core::proto::NetworkEndpoint;
    let source = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("mcp") @path("/mcp/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
@protocol("rest") @path("/rest/**")
permit (principal, action == Sandbox::Action::"HttpRequest", resource)
when { resource.host like("*.example.com", ".") && resource.port == 443 };
"#;
    let provider = NetworkEndpoint {
        host: "*.example.com".to_string(),
        ports: vec![8443, 443],
        path: "/mcp/provider/**".to_string(),
        provider_credentialed: true,
        ..Default::default()
    };
    let setting = NetworkEndpoint {
        host: "api.example.com".to_string(),
        port: 443,
        path: "/mcp/scoped".to_string(),
        allow_encoded_slash: true,
        ..Default::default()
    };
    let mut policy = openshell_policy::cedar_sandbox_policy(source.into()).unwrap();
    policy.provider_credential_rules.insert(
        "_provider_work".into(),
        openshell_core::proto::NetworkPolicyRule {
            endpoints: vec![provider.clone()],
            ..Default::default()
        },
    );
    policy.endpoint_settings.push(setting.clone());
    let policy = openshell_policy::validate_and_canonicalize_sandbox_policy(policy)
        .expect("canonical policy");
    let engine = CedarOnlyEngine::from_proto(&policy).expect("policy loads");
    let descriptors =
        openshell_policy::endpoint_status::configured_mcp_endpoints(&policy).expect("inventory");
    let (sender, mut receiver) = endpoint_status_channel();
    let mut tracker = receiver.tracker();
    sender
        .reset(
            EndpointConfigVersion {
                policy_hash: deterministic_policy_hash(&policy),
                provider_env_revision: 1,
            },
            descriptors
                .iter()
                .map(|endpoint| EndpointInventoryEntry {
                    endpoint_id: endpoint_id(endpoint),
                    uses_provider_credentials: endpoint.provider_credentialed,
                })
                .collect(),
        )
        .await
        .expect("reset");
    assert!(tracker.apply(receiver.recv().await.expect("reset received")));
    let base = NetworkEndpoint {
        host: "*.example.com".to_string(),
        port: 443,
        path: "/mcp/**".to_string(),
        ..Default::default()
    };
    for (host, path, expected) in [
        ("api.example.com", "/mcp/item", &base),
        ("other.example.com", "/mcp/item", &base),
        ("api.example.com", "/mcp/provider/item", &provider),
        ("other.example.com", "/mcp/provider/item", &provider),
        ("api.example.com", "/mcp/scoped", &setting),
    ] {
        let config = route(&engine, host, path);
        let selected = crate::l7::parse_l7_config(&config).expect("MCP config");
        assert_eq!(selected.endpoint_id, endpoint_id(expected), "{host}{path}");
        assert!(
            openshell_supervisor_network::conformance_support::observe_endpoint(
                &sender,
                &selected,
                EndpointResult::HttpResponseReceived
            )
        );
    }
    let rest = route(&engine, "api.example.com", "/rest/item");
    let rest = crate::l7::parse_l7_config(&rest).expect("REST config");
    assert!(
        !openshell_supervisor_network::conformance_support::observe_endpoint(
            &sender,
            &rest,
            EndpointResult::HttpResponseReceived
        )
    );
    while let Ok(command) = receiver.try_recv() {
        tracker.apply(command);
    }
    let snapshot = tracker.snapshot().expect("snapshot");
    for expected in [&base, &provider, &setting] {
        assert!(
            snapshot
                .endpoints
                .iter()
                .any(|endpoint| endpoint.endpoint_id == endpoint_id(expected)
                    && endpoint.result == EndpointResult::HttpResponseReceived)
        );
    }
}

const QUERY_POLICY: &str = r#"
permit (principal, action == Sandbox::Action::"NetworkConnect",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443");
permit (principal, action == Sandbox::Action::"HttpRequest",
        resource == Sandbox::NetworkEndpoint::"api.example.com:443")
when { context.query.hasTag("tag") && context.query.getTag("tag") like "foo-*" };
"#;

#[test]
fn decoded_query_params_reach_the_cedar_backend() {
    let backend = std::sync::Arc::new(CedarOnlyEngine::from_policy_str(QUERY_POLICY).unwrap());
    let engine = crate::policy_engine::PolicyEngine::from(backend);
    let tunnel = engine.tunnel_engine(engine.current_generation()).unwrap();
    let (target, query_params) =
        openshell_supervisor_network::conformance_support::parse_target_query(
            "/download?t%61g=foo%2Da&tag=foo-x+y",
        )
        .unwrap();
    let ctx = openshell_policy_runtime_interface::L7PolicyContext {
        host: "api.example.com".into(),
        port: 443,
        binary_path: "/usr/bin/curl".into(),
        ..Default::default()
    };
    let request = crate::l7::L7RequestInfo {
        action: "GET".into(),
        target,
        query_params,
        graphql: None,
        jsonrpc: None,
    };
    assert!(tunnel.evaluate_request(&ctx, &request).unwrap().0);
}
