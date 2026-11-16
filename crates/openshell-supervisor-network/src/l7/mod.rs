// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! L7 protocol-aware inspection for the CONNECT proxy.
//!
//! When an endpoint is configured with a `protocol` field (e.g. `rest`, `sql`),
//! the proxy inspects application-layer traffic within the tunnel instead of
//! doing a raw `copy_bidirectional`. Each request within the tunnel is parsed,
//! evaluated against OPA policy, and either forwarded or denied.

pub mod graphql;
pub(crate) mod http;
pub mod jsonrpc;
pub(crate) mod mcp;
pub(crate) mod middleware;
pub mod path;
pub mod provider;
pub mod relay;
pub mod rest;
pub mod tls;
pub(crate) mod token_grant_injection;
pub(crate) mod websocket;

use openshell_core::endpoint_status::{
    EndpointObservationContext, EndpointObservationHandle, EndpointObservationSender,
    EndpointResult,
};
#[cfg(test)]
use openshell_core::mcp::McpProtocolVersion;
pub use openshell_policy_runtime_interface::l7::{
    CredentialSigning, EndpointCredentialGuard, EnforcementMode, L7Decision, L7EndpointConfig,
    L7Protocol, L7RequestInfo, TlsMode, access_preset_rules, additional_l7_fields,
    check_glob_syntax, endpoint_has_graphql_policy, endpoint_path_matches, expand_access_presets,
    glob_uses_wildcard, graphql_rule_json, has_graphql_persisted_query_mode,
    json_endpoint_has_graphql_policy, json_rule_has_graphql_fields,
    json_rule_has_non_empty_path_or_query, json_rule_has_transport_fields, jsonrpc_policy_input,
    jsonrpc_rule_json, l7_request_policy_input, matcher_uses_glob_wildcard,
    mcp_endpoint_has_tool_allow_selectors, mcp_rule_has_tool_selector,
    method_matcher_matches_tools_call, parse_canonical_mcp_versions,
    parse_endpoint_credential_guard, parse_l7_config, parse_tls_mode, rule_json,
    valid_methods_for_protocol, validate_graphql_fields, validate_graphql_operation_type,
    validate_graphql_rule, validate_host_wildcard, validate_jsonrpc_rule_fields,
    validate_l7_policies, validate_matcher_map, validate_matcher_value, validate_mcp_method_field,
    validate_mcp_params_field, validate_mcp_tool_field, validate_mcp_tool_name_wildcard_policy,
    validate_mcp_versions_field,
};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use crate::policy_types::EndpointConfig;
use crate::policy_types::PolicyGenerationGuard;

pub(crate) fn build_credential_endpoint_mismatch_finding(
    policy_name: &str,
    host: &str,
    protocol: Option<&str>,
    message: &str,
) -> openshell_ocsf::OcsfEvent {
    use openshell_ocsf::{
        ActionId, ActivityId, DetectionFindingBuilder, DispositionId, FindingInfo, SeverityId,
    };

    let mut evidence = vec![("policy", policy_name), ("host", host)];
    if let Some(protocol) = protocol {
        evidence.push(("protocol", protocol));
    }
    evidence.push(("disposition", "denied"));

    DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::Open)
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .severity(SeverityId::High)
        .is_alert(true)
        .finding_info(FindingInfo::new(
            "openshell.provider_credential.endpoint_mismatch",
            "Provider credential used at an unauthorized endpoint",
        ))
        .evidence_pairs(&evidence)
        .message(message)
        .build()
}

/// Report the first network result for a selected tool endpoint.
///
/// Clones share the same pending handle, so only the first terminal result is
/// accepted. The lock is never held across an await, and reporting remains
/// nonblocking because the core sender uses a bounded `try_send` path.
#[derive(Clone)]
pub(crate) struct EndpointObserver {
    sender: EndpointObservationSender,
    observation: Arc<Mutex<Option<EndpointObservationHandle>>>,
    uses_provider_credentials: bool,
    policy_generation: Option<PolicyGenerationGuard>,
}

impl EndpointObserver {
    /// Bind a selected endpoint to authority captured before request-state lookup.
    ///
    /// Selection, provider material, and observation authority must describe the
    /// same installation. A stale policy selection never acquires a new epoch.
    pub(crate) fn begin_captured(
        sender: Option<&EndpointObservationSender>,
        config: &L7EndpointConfig,
        context: Option<&EndpointObservationContext>,
        provider_revision: Option<u64>,
        guard: Option<&PolicyGenerationGuard>,
    ) -> Option<Self> {
        if config.protocol != L7Protocol::Mcp
            || config.endpoint_id.is_empty()
            || config.policy_hash.is_empty()
        {
            // Only internal metadata from a complete MCP policy identifies
            // the endpoint and configuration whose result can be published.
            return None;
        }
        if guard.is_some_and(PolicyGenerationGuard::is_stale) {
            // Equal policy hashes can recur after a reload; the pinned guard
            // prevents an earlier selection from becoming current again.
            return None;
        }
        let sender = sender?.clone();
        let observation = sender.begin_captured(
            context?,
            config.endpoint_id.clone(),
            &config.policy_hash,
            provider_revision,
        )?;
        Some(Self {
            sender,
            observation: Arc::new(Mutex::new(Some(observation))),
            uses_provider_credentials: config.provider_credentialed,
            policy_generation: guard.cloned(),
        })
    }

    /// Capture and bind an observation synchronously for isolated unit fixtures.
    #[cfg(test)]
    pub(crate) fn begin(
        sender: Option<&EndpointObservationSender>,
        config: &L7EndpointConfig,
    ) -> Option<Self> {
        let context = sender.and_then(EndpointObservationSender::capture);
        Self::begin_captured(sender, config, context.as_ref(), None, None)
    }

    /// Report the first terminal exchange result, dropping later attempts.
    pub(crate) fn observe(&self, result: EndpointResult) {
        self.observe_with_failure(result, None);
    }

    /// Report a refused token grant as an unavailable credential with its cause.
    ///
    /// As with [`Self::observe_credential_failure`], an endpoint that does not
    /// use provider credentials records nothing.
    pub(crate) fn observe_token_grant_refusal(
        &self,
        refusal: &token_grant_injection::TokenGrantInjectionError,
        request_id: &str,
    ) {
        if !self.uses_provider_credentials {
            return;
        }
        self.observe_with_failure(
            EndpointResult::CredentialUnavailable,
            Some(refusal.endpoint_failure(request_id)),
        );
    }

    fn observe_with_failure(
        &self,
        result: EndpointResult,
        failure: Option<openshell_core::endpoint_failure::EndpointFailure>,
    ) {
        let Ok(mut pending) = self.observation.lock() else {
            // Status reporting cannot interrupt traffic if another observer panicked.
            return;
        };
        let Some(observation) = pending.take() else {
            // Another clone already reported the result for this exchange.
            return;
        };
        if self
            .policy_generation
            .as_ref()
            .is_some_and(PolicyGenerationGuard::is_stale)
        {
            // The request may finish after its policy was replaced but before
            // the replacement inventory arrives. Its old result cannot fill
            // that activation gap, including a return to equal policy values.
            return;
        }
        let _accepted = self
            .sender
            .try_observe_with_failure(observation, result, failure);
    }

    /// Report an endpoint mismatch or an unavailable provider credential.
    pub(crate) fn observe_credential_failure(&self, endpoint_mismatch: bool) {
        if endpoint_mismatch {
            self.observe(EndpointResult::PolicyDenied);
        } else if self.uses_provider_credentials {
            self.observe(EndpointResult::CredentialUnavailable);
        }
    }
}

pub(crate) fn emit_uninspected_credential_finding(host: &str, policy_name: &str, surface: &str) {
    let event = openshell_ocsf::DetectionFindingBuilder::new(openshell_ocsf::ctx::ctx())
        .severity(openshell_ocsf::SeverityId::High)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.credentials.traffic_uninspectable",
            "Credential-bearing traffic cannot be inspected",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("host", host),
            ("surface", surface),
            ("disposition", "denied"),
        ])
        .message("Uninspected credential-bearing traffic denied")
        .build();
    openshell_ocsf::ocsf_emit!(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_l7_config_rest_enforce() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "enforcement": "enforce", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Rest);
        assert_eq!(config.tls, TlsMode::Auto);
        assert_eq!(config.enforcement, EnforcementMode::Enforce);
    }

    #[test]
    fn parse_l7_config_defaults() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "api.example.com", "port": 80}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Rest);
        assert_eq!(config.tls, TlsMode::Auto);
        assert_eq!(config.enforcement, EnforcementMode::Audit);
    }

    #[tokio::test]
    async fn endpoint_observation_classifies_only_bound_credential_failure() {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, EndpointResult, EndpointStatusCommand,
            endpoint_status_channel,
        };

        let endpoint_id = "endpoint:v1:credential".to_string();
        let (sender, mut receiver) = endpoint_status_channel();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: endpoint_id.clone(),
                    uses_provider_credentials: true,
                }],
            )
            .await
            .expect("install MCP test inventory");
        let _reset = receiver.recv().await.expect("inventory reset");
        let value = serde_json::from_str::<EndpointConfig>(&format!(
            r#"{{"protocol":"mcp","mcp_versions":["2025-11-25"],"endpoint_id":"{endpoint_id}","policy_hash":"policy","provider_credentialed":true}}"#
        ))
        .expect("parse MCP config JSON");
        let config = parse_l7_config(&value).expect("parse MCP config");
        let observer = EndpointObserver::begin(Some(&sender), &config).expect("begin observation");

        observer.observe_credential_failure(false);

        assert!(matches!(
            receiver.recv().await.expect("credential observation"),
            EndpointStatusCommand::Observe {
                result: EndpointResult::CredentialUnavailable,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn endpoint_observation_rejects_old_policy_selection_after_inventory_reset() {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, endpoint_status_channel,
        };

        let endpoint_id = "endpoint:v1:shared";
        let inventory = vec![EndpointInventoryEntry {
            endpoint_id: endpoint_id.to_string(),
            uses_provider_credentials: false,
        }];
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                inventory.clone(),
            )
            .await
            .expect("install first policy inventory");
        assert!(tracker.apply(receiver.recv().await.expect("first inventory reset")));
        let value = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"mcp","mcp_versions":["2025-11-25"],"endpoint_id":"endpoint:v1:shared","policy_hash":"policy-a"}"#,
        )
        .expect("parse first policy selection");
        let selected = parse_l7_config(&value).expect("select first policy endpoint");

        // The replacement retains the endpoint address while changing policy.
        // A delayed selection must not acquire the replacement's authority.
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-b".to_string(),
                    provider_env_revision: 1,
                },
                inventory,
            )
            .await
            .expect("install replacement policy inventory");
        assert!(tracker.apply(receiver.recv().await.expect("replacement inventory reset")));
        if let Some(observer) = EndpointObserver::begin(Some(&sender), &selected) {
            observer.observe(EndpointResult::PolicyDenied);
        }
        while let Ok(command) = receiver.try_recv() {
            tracker.apply(command);
        }

        let snapshot = tracker
            .snapshot()
            .expect("replacement inventory remains installed");
        assert_eq!(snapshot.config_version.policy_hash, "policy-b");
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(
            snapshot.endpoints[0].result,
            EndpointResult::NoObservedExchange
        );
    }

    #[tokio::test]
    async fn endpoint_observation_rejects_new_policy_selection_before_inventory_reset() {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, endpoint_status_channel,
        };

        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy-a".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:v1:shared".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("install first policy inventory");
        assert!(tracker.apply(receiver.recv().await.expect("first inventory reset")));
        // The runtime can install the new policy before its inventory reset.
        // The new policy's result must not be attributed to the old inventory.
        let value = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"mcp","mcp_versions":["2025-11-25"],"endpoint_id":"endpoint:v1:shared","policy_hash":"policy-b"}"#,
        )
        .expect("parse replacement policy selection");
        let selected = parse_l7_config(&value).expect("select replacement policy endpoint");
        if let Some(observer) = EndpointObserver::begin(Some(&sender), &selected) {
            observer.observe(EndpointResult::HttpResponseReceived);
        }
        while let Ok(command) = receiver.try_recv() {
            tracker.apply(command);
        }

        let snapshot = tracker
            .snapshot()
            .expect("first inventory remains installed");
        assert_eq!(snapshot.config_version.policy_hash, "policy-a");
        assert_eq!(snapshot.endpoints.len(), 1);
        assert_eq!(
            snapshot.endpoints[0].result,
            EndpointResult::NoObservedExchange
        );
    }

    #[tokio::test]
    async fn endpoint_observation_rejects_stale_policy_guards_without_disabling_fresh_requests() {
        use openshell_core::endpoint_status::{
            EndpointConfigVersion, EndpointInventoryEntry, endpoint_status_channel,
        };

        let policy = openshell_policy::restrictive_default_policy();
        let engine = crate::opa::OpaEngine::from_proto(&policy).expect("test policy engine");
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy".to_string(),
                    provider_env_revision: 1,
                },
                vec![EndpointInventoryEntry {
                    endpoint_id: "endpoint:v1:shared".to_string(),
                    uses_provider_credentials: false,
                }],
            )
            .await
            .expect("install test inventory");
        assert!(tracker.apply(receiver.recv().await.expect("inventory reset")));
        let context = sender.capture().expect("capture installed authority");
        let value = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"mcp","mcp_versions":["2025-11-25"],"endpoint_id":"endpoint:v1:shared","policy_hash":"policy"}"#,
        )
        .expect("parse selected MCP policy");
        let selected = parse_l7_config(&value).expect("selected MCP endpoint");
        let previous_guard = engine
            .generation_guard(engine.current_generation())
            .expect("capture initial policy guard");
        let previous_observer = EndpointObserver::begin_captured(
            Some(&sender),
            &selected,
            Some(&context),
            Some(1),
            Some(&previous_guard),
        )
        .expect("current policy can begin an observation");

        // Runtime generations can advance while the canonical policy and
        // inventory stay equal. Only new selections may use the new runtime.
        engine
            .reload_from_proto(&policy)
            .expect("reinstall same policy");
        assert!(
            EndpointObserver::begin_captured(
                Some(&sender),
                &selected,
                Some(&context),
                Some(1),
                Some(&previous_guard),
            )
            .is_none()
        );
        previous_observer.observe(EndpointResult::HttpResponseReceived);
        while let Ok(command) = receiver.try_recv() {
            tracker.apply(command);
        }
        assert_eq!(
            tracker
                .snapshot()
                .expect("inventory remains installed")
                .endpoints[0]
                .result,
            EndpointResult::NoObservedExchange,
        );

        let current_guard = engine
            .generation_guard(engine.current_generation())
            .expect("capture replacement policy guard");
        let current_observer = EndpointObserver::begin_captured(
            Some(&sender),
            &selected,
            Some(&context),
            Some(1),
            Some(&current_guard),
        )
        .expect("fresh selection stays observable without an inventory reset");
        current_observer.observe(EndpointResult::HttpResponseReceived);
        assert!(tracker.apply(receiver.recv().await.expect("fresh policy observation")));
        assert_eq!(
            tracker
                .snapshot()
                .expect("inventory remains installed")
                .endpoints[0]
                .result,
            EndpointResult::HttpResponseReceived,
        );
    }

    #[tokio::test]
    async fn non_mcp_endpoint_never_begins_an_observation() {
        use openshell_core::endpoint_status::{EndpointConfigVersion, endpoint_status_channel};

        let (sender, _receiver) = endpoint_status_channel();
        sender
            .reset(
                EndpointConfigVersion {
                    policy_hash: "policy".to_string(),
                    provider_env_revision: 1,
                },
                Vec::new(),
            )
            .await
            .expect("install MCP test configuration");
        let value = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"rest","endpoint_id":"endpoint:v1:not-mcp"}"#,
        )
        .expect("parse REST config JSON");
        let config = parse_l7_config(&value).expect("parse REST config");
        assert!(EndpointObserver::begin(Some(&sender), &config).is_none());
    }

    #[test]
    fn parse_l7_config_rejects_unknown_enforcement() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "enforcement": "enforc", "access": "read-only", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();

        assert!(parse_l7_config(&val).is_none());
    }

    #[test]
    fn parse_credential_signing_sigv4() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "credential_signing": "sigv4", "signing_service": "bedrock", "host": "bedrock.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn parse_credential_signing_sigv4_body() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "credential_signing": "sigv4:body", "signing_service": "bedrock", "host": "bedrock.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4Body);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn parse_credential_signing_sigv4_no_body() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "credential_signing": "sigv4:no_body", "signing_service": "s3", "host": "s3.us-east-1.amazonaws.com", "port": 443}"#,
        ).unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.credential_signing, CredentialSigning::SigV4NoBody);
        assert!(config.credential_signing.is_sigv4());
    }

    #[test]
    fn is_sigv4_false_for_none() {
        assert!(!CredentialSigning::None.is_sigv4());
    }

    #[test]
    fn parse_l7_config_websocket_protocol() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.protocol, L7Protocol::Websocket);
    }

    #[test]
    fn parse_l7_config_skip() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "tls": "skip", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert_eq!(config.tls, TlsMode::Skip);
    }

    #[test]
    fn parse_l7_config_no_protocol() {
        let val =
            serde_json::from_str::<EndpointConfig>(r#"{"host": "api.example.com", "port": 443}"#)
                .unwrap();
        assert!(parse_l7_config(&val).is_none());
    }

    #[test]
    fn parse_endpoint_credential_guard_handles_l4_and_opt_in() {
        let guarded = serde_json::from_str::<EndpointConfig>(
            r#"{"host":"api.example.com","ports":[443],"provider_credentialed":true}"#,
        )
        .unwrap();
        let guard = parse_endpoint_credential_guard(&guarded);
        assert!(guard.blocks_connect());

        let opted_in = serde_json::from_str::<EndpointConfig>(
            r#"{"host":"api.example.com","ports":[443],"provider_credentialed":true,"allow_uninspected_credentials":true}"#,
        )
        .unwrap();
        assert!(!parse_endpoint_credential_guard(&opted_in).blocks_connect());
    }

    #[test]
    fn generic_resolver_enables_rest_body_backstop_without_provider_marker() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"rest","host":"api.example.com","ports":[443]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.deny_uninspected_body_credentials(false));
        assert!(config.deny_uninspected_body_credentials(true));

        let opted_in = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol":"rest","host":"api.example.com","ports":[443],"allow_uninspected_credentials":true}"#,
        )
        .unwrap();
        assert!(
            !parse_l7_config(&opted_in)
                .unwrap()
                .deny_uninspected_body_credentials(true)
        );
    }

    #[test]
    fn parse_l7_config_allow_encoded_slash_defaults_false() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "api.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.allow_encoded_slash);
    }

    #[test]
    fn parse_l7_config_allow_encoded_slash_opt_in() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "gitlab.example.com", "port": 443, "allow_encoded_slash": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.allow_encoded_slash);
    }

    #[test]
    fn parse_l7_config_mcp_strict_tool_names_defaults_true() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "mcp", "host": "mcp.example.com", "port": 443, "mcp_versions": ["2025-11-25"]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.mcp_strict_tool_names);
    }

    #[test]
    fn parse_l7_config_mcp_strict_tool_names_can_disable() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "mcp", "host": "mcp.example.com", "port": 443, "mcp_strict_tool_names": false, "mcp_versions": ["2025-11-25"]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.mcp_strict_tool_names);
    }

    #[test]
    fn parse_l7_config_requires_canonical_mcp_versions() {
        let explicit = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "mcp", "mcp_versions": ["2025-03-26", "2025-11-25"]}"#,
        )
        .unwrap();
        assert_eq!(
            parse_l7_config(&explicit).unwrap().mcp_versions,
            vec![
                McpProtocolVersion::V2025_03_26,
                McpProtocolVersion::V2025_11_25
            ]
        );

        for invalid in [
            r#"{"protocol": "mcp"}"#,
            r#"{"protocol": "mcp", "mcp_versions": []}"#,
            r#"{"protocol": "mcp", "mcp_versions": ["2026-01-01"]}"#,
            r#"{"protocol": "mcp", "mcp_versions": ["2025-11-25", "2025-11-25"]}"#,
            r#"{"protocol": "mcp", "mcp_versions": ["2025-11-25", "2025-03-26"]}"#,
        ] {
            let value = serde_json::from_str::<EndpointConfig>(invalid).unwrap();
            assert!(
                parse_l7_config(&value).is_none(),
                "non-canonical MCP runtime config must be rejected: {invalid}"
            );
        }
        // A non-string revision is not an endpoint config at all.
        assert!(
            serde_json::from_str::<EndpointConfig>(r#"{"protocol": "mcp", "mcp_versions": [1]}"#)
                .is_err()
        );
    }

    #[test]
    fn parse_l7_config_keeps_mcp_versions_off_other_protocols() {
        let value = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "json-rpc", "mcp_versions": ["2025-11-25"]}"#,
        )
        .unwrap();

        assert!(parse_l7_config(&value).unwrap().mcp_versions.is_empty());
    }

    #[test]
    fn parse_l7_config_websocket_credential_rewrite_defaults_false() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "gateway.example.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.websocket_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_websocket_credential_rewrite_opt_in() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "gateway.example.com", "port": 443, "websocket_credential_rewrite": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.websocket_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_request_body_credential_rewrite_defaults_false() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "slack.com", "port": 443}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.request_body_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_request_body_credential_rewrite_opt_in() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "rest", "host": "slack.com", "port": 443, "request_body_credential_rewrite": true}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.request_body_credential_rewrite);
    }

    #[test]
    fn parse_l7_config_websocket_graphql_policy_defaults_false() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443, "rules": [{"allow": {"method": "GET", "path": "/graphql"}}, {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql"}}]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(!config.websocket_graphql_policy);
    }

    #[test]
    fn parse_l7_config_websocket_graphql_policy_detects_operation_rules() {
        let val = serde_json::from_str::<EndpointConfig>(
            r#"{"protocol": "websocket", "host": "gateway.example.com", "port": 443, "rules": [{"allow": {"method": "GET", "path": "/graphql"}}, {"allow": {"operation_type": "subscription", "fields": ["messageAdded"]}}]}"#,
        )
        .unwrap();
        let config = parse_l7_config(&val).unwrap();
        assert!(config.websocket_graphql_policy);
    }

    #[test]
    fn validate_websocket_credential_rewrite_warns_unless_rest_or_websocket() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "websocket_credential_rewrite": true
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("websocket_credential_rewrite is ignored")),
            "expected websocket_credential_rewrite warning: {warnings:?}"
        );
    }

    #[test]
    fn validate_explicit_tcp_rejects_additional_l7_field_families() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "database.example.com",
                        "port": 5432,
                        "protocol": "tcp",
                        "enforcement": "enforce",
                        "path": "/query",
                        "allow_encoded_slash": true,
                        "websocket_credential_rewrite": true,
                        "request_body_credential_rewrite": true,
                        "persisted_queries": "allow_registered",
                        "graphql_persisted_queries": {},
                        "graphql_max_body_bytes": 1024,
                        "json_rpc_max_body_bytes": 1024,
                        "mcp_strict_tool_names": false,
                        "mcp_allow_all_known_mcp_methods": false,
                        "credential_signing": "sigv4",
                        "signing_service": "rds",
                        "signing_region": "us-west-2",
                        "credential_binding": {"provider": "database"}
                    }],
                    "binaries": []
                }
            }
        });

        let (errors, _) = validate_l7_policies(&data);
        let tcp_error = errors
            .iter()
            .find(|error| error.contains("protocol tcp does not support L7-only fields"))
            .expect("explicit TCP should reject additional L7 fields");

        for field in [
            "enforcement",
            "path",
            "allow_encoded_slash",
            "websocket_credential_rewrite",
            "request_body_credential_rewrite",
            "persisted_queries",
            "graphql_persisted_queries",
            "graphql_max_body_bytes",
            "json_rpc_max_body_bytes",
            "mcp.strict_tool_names",
            "mcp.allow_all_known_mcp_methods",
            "credential_signing",
            "signing_service",
            "signing_region",
            "credential_binding",
        ] {
            assert!(tcp_error.contains(field), "missing {field}: {tcp_error}");
        }
    }

    #[test]
    fn validate_request_body_credential_rewrite_warns_unless_rest() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "request_body_credential_rewrite": true
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("request_body_credential_rewrite is ignored")),
            "expected request_body_credential_rewrite warning: {warnings:?}"
        );
    }

    #[test]
    fn expand_websocket_read_write_access_includes_text_messages() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "access": "read-write"
                    }],
                    "binaries": []
                }
            }
        });

        let warnings = expand_access_presets(&mut data);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        let methods: Vec<&str> = rules
            .iter()
            .map(|r| r["allow"]["method"].as_str().unwrap())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"WEBSOCKET_TEXT"));
    }

    #[test]
    fn validate_websocket_accepts_graphql_operation_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"operation_type": "subscription", "fields": ["messageAdded"]}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "expected no errors: {errors:?}");
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
    }

    #[test]
    fn validate_websocket_graphql_rule_requires_operation_type() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"fields": ["messageAdded"]}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("operation_type")),
            "expected missing operation_type error: {errors:?}"
        );
    }

    #[test]
    fn validate_websocket_graphql_rule_rejects_mixed_transport_fields() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql", "operation_type": "subscription"}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("must not combine")),
            "expected mixed-field error: {errors:?}"
        );
    }

    #[test]
    fn validate_websocket_graphql_policy_rejects_raw_text_message_rule() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "gateway.example.com",
                        "port": 443,
                        "protocol": "websocket",
                        "rules": [
                            {"allow": {"method": "GET", "path": "/graphql"}},
                            {"allow": {"method": "WEBSOCKET_TEXT", "path": "/graphql"}},
                            {"allow": {"operation_type": "query"}}
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("instead of WEBSOCKET_TEXT")),
            "expected raw WEBSOCKET_TEXT rejection: {errors:?}"
        );
    }

    #[test]
    fn validate_rules_and_access_mutual_exclusion() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-only",
                        "rules": [{"allow": {"method": "GET", "path": "**"}}]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(errors.iter().any(|e| e.contains("mutually exclusive")));
    }

    #[test]
    fn validate_jsonrpc_rejects_access_presets() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "access": "full"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("json-rpc")
                    && e.contains("does not support access presets")
                    && e.contains("method")
            }),
            "JSON-RPC access presets should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_requires_method_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "path": "/rpc"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow.method") && e.contains("required") }),
            "JSON-RPC allow rules without method should be rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("must use method, not path/query") }),
            "JSON-RPC allow rules with path/query should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_selectors_use_endpoint_method_profile_and_reject_arguments() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{
                            "allow": {
                                "tool": { "any": ["read_status", "submit_*"] }
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "tool": "submit_report",
                                "params": {
                                    "arguments": {
                                        "scope": "workspace/main"
                                    }
                                }
                            }
                        }, {
                            "allow": {
                                "method": "initialize"
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "tool": "list_reports"
                            }
                        }],
                        "deny_rules": [{
                            "tool": "delete_*"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("rules[0].allow.method") && e.contains("required")),
            "MCP tool rules can omit method while allow_all_known_mcp_methods is enabled: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.params.arguments")
                    && e.contains("argument matching is not supported")
            }),
            "MCP argument params should be rejected: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[2].allow.method")),
            "MCP method-only rules should not require a tool selector: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[3].allow.method")),
            "MCP tool rules with method: tools/call should validate: {errors:?}"
        );
        assert!(
            !errors
                .iter()
                .any(|e| e.contains("deny_rules[0].method") && e.contains("tools/call")),
            "MCP deny tool rules can omit method while allow_all_known_mcp_methods is enabled: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_selectors_require_method_by_default() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "tool": "read_status"
                            }
                        }],
                        "deny_rules": [{
                            "tool": "delete_*"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow.method")
                    && e.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "MCP allow tool rules should require method when method profile is disabled: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0].method")
                    && e.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "MCP deny tool rules should require method when method profile is disabled: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_method_globs_are_tools_family_only() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "vendor/extension"
                            }
                        }, {
                            "allow": {
                                "method": "vendor/*"
                            }
                        }, {
                            "allow": {
                                "method": "*"
                            }
                        }, {
                            "allow": {
                                "method": "tools/*"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors.iter().any(|e| e.contains("rules[0].allow.method")),
            "literal extension methods should stay addressable: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.method")
                    && e.contains("only valid for the tools/ method family")
            }),
            "non-tools method globs should be rejected: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[2].allow.method")
                    && e.contains("only valid for the tools/ method family")
            }),
            "authored method: * should be rejected for MCP: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| e.contains("rules[3].allow.method")),
            "tools-family method globs should validate: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_wildcard_tool_requires_strict_tool_names() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_strict_tool_names": false,
                        "rules": [{
                            "allow": {
                                "method": "tools/call",
                                "tool": "read_*"
                            }
                        }, {
                            "allow": {
                                "method": "tools/call",
                                "params": {
                                    "name": { "any": ["safe_tool", "list_*"] }
                                }
                            }
                        }],
                        "deny_rules": [{
                            "method": "tools/call",
                            "tool": "delete_resource"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow.tool")
                    && e.contains("strict_tool_names to remain enabled")
            }),
            "wildcard tool aliases should require strict tool names: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.params.name")
                    && e.contains("strict_tool_names to remain enabled")
            }),
            "wildcard params.name should require strict tool names: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_protocol_requires_endpoint_target() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "protocol": "mcp"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocol mcp requires host")),
            "MCP protocol-only endpoint should require host: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("protocol mcp requires port or ports")),
            "MCP protocol-only endpoint should require port: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_broad_tools_call_deny_rejects_tool_allow_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "tools/call",
                                "tool": "read_status"
                            }
                        }],
                        "deny_rules": [{
                            "method": "tools/call"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0]")
                    && e.contains("denies every tool call")
                    && e.contains("conflicts with MCP tool allow rules")
            }),
            "broad tools/call deny should reject tool allow rules with a reason: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_broad_tools_call_allow_rejects_tool_allow_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "rules": [{
                            "allow": {
                                "method": "tools/*"
                            }
                        }, {
                            "allow": {
                                "tool": "read_status"
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[0].allow")
                    && e.contains("allows every tool call")
                    && e.contains("conflicts with MCP tool allow rules")
            }),
            "broad tools/call allow should reject tool allow rules with a reason: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_empty_allow_with_allow_all_conflicts_with_tool_rules() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{
                            "allow": {
                                "params": { "name": { "glob": "read_*" } }
                            }
                        }, {
                            "allow": {
                                "method": "",
                                "path": "",
                                "command": "",
                                "operation_type": "",
                                "operation_name": ""
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow")
                    && e.contains("allows every tool call")
                    && e.contains("conflicts with MCP tool allow rules")
            }),
            "empty allow with allow_all_known_mcp_methods normalizes to method:* and should \
             conflict with tool-specific rules: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_rejects_params_matchers() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "reports.search",
                                "params": { "query": "quarterly" }
                            }
                        }],
                        "deny_rules": [{
                            "method": "reports.archive",
                            "params": { "report_id": "rpt-123" }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow") && e.contains("do not support params") }),
            "JSON-RPC allow params should be rejected: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("deny_rules[0]") && e.contains("do not support params") }),
            "JSON-RPC deny params should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_strict_tool_names_is_mcp_only() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [
                        {
                            "host": "mcp.example.com",
                            "port": 443,
                            "path": "/mcp",
                            "protocol": "mcp",
                            "mcp_strict_tool_names": false,
                            "rules": [{ "allow": { "method": "tools/call" } }]
                        },
                        {
                            "host": "api.example.com",
                            "port": 443,
                            "protocol": "rest",
                            "mcp_strict_tool_names": false,
                            "mcp_allow_all_known_mcp_methods": true,
                            "access": "full"
                        }
                    ],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("is only valid for protocol mcp"))
                .count(),
            2,
            "only the REST endpoint should reject MCP-specific options: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_options_require_bool() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp",
                        "mcp_strict_tool_names": "false",
                        "mcp_allow_all_known_mcp_methods": "false",
                        "rules": [{ "allow": { "method": "tools/call" } }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("mcp.strict_tool_names must be boolean")),
            "expected bool validation error: {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("mcp.allow_all_known_mcp_methods must be boolean")),
            "expected bool validation error: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_requires_rules_by_default() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "path": "/mcp",
                        "protocol": "mcp"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|error| {
                error.contains("protocol mcp requires rules")
                    && error.contains("mcp.allow_all_known_mcp_methods is false")
            }),
            "expected disabled method profile to require rules: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_deny_rules_require_method() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "*"
                            }
                        }],
                        "deny_rules": [{
                            "params": { "name": "delete_resource" }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules[0].method") && e.contains("required")),
            "JSON-RPC deny rules without method should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_method_rejects_globs_except_allow_all() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "path": "/rpc",
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "*"
                            }
                        }, {
                            "allow": {
                                "method": "reports.*"
                            }
                        }],
                        "deny_rules": [{
                            "method": "reports/{archive,delete}"
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            !errors.iter().any(|e| e.contains("rules[0].allow.method")),
            "JSON-RPC method: * should remain the allow-all sentinel: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("rules[1].allow.method")
                    && e.contains("do not support glob or wildcard matchers")
            }),
            "JSON-RPC allow method globs should be rejected: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| {
                e.contains("deny_rules[0].method")
                    && e.contains("do not support glob or wildcard matchers")
            }),
            "JSON-RPC deny method globs should be rejected: {errors:?}"
        );
    }

    #[test]
    fn validate_protocol_requires_rules_or_access() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("requires rules or access"))
        );
    }

    #[test]
    fn validate_sql_enforce_blocked() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "db.internal",
                        "port": 5432,
                        "protocol": "sql",
                        "enforcement": "enforce",
                        "rules": [{"allow": {"command": "SELECT"}}]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(errors.iter().any(|e| e.contains("SQL enforcement")));
    }

    #[test]
    fn validate_rejects_unknown_endpoint_modes_without_warning() {
        for (field, value) in [
            ("tls", "terminate"),
            ("tls", "passthrough"),
            ("enforcement", "enforcee"),
            ("access", "read_only"),
        ] {
            let mut endpoint = serde_json::json!({
                "host": "api.example.com",
                "port": 443,
                "protocol": "rest",
                "access": "full"
            });
            endpoint[field] = value.into();
            let data = serde_json::json!({
                "network_policies": {
                    "test": { "endpoints": [endpoint], "binaries": [] }
                }
            });

            let (errors, warnings) = validate_l7_policies(&data);
            assert!(
                errors.iter().any(|e| e.contains("test.endpoints[0]")
                    && e.contains(&format!("unknown {field} value '{value}'"))),
                "{field}: {value} should be rejected: {errors:?}"
            );
            assert!(
                !warnings.iter().any(|w| w.contains("deprecated")),
                "{field}: {value} should not warn: {warnings:?}"
            );
        }
    }

    #[test]
    fn validate_tls_skip_with_l7_on_443_warns() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "tls": "skip",
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (_errors, warnings) = validate_l7_policies(&data);
        assert!(
            warnings.iter().any(|w| w.contains("tls: skip")),
            "should warn about skip + L7 on 443: {warnings:?}"
        );
    }

    #[test]
    fn validate_port_443_rest_no_tls_no_warning() {
        // With auto-TLS, no warning is needed for port 443 + rest without
        // explicit tls field — TLS will be auto-detected.
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "should have no errors: {errors:?}");
        assert!(
            !warnings.iter().any(|w| w.contains("tls")),
            "should have no tls warnings with auto-detect: {warnings:?}"
        );
    }

    #[test]
    fn expand_read_only_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 80,
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let warnings = expand_access_presets(&mut data);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 3);
        let methods: Vec<&str> = rules
            .iter()
            .map(|r| r["allow"]["method"].as_str().unwrap())
            .collect();
        assert!(methods.contains(&"GET"));
        assert!(methods.contains(&"HEAD"));
        assert!(methods.contains(&"OPTIONS"));
    }

    #[test]
    fn expand_full_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 80,
                        "protocol": "rest",
                        "access": "full"
                    }],
                    "binaries": []
                }
            }
        });
        let warnings = expand_access_presets(&mut data);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["allow"]["method"].as_str().unwrap(), "*");
        assert_eq!(rules[0]["allow"]["path"].as_str().unwrap(), "**");
    }

    #[test]
    fn expand_unsupported_access_preset_warns_and_leaves_rules_unexpanded() {
        let mut data = serde_json::json!({
            "network_policies": {
                "allow-my-service": {
                    "endpoints": [{
                        "host": "my-service.example.com",
                        "port": 80,
                        "protocol": "rest",
                        "access": "allow"
                    }],
                    "binaries": []
                }
            }
        });
        let warnings = expand_access_presets(&mut data);
        assert!(
            data["network_policies"]["allow-my-service"]["endpoints"][0]
                .get("rules")
                .is_none(),
            "unsupported access preset must not expand rules"
        );
        assert_eq!(
            warnings,
            vec![
                "allow-my-service.endpoints[0]: unsupported L7 access preset 'allow' ignored; expected one of: read-only, read-write, full".to_string()
            ]
        );
    }

    #[test]
    fn expand_graphql_readonly_preset() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let warnings = expand_access_presets(&mut data);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
        let rules = data["network_policies"]["test"]["endpoints"][0]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0]["allow"]["operation_type"].as_str().unwrap(),
            "query"
        );
    }

    #[test]
    fn validate_graphql_rule_requires_operation_type() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "rules": [{
                            "allow": {
                                "fields": ["viewer"]
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("operation_type")),
            "GraphQL rules should require operation_type: {errors:?}"
        );
    }

    #[test]
    fn validate_graphql_persisted_query_mode() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "graphql",
                        "access": "full",
                        "persisted_queries": "allow_all"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("persisted_queries")),
            "invalid persisted query mode should be rejected: {errors:?}"
        );
    }

    #[test]
    fn l4_only_endpoint_untouched() {
        let mut data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let warnings = expand_access_presets(&mut data);
        assert!(warnings.is_empty(), "expected no warnings: {warnings:?}");
        assert!(
            data["network_policies"]["test"]["endpoints"][0]
                .get("rules")
                .is_none()
        );
    }

    // ---- Host wildcard validation tests ----

    #[test]
    fn validate_wildcard_host_star_only_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("matches all hosts")),
            "Bare * host should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_only_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("matches all hosts")),
            "Bare ** host should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_star_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.*.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*.s3.*.amazonaws.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*.s3.*.amazonaws.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_partial_star_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.us-*.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("middle DNS label wildcard")),
            "Partial middle-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_middle_label_double_star_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.s3.**.amazonaws.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("recursive host wildcard")),
            "Middle-label ** wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_single_label_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "Single-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_recursive_intra_label_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "foo**.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("recursive host wildcard")),
            "Recursive intra-label wildcard should be rejected, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_tld_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "*.com should be rejected as TLD wildcard, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_tld_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**.org",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("TLD wildcard")),
            "**.org should be rejected as TLD wildcard, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*.example.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*.example.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_double_star_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "**.example.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "**.example.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "**.example.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_wildcard_host_intra_label_valid_no_error() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "*-aiplatform.googleapis.com",
                        "port": 443
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "*-aiplatform.googleapis.com should be valid, got errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "*-aiplatform.googleapis.com should not warn, got warnings: {warnings:?}"
        );
    }

    #[test]
    fn validate_port_and_ports_mutually_exclusive() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "ports": [443, 8443]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("port and ports are mutually exclusive")),
            "Should reject both port and ports, got errors: {errors:?}"
        );
    }

    #[test]
    fn validate_ports_array_rest_443_no_warning() {
        // With auto-TLS, no warning needed for ports array containing 443.
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "ports": [443, 8080],
                        "protocol": "rest",
                        "access": "read-only"
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(errors.is_empty(), "should have no errors: {errors:?}");
        assert!(
            !warnings.iter().any(|w| w.contains("tls")),
            "should have no tls warnings with auto-detect: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_any_requires_non_empty_array() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "any": [] }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("allow.query.tag.any")),
            "expected query any validation error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_query_object_rejects_unknown_keys() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "mode": "foo-*" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("unknown matcher keys")),
            "expected unknown query matcher key error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_query_glob_warns_on_unclosed_bracket() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": "[unclosed"
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '['") && w.contains("allow.query.tag")),
            "expected glob syntax warning, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_glob_warns_on_unclosed_brace() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "format": { "glob": "{json,xml" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '{'") && w.contains("allow.query.format.glob")),
            "expected glob syntax warning, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_any_warns_on_malformed_glob_item() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "tag": { "any": ["valid-*", "[bad"] }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "malformed glob in any should warn, not error: {errors:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("unclosed '['") && w.contains("allow.query.tag.any")),
            "expected glob syntax warning for any item, got: {warnings:?}"
        );
    }

    #[test]
    fn validate_query_string_and_any_matchers_are_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 8080,
                        "protocol": "rest",
                        "rules": [{
                            "allow": {
                                "method": "GET",
                                "path": "/download",
                                "query": {
                                    "slug": "my-*",
                                    "tag": { "any": ["foo-*", "bar-*"] },
                                    "owner": { "glob": "org-*" }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _warnings) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid query matcher shapes should not error: {errors:?}"
        );
    }

    #[test]
    fn validate_jsonrpc_nested_params_matchers_are_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "jsonrpc.example.com",
                        "port": 443,
                        "protocol": "json-rpc",
                        "rules": [{
                            "allow": {
                                "method": "reports.search",
                                "params": {
                                    "query": "quarterly",
                                    "filters": {
                                        "scope": "workspace/main",
                                        "repository": { "any": ["NVIDIA/OpenShell", "NVIDIA/*"] }
                                    }
                                }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, warnings) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| { e.contains("rules[0].allow") && e.contains("do not support params") }),
            "JSON-RPC nested params matchers should be rejected: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "unsupported params should not emit warnings: {warnings:?}"
        );
    }

    // --- Deny rules validation tests ---

    #[test]
    fn validate_deny_rules_require_protocol() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "deny_rules": [{ "method": "POST", "path": "/admin" }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require protocol")),
            "should require protocol for deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_require_allow_base() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "deny_rules": [{ "method": "POST", "path": "/admin" }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules require rules or access")),
            "should require rules or access for deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_rules_empty_list_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "rules": []
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("rules list cannot be empty")),
            "should reject empty rules: {errors:?}"
        );
    }

    #[test]
    fn validate_rules_deny_all_with_empty_allow_object() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "rules": [{"allow": {"method": "", "path": ""}}]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.iter().any(|e| e.contains("would deny all traffic")),
            "should detect deny-all with empty allow object: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_params_selector_not_classified_as_deny_all() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{
                            "allow": {
                                "method": "",
                                "path": "",
                                "command": "",
                                "operation_type": "",
                                "operation_name": "",
                                "params": { "name": { "glob": "read_*" } }
                            }
                        }],
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "MCP rule with params.name selector should not be classified as deny-all: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_tool_selector_not_classified_as_deny_all() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{
                            "allow": {
                                "method": "",
                                "path": "",
                                "command": "",
                                "operation_type": "",
                                "operation_name": "",
                                "tool": "my-tool"
                            }
                        }],
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "MCP rule with tool selector should not be classified as deny-all: {errors:?}"
        );
    }

    #[test]
    fn validate_mcp_allow_all_with_empty_allow_not_denied() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "mcp.example.com",
                        "port": 443,
                        "protocol": "mcp",
                        "mcp_allow_all_known_mcp_methods": true,
                        "rules": [{"allow": {}}],
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            !errors.iter().any(|e| e.contains("would deny all traffic")),
            "MCP with allow_all and empty allow should not be rejected as deny-all: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_empty_list_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": []
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("deny_rules list cannot be empty")),
            "should reject empty deny_rules: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_valid_config_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "read-write",
                        "deny_rules": [
                            { "method": "POST", "path": "/repos/*/pulls/*/reviews" },
                            { "method": "PUT", "path": "/repos/*/branches/*/protection" }
                        ]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid deny_rules should not error: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_empty_any_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin",
                            "query": { "type": { "any": [] } }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("any: list must not be empty")),
            "should reject empty any list in deny query: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_non_string_rejected() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin",
                            "query": { "force": 123 }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expected string glob or matcher object")),
            "should reject non-string/non-object matcher in deny query: {errors:?}"
        );
    }

    #[test]
    fn validate_deny_rules_query_valid_matchers_accepted() {
        let data = serde_json::json!({
            "network_policies": {
                "test": {
                    "endpoints": [{
                        "host": "api.example.com",
                        "port": 443,
                        "protocol": "rest",
                        "access": "full",
                        "deny_rules": [{
                            "method": "POST",
                            "path": "/admin/**",
                            "query": {
                                "force": "true",
                                "type": { "any": ["admin-*", "root-*"] },
                                "scope": { "glob": "org-*" }
                            }
                        }]
                    }],
                    "binaries": []
                }
            }
        });
        let (errors, _) = validate_l7_policies(&data);
        assert!(
            errors.is_empty(),
            "valid deny query matchers should not error: {errors:?}"
        );
    }
}
