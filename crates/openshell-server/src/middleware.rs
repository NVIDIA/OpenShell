// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;
use tonic::Status;

/// Validate implementation-owned middleware config, and the HTTP protocol
/// rules, before accepting a policy.
pub async fn validate_policy(
    registry: &MiddlewareRegistry,
    policy: &SandboxPolicy,
) -> Result<(), Status> {
    async {
        registry.validate_policy_configs(policy).await?;
        registry.validate_http_protocol_rules(policy).await
    }
    .await
    .map_err(|error| {
        Status::invalid_argument(format!("policy middleware validation failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::extension_protocol::{ExtensionFamily, extension_metadata};
    use openshell_core::proto::{
        HttpRequestResult, MiddlewareBinding, MiddlewareEndpointSelector, MiddlewareManifest,
        NetworkMiddlewareConfig, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    };
    use openshell_supervisor_middleware::{HttpRequestView, InProcessMiddleware};
    use std::sync::Arc;

    /// HTTP protocol 2 middleware with the given HTTP operations, and
    /// optionally a WebSocket binding.
    struct ProtocolTwoMiddleware {
        name: &'static str,
        operations: &'static [SupervisorMiddlewareOperation],
        websocket: bool,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for ProtocolTwoMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            let mut bindings: Vec<_> = self
                .operations
                .iter()
                .map(|operation| MiddlewareBinding {
                    operation: *operation as i32,
                    phase: if *operation == SupervisorMiddlewareOperation::HttpResponseV2 {
                        SupervisorMiddlewarePhase::PreReturn as i32
                    } else {
                        SupervisorMiddlewarePhase::PreCredentials as i32
                    },
                    max_payload_bytes: 1024,
                    ..Default::default()
                })
                .collect();
            if self.websocket {
                bindings.push(MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 1024,
                    ..Default::default()
                });
            }
            MiddlewareManifest {
                name: self.name.into(),
                bindings,
                extension: Some(extension_metadata(
                    ExtensionFamily::SupervisorMiddleware,
                    self.name,
                    "test",
                    [],
                )),
                ..Default::default()
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Err(miette::miette!("HTTP protocol 2 test middleware"))
        }
    }

    async fn registry() -> MiddlewareRegistry {
        let mut services = openshell_supervisor_middleware_builtins::services();
        services.push(Arc::new(ProtocolTwoMiddleware {
            name: "example/guard",
            operations: &[
                SupervisorMiddlewareOperation::HttpRequestV2,
                SupervisorMiddlewareOperation::HttpResponseV2,
            ],
            websocket: false,
        }));
        services.push(Arc::new(ProtocolTwoMiddleware {
            name: "example/guard-with-websocket",
            operations: &[SupervisorMiddlewareOperation::HttpRequestV2],
            websocket: true,
        }));
        services.push(Arc::new(ProtocolTwoMiddleware {
            name: "example/response-guard",
            operations: &[SupervisorMiddlewareOperation::HttpResponseV2],
            websocket: false,
        }));
        MiddlewareRegistry::connect_services(services, Vec::new())
            .await
            .expect("registry")
    }

    fn entry(
        middleware: &str,
        order: i32,
        include: &str,
        on_error: &str,
    ) -> NetworkMiddlewareConfig {
        NetworkMiddlewareConfig {
            middleware: middleware.into(),
            order,
            on_error: on_error.into(),
            endpoints: Some(MiddlewareEndpointSelector {
                include: vec![include.into()],
                exclude: Vec::new(),
            }),
            ..Default::default()
        }
    }

    fn policy(entries: Vec<(&str, NetworkMiddlewareConfig)>) -> SandboxPolicy {
        SandboxPolicy {
            network_middlewares: entries
                .into_iter()
                .map(|(name, entry)| (name.to_string(), entry))
                .collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fail_open_is_rejected_on_http_protocol_2_middleware() {
        let registry = registry().await;
        for middleware in ["example/guard", "example/guard-with-websocket"] {
            let error = validate_policy(
                &registry,
                &policy(vec![(
                    "guard",
                    entry(middleware, 0, "api.example.com", "fail_open"),
                )]),
            )
            .await
            .expect_err("HTTP protocol 2 middleware is always fail-closed");
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
            assert!(
                error.message().contains("cannot use on_error: fail_open"),
                "{}",
                error.message()
            );
        }
        validate_policy(
            &registry,
            &policy(vec![(
                "redactor",
                entry(
                    openshell_supervisor_middleware_builtins::BUILTIN_REGEX,
                    0,
                    "api.example.com",
                    "fail_open",
                ),
            )]),
        )
        .await
        .expect("HTTP protocol 1 middleware keeps fail_open");
    }

    #[tokio::test]
    async fn overlapping_selectors_must_use_one_http_protocol_per_operation() {
        let registry = registry().await;
        let regex = openshell_supervisor_middleware_builtins::BUILTIN_REGEX;
        let error = validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "*.example.com", "")),
                ("guard", entry("example/guard", 1, "api.example.com", "")),
            ]),
        )
        .await
        .expect_err("one HTTP request cannot run both protocols");
        assert!(
            error
                .message()
                .contains("separate their endpoint selectors"),
            "{}",
            error.message()
        );

        // Disjoint selectors never select the same message.
        validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "legacy.example.com", "")),
                ("guard", entry("example/guard", 1, "api.example.com", "")),
            ]),
        )
        .await
        .expect("disjoint selectors may use different protocols");

        // The regex middleware has no response binding, so a response-only
        // HTTP protocol 2 service may share its selector.
        validate_policy(
            &registry,
            &policy(vec![
                ("redactor", entry(regex, 0, "api.example.com", "")),
                (
                    "guard",
                    entry("example/response-guard", 1, "api.example.com", ""),
                ),
            ]),
        )
        .await
        .expect("no HTTP operation is served by both protocols");
    }

    #[tokio::test]
    async fn tls_skip_rule_exempts_registered_http_protocol_2_middleware() {
        let registry = registry().await;
        let tls_skip_policy = |middleware: &str| {
            let mut policy = SandboxPolicy {
                network_middlewares: std::collections::HashMap::from([(
                    "guard".into(),
                    entry(middleware, 0, "api.example.com", ""),
                )]),
                ..Default::default()
            };
            policy.network_policies.insert(
                "api".into(),
                openshell_core::proto::NetworkPolicyRule {
                    name: "api".into(),
                    endpoints: vec![openshell_core::proto::NetworkEndpoint {
                        host: "api.example.com".into(),
                        port: 443,
                        tls: openshell_core::proto::NetworkTlsMode::Skip as i32,
                        ..Default::default()
                    }],
                    binaries: Vec::new(),
                },
            );
            policy
        };
        let conflicts = |middleware: &str| {
            openshell_policy::middleware_tls_skip_conflicts(
                &tls_skip_policy(middleware),
                |middleware| registry.is_http_v2(middleware),
            )
        };

        assert!(conflicts("example/guard").is_empty());
        assert_eq!(
            conflicts(openshell_supervisor_middleware_builtins::BUILTIN_REGEX).len(),
            1,
            "HTTP protocol 1 fail-closed middleware cannot cover tls: skip"
        );
    }

    #[tokio::test]
    async fn unregistered_external_middleware_is_rejected_before_admission() {
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    middleware: "example/content-guard".into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&MiddlewareRegistry::default(), &policy)
            .await
            .expect_err("unregistered middleware must fail");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("not registered"));
    }

    #[tokio::test]
    async fn invalid_builtin_config_is_rejected_by_implementation() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("built-in registry");
        let policy = SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "redactor".into(),
                NetworkMiddlewareConfig {
                    middleware: openshell_supervisor_middleware_builtins::BUILTIN_REGEX.into(),
                    config: Some(prost_types::Struct {
                        fields: std::iter::once((
                            "mode".into(),
                            prost_types::Value {
                                kind: Some(prost_types::value::Kind::StringValue("allow".into())),
                            },
                        ))
                        .collect(),
                    }),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let error = validate_policy(&registry, &policy)
            .await
            .expect_err("invalid built-in config must fail admission");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains("supports only mode: redact"));
    }
}
