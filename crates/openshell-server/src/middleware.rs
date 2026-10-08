// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::proto::SandboxPolicy;
use openshell_supervisor_middleware::MiddlewareRegistry;
use tonic::Status;

/// Validate implementation-owned middleware config, and the scope of
/// `on_error`, before accepting a policy.
pub async fn validate_policy(
    registry: &MiddlewareRegistry,
    policy: &SandboxPolicy,
) -> Result<(), Status> {
    async {
        registry.validate_policy_configs(policy).await?;
        registry.validate_on_error_scope(policy).await
    }
    .await
    .map_err(|error| {
        Status::invalid_argument(format!("policy middleware validation failed: {error}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        HttpRequestResult, MiddlewareBinding, MiddlewareManifest, NetworkMiddlewareConfig,
        SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
    };
    use openshell_supervisor_middleware::{HttpRequestView, InProcessMiddleware};
    use std::sync::Arc;

    /// Middleware whose HTTP request binding uses version 2, optionally with a
    /// WebSocket binding.
    struct VersionTwoMiddleware {
        websocket: bool,
    }

    #[tonic::async_trait]
    impl InProcessMiddleware for VersionTwoMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            let mut bindings = vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                http_protocol_version: 2,
                ..Default::default()
            }];
            if self.websocket {
                bindings.push(MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::WebsocketMessage as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_payload_bytes: 1024,
                    ..Default::default()
                });
            }
            let name = if self.websocket {
                "example/v2-http-and-websocket"
            } else {
                "example/v2-http"
            };
            MiddlewareManifest {
                name: name.into(),
                bindings,
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    name,
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
            Err(miette::miette!("version 2-only test middleware"))
        }
    }

    fn fail_open_policy(middleware: &str, on_uninspectable: &str) -> SandboxPolicy {
        SandboxPolicy {
            network_middlewares: std::collections::HashMap::from([(
                "guard".into(),
                NetworkMiddlewareConfig {
                    middleware: middleware.into(),
                    on_error: "fail_open".into(),
                    on_uninspectable: on_uninspectable.into(),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn on_error_fail_open_is_rejected_where_it_has_no_effect() {
        let registry = MiddlewareRegistry::connect_services_with_http_v2(
            vec![
                Arc::new(VersionTwoMiddleware { websocket: false }),
                Arc::new(VersionTwoMiddleware { websocket: true }),
            ],
            Vec::new(),
        )
        .await
        .expect("registry");

        let error = validate_policy(&registry, &fail_open_policy("example/v2-http", "deny"))
            .await
            .expect_err("version 2 HTTP middleware is always fail-closed");
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(error.message().contains(
            "on_error applies only to WebSocket bindings and, until 0.2.0, legacy HTTP bindings; version 2 HTTP middleware is fail-closed"
        ));

        validate_policy(
            &registry,
            &fail_open_policy("example/v2-http-and-websocket", "deny"),
        )
        .await
        .expect("fail_open still governs the WebSocket binding");
        for on_uninspectable in ["", "allow"] {
            validate_policy(
                &registry,
                &fail_open_policy("example/v2-http", on_uninspectable),
            )
            .await
            .expect("fail_open still governs uninspectable traffic");
        }
    }

    #[tokio::test]
    async fn on_error_fail_open_stays_valid_for_legacy_http_and_websocket_bindings() {
        let registry = MiddlewareRegistry::connect_services(
            openshell_supervisor_middleware_builtins::services(),
            Vec::new(),
        )
        .await
        .expect("built-in registry");
        validate_policy(
            &registry,
            &fail_open_policy(
                openshell_supervisor_middleware_builtins::BUILTIN_REGEX,
                "deny",
            ),
        )
        .await
        .expect("openshell/regex keeps legacy HTTP and WebSocket fail_open");
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
