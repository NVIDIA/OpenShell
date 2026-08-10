// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! First-party in-process supervisor middleware implementations.

mod regex;

use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::middleware::{HttpRequestView, InProcessMiddleware};
use openshell_core::proto::{HttpRequestResult, MiddlewareManifest};

pub use regex::{NAME as BUILTIN_REGEX, RegexConfig, RegexMode};

/// Return the first-party in-process services installed by the gateway and supervisor.
pub fn services() -> Vec<Arc<dyn InProcessMiddleware>> {
    vec![Arc::new(BuiltinMiddlewareService)]
}

/// Validate configuration for a first-party binding.
pub fn validate_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_REGEX => regex::validate_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

fn evaluate_http_request(request: HttpRequestView<'_>) -> Result<HttpRequestResult> {
    match request.middleware_name() {
        BUILTIN_REGEX => regex::evaluate_http_request(request.config(), request.body()),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

/// Aggregate service exposing first-party middleware through the borrowed in-process contract.
#[derive(Debug, Default)]
pub struct BuiltinMiddlewareService;

#[async_trait::async_trait]
impl InProcessMiddleware for BuiltinMiddlewareService {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: BUILTIN_REGEX.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![regex::describe()],
        }
    }

    async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> Result<()> {
        validate_config(middleware_name, config)
    }

    async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> Result<HttpRequestResult> {
        evaluate_http_request(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        Decision, HttpRequestTarget, RequestContext, SupervisorMiddlewareOperation,
        SupervisorMiddlewarePhase,
    };

    fn string_config(key: &str, value: &str) -> prost_types::Struct {
        prost_types::Struct {
            fields: std::iter::once((
                key.to_string(),
                prost_types::Value {
                    kind: Some(prost_types::value::Kind::StringValue(value.into())),
                },
            ))
            .collect(),
        }
    }

    fn evaluate_body(body: &[u8], config: &prost_types::Struct) -> Result<HttpRequestResult> {
        let context = RequestContext::default();
        let target = HttpRequestTarget::default();
        evaluate_http_request(HttpRequestView::new(
            SupervisorMiddlewarePhase::PreCredentials,
            &context,
            config,
            &target,
            &[],
            body,
            BUILTIN_REGEX,
        ))
    }

    #[tokio::test]
    async fn service_describes_regex_binding() {
        let manifest = BuiltinMiddlewareService.describe().await;
        assert_eq!(manifest.bindings.len(), 1);
        assert_eq!(
            manifest.bindings[0].operation,
            SupervisorMiddlewareOperation::HttpRequest as i32
        );
        assert_eq!(
            manifest.bindings[0].phase,
            SupervisorMiddlewarePhase::PreCredentials as i32
        );
        assert_eq!(manifest.bindings[0].max_body_bytes, 256 * 1024);
    }

    #[test]
    fn regex_config_defaults_to_redact() {
        let config = RegexConfig::from_struct(&prost_types::Struct::default()).unwrap();
        assert_eq!(config.mode, RegexMode::Redact);
    }

    #[test]
    fn regex_config_accepts_explicit_redact() {
        let config = RegexConfig::from_struct(&string_config("mode", "redact")).unwrap();
        assert_eq!(config.mode, RegexMode::Redact);
    }

    #[test]
    fn regex_config_rejects_unsupported_or_malformed_values() {
        for config in [
            string_config("mode", "allow"),
            string_config("patterns", "password"),
            prost_types::Struct {
                fields: std::iter::once((
                    "mode".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::NumberValue(42.0)),
                    },
                ))
                .collect(),
            },
        ] {
            assert!(validate_config(BUILTIN_REGEX, &config).is_err());
        }
    }

    #[test]
    fn registry_rejects_unknown_builtin_name() {
        let error = validate_config("openshell/unknown", &prost_types::Struct::default())
            .expect_err("unknown built-in");
        assert!(
            error
                .to_string()
                .contains("is not a registered OpenShell built-in")
        );
    }

    #[test]
    fn regex_replacement_evaluates_through_binding() {
        let result = evaluate_body(
            br#"{"password":"top-secret","token":"sk-ABCDEFGHIJKLMNOP"}"#,
            &prost_types::Struct::default(),
        )
        .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(result.has_body);
        let body = String::from_utf8(result.body).unwrap();
        assert!(body.contains("top-secret"));
        assert!(!body.contains("sk-ABCDEFGHIJKLMNOP"));
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.r#type != "regex.keyword")
        );
    }

    #[test]
    fn regex_replacement_does_not_parse_keyword_assignments() {
        let body = concat!(
            r#"{"password":"alpha beta","secret":"alpha,beta","api_key":"alpha\"beta"}"#,
            "\npassword=alpha\nnotpassword=omega"
        );
        let result = evaluate_body(body.as_bytes(), &prost_types::Struct::default())
            .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert!(result.body.is_empty());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn regex_rejects_non_utf8_borrowed_body() {
        let error =
            evaluate_body(&[0xff], &prost_types::Struct::default()).expect_err("non-UTF-8 body");
        assert!(error.to_string().contains("requires UTF-8 request bodies"));
    }
}
