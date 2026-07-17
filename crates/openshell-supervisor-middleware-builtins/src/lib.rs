// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! First-party in-process supervisor middleware implementations.

mod regex;

use std::sync::Arc;

use miette::{Result, miette};
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, MiddlewareManifest, ValidateConfigRequest,
    ValidateConfigResponse,
};
use tonic::{Request, Response, Status};

pub use regex::{NAME as BUILTIN_REGEX, RegexConfig, RegexMode};

/// Return the first-party services that the gateway and supervisor install.
pub fn services() -> Vec<Arc<dyn SupervisorMiddleware>> {
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

fn evaluate_http_request(evaluation: &HttpRequestEvaluation) -> Result<HttpRequestResult> {
    match evaluation.middleware_name.as_str() {
        BUILTIN_REGEX => regex::evaluate_http_request(evaluation),
        other => Err(miette!(
            "middleware implementation '{other}' is not a registered OpenShell built-in"
        )),
    }
}

/// Built-in regex service exposed through the standard middleware contract.
#[derive(Debug, Default)]
pub struct BuiltinMiddlewareService;

#[tonic::async_trait]
impl SupervisorMiddleware for BuiltinMiddlewareService {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: BUILTIN_REGEX.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![regex::describe()],
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let config = request.config.unwrap_or_default();
        Ok(Response::new(
            match validate_config(&request.middleware_name, &config) {
                Ok(()) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(error) => ValidateConfigResponse {
                    valid: false,
                    reason: error.to_string(),
                },
            },
        ))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        evaluate_http_request(&request.into_inner())
            .map(Response::new)
            .map_err(|error| Status::invalid_argument(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::{
        Decision, SupervisorMiddlewareOperation, SupervisorMiddlewarePhase,
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

    #[tokio::test]
    async fn service_describes_regex_binding() {
        let manifest = BuiltinMiddlewareService
            .describe(Request::new(()))
            .await
            .expect("describe")
            .into_inner();
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
    fn regex_replacement_evaluates_through_binding() {
        let result = evaluate_http_request(&HttpRequestEvaluation {
            middleware_name: BUILTIN_REGEX.into(),
            body: br#"{"password":"top-secret","token":"sk-ABCDEFGHIJKLMNOP"}"#.to_vec(),
            config: Some(prost_types::Struct::default()),
            ..Default::default()
        })
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
        let result = evaluate_http_request(&HttpRequestEvaluation {
            middleware_name: BUILTIN_REGEX.into(),
            body: body.as_bytes().to_vec(),
            config: Some(prost_types::Struct::default()),
            ..Default::default()
        })
        .expect("evaluate regex binding");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert_eq!(result.body, body.as_bytes());
        assert!(result.findings.is_empty());
    }
}
