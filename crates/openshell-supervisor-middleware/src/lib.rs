// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process supervisor middleware chain execution.

mod builtins;
mod service;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use miette::{Result, miette};
pub use service::InProcessMiddlewareService;

use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestTarget, NetworkMiddlewareConfig,
    RequestContext,
};
use tonic::Request;

pub const API_VERSION: &str = "openshell.middleware.v1";
pub const HTTP_REQUEST_OPERATION: &str = "HttpRequest";
pub const PRE_CREDENTIALS_PHASE: &str = "pre_credentials";
pub const BUILTIN_SECRETS: &str = "openshell/secrets";

/// Validate the configuration for an in-process middleware implementation.
///
/// Policy admission uses this same implementation-specific validation before a
/// configuration can reach the request path.
pub fn validate_builtin_config(implementation: &str, config: &prost_types::Struct) -> Result<()> {
    match implementation {
        BUILTIN_SECRETS => builtins::secrets::validate_config(config),
        other => Err(miette!(
            "middleware implementation '{other}' is not available in phase 1"
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    FailClosed,
    FailOpen,
}

impl OnError {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "" | "fail_closed" => Ok(Self::FailClosed),
            "fail_open" => Ok(Self::FailOpen),
            other => Err(miette!(
                "invalid middleware on_error '{other}', expected fail_closed or fail_open"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainEntry {
    pub name: String,
    pub implementation: String,
    pub config: prost_types::Struct,
    pub on_error: OnError,
}

impl TryFrom<&NetworkMiddlewareConfig> for ChainEntry {
    type Error = miette::Report;

    fn try_from(value: &NetworkMiddlewareConfig) -> Result<Self> {
        if value.name.is_empty() {
            return Err(miette!("middleware config name cannot be empty"));
        }
        if value.middleware.is_empty() {
            return Err(miette!(
                "middleware config '{}' must name an implementation",
                value.name
            ));
        }
        Ok(Self {
            name: value.name.clone(),
            implementation: value.middleware.clone(),
            config: value.config.clone().unwrap_or_default(),
            on_error: OnError::parse(&value.on_error)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HttpRequestInput {
    pub request_id: String,
    pub sandbox_id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ChainOutcome {
    pub allowed: bool,
    pub reason: String,
    pub body: Vec<u8>,
    pub added_headers: BTreeMap<String, String>,
    pub findings: Vec<NamespacedFinding>,
    pub metadata: BTreeMap<String, BTreeMap<String, String>>,
    pub applied: Vec<MiddlewareInvocation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespacedFinding {
    pub middleware: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiddlewareInvocation {
    pub name: String,
    pub implementation: String,
    pub decision: Decision,
    pub transformed: bool,
    /// True when the middleware could not be evaluated and `on_error` was applied
    /// (service error, malformed/unsafe response, etc.). The `decision` reflects
    /// the `on_error` outcome, not a decision the middleware actually returned.
    pub failed: bool,
}

enum OnErrorAction {
    /// `fail_open`: skip this middleware, leaving the request unchanged.
    FailOpen,
    /// `fail_closed`: short-circuit the chain and deny with the given reason.
    FailClosed(String),
}

/// Apply a middleware entry's `on_error` policy after a failure (service error or
/// malformed response). Records a `failed` invocation for telemetry in both cases.
fn apply_on_error(
    entry: &ChainEntry,
    reason: &str,
    applied: &mut Vec<MiddlewareInvocation>,
) -> OnErrorAction {
    match entry.on_error {
        OnError::FailOpen => {
            applied.push(MiddlewareInvocation {
                name: entry.name.clone(),
                implementation: entry.implementation.clone(),
                decision: Decision::Allow,
                transformed: false,
                failed: true,
            });
            OnErrorAction::FailOpen
        }
        OnError::FailClosed => {
            applied.push(MiddlewareInvocation {
                name: entry.name.clone(),
                implementation: entry.implementation.clone(),
                decision: Decision::Deny,
                transformed: false,
                failed: true,
            });
            OnErrorAction::FailClosed(format!("middleware_failed: {reason}"))
        }
    }
}

#[derive(Clone)]
pub struct ChainRunner {
    service: Arc<dyn SupervisorMiddleware>,
}

impl Default for ChainRunner {
    fn default() -> Self {
        Self::new(Arc::new(InProcessMiddlewareService))
    }
}

impl ChainRunner {
    pub fn new(service: Arc<dyn SupervisorMiddleware>) -> Self {
        Self { service }
    }

    pub async fn evaluate(
        &self,
        entries: &[ChainEntry],
        input: HttpRequestInput,
    ) -> Result<ChainOutcome> {
        let mut headers = input.headers.clone();
        let mut body = input.body.clone();
        let mut added_headers = BTreeMap::new();
        let mut findings = Vec::new();
        let mut metadata = BTreeMap::new();
        let mut applied = Vec::new();

        for entry in entries {
            let evaluation = build_evaluation(entry, &input, &headers, &body);
            let result = match self
                .service
                .evaluate_http_request(Request::new(evaluation))
                .await
            {
                Ok(result) => result.into_inner(),
                Err(err) => {
                    match apply_on_error(entry, &safe_reason(&err.to_string()), &mut applied) {
                        OnErrorAction::FailOpen => continue,
                        OnErrorAction::FailClosed(reason) => {
                            return Ok(ChainOutcome {
                                allowed: false,
                                reason,
                                body,
                                added_headers,
                                findings,
                                metadata,
                                applied,
                            });
                        }
                    }
                }
            };

            let decision = match Decision::try_from(result.decision) {
                Ok(decision @ (Decision::Allow | Decision::Deny)) => decision,
                Ok(Decision::Unspecified) | Err(_) => {
                    match apply_on_error(entry, "invalid_response_decision", &mut applied) {
                        OnErrorAction::FailOpen => continue,
                        OnErrorAction::FailClosed(reason) => {
                            return Ok(ChainOutcome {
                                allowed: false,
                                reason,
                                body,
                                added_headers,
                                findings,
                                metadata,
                                applied,
                            });
                        }
                    }
                }
            };

            // A result proposing unsafe header mutations is a malformed response:
            // route it through `on_error` instead of applying any of it.
            if validate_header_mutations(&headers, &result.add_headers).is_err() {
                match apply_on_error(entry, "unsafe_response_headers", &mut applied) {
                    OnErrorAction::FailOpen => continue,
                    OnErrorAction::FailClosed(reason) => {
                        return Ok(ChainOutcome {
                            allowed: false,
                            reason,
                            body,
                            added_headers,
                            findings,
                            metadata,
                            applied,
                        });
                    }
                }
            }
            for (name, value) in &result.add_headers {
                headers.insert(name.to_ascii_lowercase(), value.clone());
                added_headers.insert(name.to_ascii_lowercase(), value.clone());
            }
            let transformed = result.has_body;
            if result.has_body {
                result.body.clone_into(&mut body);
            }
            for finding in result.findings {
                findings.push(NamespacedFinding {
                    middleware: entry.name.clone(),
                    finding,
                });
            }
            if !result.metadata.is_empty() {
                metadata.insert(
                    entry.name.clone(),
                    result.metadata.clone().into_iter().collect(),
                );
            }
            applied.push(MiddlewareInvocation {
                name: entry.name.clone(),
                implementation: entry.implementation.clone(),
                decision,
                transformed,
                failed: false,
            });
            if decision == Decision::Deny {
                return Ok(ChainOutcome {
                    allowed: false,
                    reason: safe_reason(&result.reason),
                    body,
                    added_headers,
                    findings,
                    metadata,
                    applied,
                });
            }
        }

        Ok(ChainOutcome {
            allowed: true,
            reason: String::new(),
            body,
            added_headers,
            findings,
            metadata,
            applied,
        })
    }
}

fn build_evaluation(
    entry: &ChainEntry,
    input: &HttpRequestInput,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        api_version: API_VERSION.into(),
        binding_id: entry.implementation.clone(),
        phase: PRE_CREDENTIALS_PHASE.into(),
        context: Some(RequestContext {
            request_id: input.request_id.clone(),
            sandbox_id: input.sandbox_id.clone(),
            originating_process: None,
        }),
        config: Some(entry.config.clone()),
        target: Some(HttpRequestTarget {
            scheme: input.scheme.clone(),
            host: input.host.clone(),
            port: u32::from(input.port),
            method: input.method.clone(),
            path: input.path.clone(),
            query: input.query.clone(),
        }),
        headers: headers.clone().into_iter().collect(),
        body: body.to_vec(),
    }
}

fn validate_header_mutations(
    existing_headers: &BTreeMap<String, String>,
    mutations: &HashMap<String, String>,
) -> Result<()> {
    let mut seen = HashSet::new();
    for (name, value) in mutations {
        let lower = name.to_ascii_lowercase();
        if !seen.insert(lower.clone()) || existing_headers.contains_key(&lower) {
            return Err(miette!(
                "middleware cannot rewrite existing header '{name}'"
            ));
        }
        if !is_safe_append_header(&lower) {
            return Err(miette!("middleware cannot append unsafe header '{name}'"));
        }
        // Reject CR/LF and other control characters in the value: writing them
        // verbatim into the upstream header block would enable header injection
        // and request smuggling past the credential boundary.
        if !is_safe_header_value(value) {
            return Err(miette!(
                "middleware cannot append header '{name}' with an unsafe value"
            ));
        }
    }
    Ok(())
}

/// A header value is safe to append only if it contains no control characters.
/// Horizontal tab, printable ASCII, and obs-text (>= 0x80) are permitted; CR, LF,
/// NUL, and other control bytes are rejected.
fn is_safe_header_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

fn is_safe_append_header(name: &str) -> bool {
    if name.is_empty()
        || name.contains(':')
        || name.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || matches!(
            name,
            "authorization" | "cookie" | "host" | "content-length" | "transfer-encoding"
        )
        || name.starts_with("x-amz-")
        || name.starts_with("x-openshell-credential")
    {
        return false;
    }
    name.starts_with("x-openshell-middleware-")
}

pub(crate) fn safe_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | ':' | ' '))
        .take(160)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;

    fn entry(name: &str, on_error: OnError) -> ChainEntry {
        ChainEntry {
            name: name.into(),
            implementation: BUILTIN_SECRETS.into(),
            config: prost_types::Struct {
                fields: std::iter::once((
                    "secrets".into(),
                    prost_types::Value {
                        kind: Some(prost_types::value::Kind::StringValue("redact".into())),
                    },
                ))
                .collect(),
            },
            on_error,
        }
    }

    fn input(body: &str) -> HttpRequestInput {
        HttpRequestInput {
            request_id: "req".into(),
            sandbox_id: "sbx".into(),
            scheme: "https".into(),
            host: "api.example.com".into(),
            port: 443,
            method: "POST".into(),
            path: "/v1".into(),
            query: String::new(),
            headers: BTreeMap::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn phase_one_evaluation_omits_originating_process() {
        let entry = entry("redact", OnError::FailClosed);
        let input = input("payload");
        let evaluation = build_evaluation(&entry, &input, &BTreeMap::new(), b"payload");

        assert!(
            evaluation
                .context
                .expect("request context")
                .originating_process
                .is_none()
        );
    }

    #[tokio::test]
    async fn redacts_common_secret_patterns() {
        let outcome = ChainRunner::default()
            .evaluate(
                &[entry("redact", OnError::FailClosed)],
                input(r#"{"api_key":"sk-1234567890abcdef"}"#),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"{"api_key":"[REDACTED]"}"#
        );
        assert_eq!(outcome.findings[0].finding.count, 1);
    }

    #[tokio::test]
    async fn transformed_body_feeds_next_stage() {
        let entries = [
            entry("first", OnError::FailClosed),
            entry("second", OnError::FailClosed),
        ];
        let outcome = ChainRunner::default()
            .evaluate(&entries, input(r#"password="top-secret""#))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(
            String::from_utf8(outcome.body).expect("utf8"),
            r#"password="[REDACTED]""#
        );
        assert_eq!(outcome.applied.len(), 2);
    }

    #[tokio::test]
    async fn fail_open_allows_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailOpen,
        };
        let outcome = ChainRunner::default()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
    }

    #[tokio::test]
    async fn fail_closed_denies_unavailable_middleware() {
        let unavailable = ChainEntry {
            name: "missing".into(),
            implementation: "third-party/missing".into(),
            config: prost_types::Struct::default(),
            on_error: OnError::FailClosed,
        };
        let outcome = ChainRunner::default()
            .evaluate(&[unavailable], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
    }

    #[tokio::test]
    async fn in_process_service_describes_builtin_binding() {
        let manifest = InProcessMiddlewareService
            .describe(Request::new(()))
            .await
            .expect("describe")
            .into_inner();
        assert_eq!(manifest.api_version, API_VERSION);
        assert_eq!(manifest.bindings[0].id, BUILTIN_SECRETS);
        assert_eq!(manifest.bindings[0].operation, HTTP_REQUEST_OPERATION);
        assert_eq!(manifest.bindings[0].phase, PRE_CREDENTIALS_PHASE);
    }

    #[test]
    fn unsafe_header_mutation_is_rejected() {
        let err = validate_header_mutations(
            &BTreeMap::new(),
            &std::iter::once(("Authorization".into(), "Bearer nope".into())).collect(),
        )
        .expect_err("unsafe header");
        assert!(err.to_string().contains("unsafe header"));
    }

    #[test]
    fn header_value_with_crlf_is_rejected() {
        // A safe header *name* with a CRLF-bearing value must still be rejected,
        // otherwise it would inject extra headers into the upstream request.
        let err = validate_header_mutations(
            &BTreeMap::new(),
            &std::iter::once((
                "x-openshell-middleware-inject".into(),
                "ok\r\nAuthorization: Bearer evil".into(),
            ))
            .collect(),
        )
        .expect_err("crlf value");
        assert!(err.to_string().contains("unsafe value"));
    }

    /// A mock middleware that returns a fixed, caller-supplied result for every
    /// evaluation. Used to exercise chain behavior the built-in cannot produce
    /// (explicit deny, metadata, findings, unsafe header mutations).
    struct ScriptedService {
        result: openshell_core::proto::HttpRequestResult,
    }

    #[tonic::async_trait]
    impl SupervisorMiddleware for ScriptedService {
        async fn describe(
            &self,
            _request: Request<()>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::MiddlewareManifest>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::MiddlewareManifest::default(),
            ))
        }

        async fn validate_config(
            &self,
            _request: Request<openshell_core::proto::ValidateConfigRequest>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::ValidateConfigResponse>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(
                openshell_core::proto::ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
            ))
        }

        async fn evaluate_http_request(
            &self,
            _request: Request<HttpRequestEvaluation>,
        ) -> std::result::Result<
            tonic::Response<openshell_core::proto::HttpRequestResult>,
            tonic::Status,
        > {
            Ok(tonic::Response::new(self.result.clone()))
        }
    }

    fn allow_result() -> openshell_core::proto::HttpRequestResult {
        openshell_core::proto::HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            add_headers: HashMap::new(),
            findings: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn deny_decision_short_circuits_chain() {
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            result: openshell_core::proto::HttpRequestResult {
                decision: Decision::Deny as i32,
                reason: "blocked_by_policy".into(),
                ..allow_result()
            },
        }));
        let outcome = runner
            .evaluate(
                &[
                    entry("first", OnError::FailClosed),
                    entry("second", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert_eq!(outcome.reason, "blocked_by_policy");
        // The deny short-circuits the chain: the second middleware never runs.
        assert_eq!(outcome.applied.len(), 1);
        assert_eq!(outcome.applied[0].decision, Decision::Deny);
        assert!(!outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn metadata_and_findings_are_namespaced_per_config() {
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            result: openshell_core::proto::HttpRequestResult {
                findings: vec![Finding {
                    r#type: "pii.email".into(),
                    label: "email address".into(),
                    count: 2,
                    confidence: "high".into(),
                    severity: "medium".into(),
                }],
                metadata: std::iter::once(("sensitivity".to_string(), "high".to_string()))
                    .collect(),
                ..allow_result()
            },
        }));
        let outcome = runner
            .evaluate(
                &[
                    entry("alpha", OnError::FailClosed),
                    entry("beta", OnError::FailClosed),
                ],
                input("hello"),
            )
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        // Metadata is bucketed under each config's local name, so two configs
        // emitting the same key do not collide.
        assert_eq!(outcome.metadata["alpha"]["sensitivity"], "high");
        assert_eq!(outcome.metadata["beta"]["sensitivity"], "high");
        // Findings are tagged with the emitting config's name.
        assert_eq!(outcome.findings.len(), 2);
        assert_eq!(outcome.findings[0].middleware, "alpha");
        assert_eq!(outcome.findings[1].middleware, "beta");
        assert_eq!(outcome.findings[0].finding.r#type, "pii.email");
        assert_eq!(outcome.findings[0].finding.count, 2);
    }

    fn unsafe_header_service() -> ScriptedService {
        ScriptedService {
            result: openshell_core::proto::HttpRequestResult {
                add_headers: std::iter::once((
                    "x-openshell-middleware-inject".to_string(),
                    "ok\r\nHost: evil".to_string(),
                ))
                .collect(),
                ..allow_result()
            },
        }
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_closed_denies() {
        let runner = ChainRunner::new(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");
        assert!(!outcome.allowed);
        assert!(outcome.reason.starts_with("middleware_failed:"));
        assert!(outcome.applied.iter().any(|inv| inv.failed));
        // The unsafe header is never forwarded.
        assert!(outcome.added_headers.is_empty());
    }

    #[tokio::test]
    async fn malformed_response_headers_fail_open_continues() {
        let runner = ChainRunner::new(Arc::new(unsafe_header_service()));
        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailOpen)], input("hello"))
            .await
            .expect("evaluate");
        assert!(outcome.allowed);
        assert_eq!(outcome.body, b"hello");
        assert!(outcome.added_headers.is_empty());
        assert_eq!(outcome.applied.len(), 1);
        assert!(outcome.applied[0].failed);
    }

    #[tokio::test]
    async fn unspecified_decision_uses_fail_closed() {
        let runner = ChainRunner::new(Arc::new(ScriptedService {
            result: openshell_core::proto::HttpRequestResult {
                decision: Decision::Unspecified as i32,
                ..allow_result()
            },
        }));

        let outcome = runner
            .evaluate(&[entry("redact", OnError::FailClosed)], input("hello"))
            .await
            .expect("evaluate");

        assert!(!outcome.allowed);
        assert_eq!(
            outcome.reason,
            "middleware_failed: invalid_response_decision"
        );
        assert!(outcome.applied[0].failed);
    }
}
