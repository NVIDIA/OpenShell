// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

use clap::Parser;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::{
    SupervisorMiddleware, SupervisorMiddlewareServer,
};
use openshell_core::proto::{
    Decision, Finding, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareManifest, ValidateConfigRequest, ValidateConfigResponse,
};
use prost_types::Struct;
use prost_types::value::Kind;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const API_VERSION: &str = "openshell.middleware.v1";
const BINDING_ID: &str = "example/content-guard";
const OPERATION: &str = "HttpRequest";
const PHASE: &str = "pre_credentials";
const MAX_BODY_BYTES: u64 = 256 * 1024;
const DEFAULT_REPLACEMENT: &str = "[REDACTED]";

#[derive(Debug, Parser)]
#[command(about = "Run the example OpenShell supervisor middleware service")]
struct Cli {
    /// Address on which to serve plaintext gRPC.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Redact,
    Deny,
}

#[derive(Debug, PartialEq, Eq)]
struct GuardConfig {
    mode: Mode,
    terms: Vec<String>,
    replacement: String,
}

impl GuardConfig {
    fn parse(config: Option<&Struct>) -> Result<Self, String> {
        let config = config.ok_or_else(|| "config is required".to_string())?;
        if let Some(field) = config
            .fields
            .keys()
            .find(|field| !matches!(field.as_str(), "mode" | "terms" | "replacement"))
        {
            return Err(format!("unsupported config field '{field}'"));
        }

        let mode = match string_field(config, "mode").unwrap_or("redact") {
            "redact" => Mode::Redact,
            "deny" => Mode::Deny,
            _ => return Err("config.mode must be 'redact' or 'deny'".into()),
        };

        let terms = config
            .fields
            .get("terms")
            .and_then(|value| match value.kind.as_ref() {
                Some(Kind::ListValue(value)) => Some(&value.values),
                _ => None,
            })
            .ok_or_else(|| "config.terms must be a non-empty string list".to_string())?;
        let mut unique_terms = BTreeSet::new();
        for term in terms {
            let Some(Kind::StringValue(term)) = term.kind.as_ref() else {
                return Err("config.terms must contain only strings".into());
            };
            if term.is_empty() {
                return Err("config.terms cannot contain an empty string".into());
            }
            unique_terms.insert(term.clone());
        }
        if unique_terms.is_empty() {
            return Err("config.terms must contain at least one string".into());
        }

        let replacement = string_field(config, "replacement")
            .unwrap_or(DEFAULT_REPLACEMENT)
            .to_string();
        if mode == Mode::Deny && config.fields.contains_key("replacement") {
            return Err("config.replacement is only valid in redact mode".into());
        }

        Ok(Self {
            mode,
            terms: unique_terms.into_iter().collect(),
            replacement,
        })
    }
}

fn string_field<'a>(config: &'a Struct, name: &str) -> Option<&'a str> {
    config
        .fields
        .get(name)
        .and_then(|value| match value.kind.as_ref() {
            Some(Kind::StringValue(value)) => Some(value.as_str()),
            _ => None,
        })
}

#[derive(Debug, Default)]
struct ContentGuard;

#[tonic::async_trait]
impl SupervisorMiddleware for ContentGuard {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            api_version: API_VERSION.into(),
            name: "example/content-guard-service".into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: vec![MiddlewareBinding {
                id: BINDING_ID.into(),
                operation: OPERATION.into(),
                phase: PHASE.into(),
                max_body_bytes: MAX_BODY_BYTES,
            }],
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        let validation = validate_envelope(&request.api_version, &request.binding_id, None)
            .and_then(|()| GuardConfig::parse(request.config.as_ref()));
        Ok(Response::new(match validation {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(reason) => ValidateConfigResponse {
                valid: false,
                reason,
            },
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        validate_envelope(
            &request.api_version,
            &request.binding_id,
            Some(&request.phase),
        )
        .map_err(Status::invalid_argument)?;
        let config =
            GuardConfig::parse(request.config.as_ref()).map_err(Status::invalid_argument)?;
        let body = String::from_utf8(request.body)
            .map_err(|_| Status::invalid_argument("content guard requires a UTF-8 body"))?;
        Ok(Response::new(evaluate(&config, &body)))
    }
}

fn validate_envelope(
    api_version: &str,
    binding_id: &str,
    phase: Option<&str>,
) -> Result<(), String> {
    if api_version != API_VERSION {
        return Err(format!("unsupported api_version '{api_version}'"));
    }
    if binding_id != BINDING_ID {
        return Err(format!("unsupported binding_id '{binding_id}'"));
    }
    if let Some(phase) = phase
        && phase != PHASE
    {
        return Err(format!("unsupported phase '{phase}'"));
    }
    Ok(())
}

fn evaluate(config: &GuardConfig, body: &str) -> HttpRequestResult {
    let mut transformed = body.to_string();
    let mut match_count = 0_u32;
    let mut matched_term_count = 0_u32;
    for term in &config.terms {
        let count = u32::try_from(transformed.matches(term).count()).unwrap_or(u32::MAX);
        if count == 0 {
            continue;
        }
        match_count = match_count.saturating_add(count);
        matched_term_count = matched_term_count.saturating_add(1);
        if config.mode == Mode::Redact {
            transformed = transformed.replace(term, &config.replacement);
        }
    }

    if match_count == 0 {
        return allow_result();
    }

    let finding = Finding {
        r#type: "content_guard.match".into(),
        label: "configured content matched".into(),
        count: match_count,
        confidence: "high".into(),
        severity: "medium".into(),
    };
    let metadata = HashMap::from([
        ("match_count".into(), match_count.to_string()),
        ("matched_term_count".into(), matched_term_count.to_string()),
        (
            "mode".into(),
            match config.mode {
                Mode::Redact => "redact".into(),
                Mode::Deny => "deny".into(),
            },
        ),
    ]);

    match config.mode {
        Mode::Redact => HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body: transformed.into_bytes(),
            has_body: true,
            add_headers: HashMap::new(),
            findings: vec![finding],
            metadata,
        },
        Mode::Deny => HttpRequestResult {
            decision: Decision::Deny as i32,
            reason: "request body matched configured content".into(),
            body: Vec::new(),
            has_body: false,
            add_headers: HashMap::new(),
            findings: vec![finding],
            metadata,
        },
    }
}

fn allow_result() -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Allow as i32,
        reason: String::new(),
        body: Vec::new(),
        has_body: false,
        add_headers: HashMap::new(),
        findings: Vec::new(),
        metadata: HashMap::new(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    println!("serving {BINDING_ID} on http://{}", cli.bind);
    Server::builder()
        .add_service(SupervisorMiddlewareServer::new(ContentGuard))
        .serve(cli.bind)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::{ListValue, Value};
    use std::collections::BTreeMap;

    fn string(value: &str) -> Value {
        Value {
            kind: Some(Kind::StringValue(value.into())),
        }
    }

    fn config(mode: &str, terms: &[&str], replacement: Option<&str>) -> Struct {
        let mut fields = BTreeMap::from([
            ("mode".into(), string(mode)),
            (
                "terms".into(),
                Value {
                    kind: Some(Kind::ListValue(ListValue {
                        values: terms.iter().map(|term| string(term)).collect(),
                    })),
                },
            ),
        ]);
        if let Some(replacement) = replacement {
            fields.insert("replacement".into(), string(replacement));
        }
        Struct { fields }
    }

    #[test]
    fn redact_replaces_every_configured_match() {
        let config = GuardConfig::parse(Some(&config(
            "redact",
            &["prototype-secret", "internal-only"],
            Some("[FILTERED]"),
        )))
        .expect("valid config");
        let result = evaluate(
            &config,
            "prototype-secret then internal-only then prototype-secret",
        );

        assert_eq!(result.decision, Decision::Allow as i32);
        assert_eq!(
            String::from_utf8(result.body).unwrap(),
            "[FILTERED] then [FILTERED] then [FILTERED]"
        );
        assert!(result.has_body);
        assert_eq!(result.findings[0].count, 3);
    }

    #[test]
    fn deny_returns_a_generic_reason_without_echoing_the_term() {
        let config = GuardConfig::parse(Some(&config("deny", &["prototype-secret"], None)))
            .expect("valid config");
        let result = evaluate(&config, "contains prototype-secret");

        assert_eq!(result.decision, Decision::Deny as i32);
        assert!(!result.reason.contains("prototype-secret"));
        assert!(!result.has_body);
    }

    #[test]
    fn no_match_allows_without_replacing_the_body() {
        let config =
            GuardConfig::parse(Some(&config("redact", &["blocked"], None))).expect("valid config");
        let result = evaluate(&config, "safe content");

        assert_eq!(result.decision, Decision::Allow as i32);
        assert!(!result.has_body);
        assert!(result.body.is_empty());
    }

    #[test]
    fn validation_rejects_missing_terms_and_deny_replacement() {
        let missing_terms = Struct {
            fields: BTreeMap::from([("mode".into(), string("redact"))]),
        };
        assert!(GuardConfig::parse(Some(&missing_terms)).is_err());
        assert!(
            GuardConfig::parse(Some(&config(
                "deny",
                &["prototype-secret"],
                Some("ignored")
            )))
            .is_err()
        );
    }
}
