// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone reference middleware for the Pi conversation prototype.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use openshell_core::proto::{
    AgentConversationEvaluation, AgentConversationResult, ConversationMessageV1,
    ConversationRequestV1, Decision, Finding, HeaderMutation, HttpRequestEvaluation,
    HttpRequestResult, MiddlewareBinding, MiddlewareManifest, RemoveHeader,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, ValidateConfigRequest,
    ValidateConfigResponse, header_mutation,
};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tonic::{Request, Response, Status};

pub const SERVICE_NAME: &str = "operator/pi-conversation-prototype";
pub const ATTESTATION_HEADER: &str = "x-openshell-agent-attestation";

const CLAIMS_VERSION: &str = "pi-conversation-attestation/v1";
const CANONICALIZATION_VERSION: &str = "openai-chat-completions-conversation/v1";
const ATTESTATION_FORMAT: &str = "v1";
const KEY_ID: &str = "prototype-ed25519-2026-01";
const DEFAULT_TTL_SECONDS: u64 = 60;
const MAX_BODY_BYTES: u64 = 256 * 1024;
const MAX_ATTESTATION_BYTES: usize = 8 * 1024;

// Public deterministic prototype key. Production must use operator-controlled
// secret storage, separate signing/verifying material, and key-id rotation.
const PROTOTYPE_SIGNING_SEED: [u8; 32] = [
    0x70, 0x69, 0x2d, 0x63, 0x6f, 0x6e, 0x76, 0x65, 0x72, 0x73, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d,
    0x70, 0x72, 0x6f, 0x74, 0x6f, 0x74, 0x79, 0x70, 0x65, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x31,
];

#[derive(Clone)]
pub struct PrototypeService {
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl fmt::Debug for PrototypeService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PrototypeService").finish()
    }
}

impl Default for PrototypeService {
    fn default() -> Self {
        Self::new()
    }
}

impl PrototypeService {
    pub fn new() -> Self {
        Self {
            now: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |duration| duration.as_secs())
            }),
        }
    }

    #[cfg(test)]
    fn with_clock(now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        Self { now: Arc::new(now) }
    }

    fn now(&self) -> u64 {
        (self.now)()
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PrototypeConfig {
    policy_revision: String,
}

impl Default for PrototypeConfig {
    fn default() -> Self {
        Self {
            policy_revision: "prototype-v1".into(),
        }
    }
}

impl PrototypeConfig {
    fn from_struct(config: Option<&prost_types::Struct>) -> Result<Self, String> {
        let value = config.map_or_else(
            || serde_json::json!({}),
            openshell_core::proto_struct::struct_to_json_value,
        );
        let parsed: Self = serde_json::from_value(value).map_err(|error| error.to_string())?;
        if parsed.policy_revision.is_empty() {
            return Err("policy_revision cannot be empty".into());
        }
        Ok(parsed)
    }
}

#[derive(Debug, Serialize)]
struct CanonicalConversation<'a> {
    canonicalization_version: &'static str,
    model: &'a str,
    messages: Vec<CanonicalMessage<'a>>,
}

#[derive(Debug, Serialize)]
struct CanonicalMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationClaims {
    attestation_version: String,
    canonicalization_version: String,
    middleware_binding: String,
    key_id: String,
    sandbox_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    turn_id: String,
    scheme: String,
    host: String,
    port: u32,
    path: String,
    model: String,
    policy_revision: String,
    conversation_hash: String,
    issued_at: u64,
    expires_at: u64,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionsBody {
    model: String,
    messages: Vec<ChatMessageBody>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChatMessageBody {
    role: String,
    content: String,
}

fn conversation_json(conversation: &ConversationRequestV1) -> serde_json::Value {
    serde_json::json!({
        "model": conversation.model,
        "messages": conversation.messages.iter().map(|message| serde_json::json!({
            "role": message.role,
            "content": message.content,
        })).collect::<Vec<_>>(),
    })
}

fn redact_conversation(conversation: &mut ConversationRequestV1) -> u32 {
    let mut replacements = 0u32;
    for message in &mut conversation.messages {
        let count = message.content.matches("sandbox").count();
        replacements = replacements.saturating_add(u32::try_from(count).unwrap_or(u32::MAX));
        message.content = message.content.replace("sandbox", "REDACTED");
    }
    replacements
}

fn validate_conversation(conversation: &ConversationRequestV1) -> Result<(), &'static str> {
    if conversation.model.is_empty() || conversation.messages.is_empty() {
        return Err("model and messages must be non-empty");
    }
    if conversation.messages.iter().any(|message| {
        !matches!(
            message.role.as_str(),
            "system" | "developer" | "user" | "assistant"
        )
    }) {
        return Err("unsupported message role");
    }
    Ok(())
}

fn conversation_hash(conversation: &ConversationRequestV1) -> Result<String, String> {
    validate_conversation(conversation).map_err(str::to_owned)?;
    let canonical = CanonicalConversation {
        canonicalization_version: CANONICALIZATION_VERSION,
        model: &conversation.model,
        messages: conversation
            .messages
            .iter()
            .map(|message| CanonicalMessage {
                role: &message.role,
                content: &message.content,
            })
            .collect(),
    };
    let encoded = serde_json::to_vec(&canonical).map_err(|error| error.to_string())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(encoded)))
}

fn sign_claims(claims: &AttestationClaims) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(claims).map_err(|error| error.to_string())?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&PROTOTYPE_SIGNING_SEED)
        .map_err(|_| "invalid prototype signing key".to_string())?;
    let signature = key_pair.sign(&payload);
    let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(format!(
        "{ATTESTATION_FORMAT}.{}.{}",
        base64.encode(payload),
        base64.encode(signature.as_ref())
    )
    .into_bytes())
}

fn verify_attestation(value: &[u8]) -> Result<AttestationClaims, String> {
    if value.len() > MAX_ATTESTATION_BYTES {
        return Err("attestation exceeds capacity".into());
    }
    let value = std::str::from_utf8(value).map_err(|_| "attestation is not UTF-8")?;
    let mut parts = value.split('.');
    let (Some(format), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed attestation".into());
    };
    if format != ATTESTATION_FORMAT {
        return Err("unsupported attestation format".into());
    }
    let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = base64
        .decode(payload)
        .map_err(|_| "invalid payload encoding")?;
    let signature = base64
        .decode(signature)
        .map_err(|_| "invalid signature encoding")?;
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&PROTOTYPE_SIGNING_SEED)
        .map_err(|_| "invalid prototype signing key")?;
    UnparsedPublicKey::new(&ED25519, key_pair.public_key().as_ref())
        .verify(&payload, &signature)
        .map_err(|_| "signature verification failed")?;
    serde_json::from_slice(&payload).map_err(|error| error.to_string())
}

fn deny_http(reason_code: &str) -> HttpRequestResult {
    HttpRequestResult {
        decision: Decision::Deny as i32,
        reason_code: reason_code.into(),
        findings: vec![Finding {
            r#type: "pi_conversation.attestation_denied".into(),
            label: "Pi conversation attestation denied".into(),
            count: 1,
            confidence: "high".into(),
            severity: "high".into(),
        }],
        ..Default::default()
    }
}

fn deny_agent(reason_code: &str) -> AgentConversationResult {
    AgentConversationResult {
        decision: Decision::Deny as i32,
        reason_code: reason_code.into(),
        ..Default::default()
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for PrototypeService {
    async fn describe(
        &self,
        _request: Request<()>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: SERVICE_NAME.into(),
            service_version: env!("CARGO_PKG_VERSION").into(),
            bindings: ["input", "before_agent_start", "message_end", "context"]
                .into_iter()
                .map(|hook| MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::AgentConversation as i32,
                    phase: SupervisorMiddlewarePhase::AgentContext as i32,
                    max_body_bytes: MAX_BODY_BYTES,
                    harness: "pi".into(),
                    hook: hook.into(),
                    schema_version: "v1".into(),
                    ..Default::default()
                })
                .chain(std::iter::once(MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                    phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                    max_body_bytes: MAX_BODY_BYTES,
                    ..Default::default()
                }))
                .collect(),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let request = request.into_inner();
        Ok(Response::new(
            match PrototypeConfig::from_struct(request.config.as_ref()) {
                Ok(_) => ValidateConfigResponse {
                    valid: true,
                    reason: String::new(),
                },
                Err(reason) => ValidateConfigResponse {
                    valid: false,
                    reason,
                },
            },
        ))
    }

    async fn evaluate_agent_conversation(
        &self,
        request: Request<AgentConversationEvaluation>,
    ) -> Result<Response<AgentConversationResult>, Status> {
        let request = request.into_inner();
        let config = PrototypeConfig::from_struct(request.config.as_ref())
            .map_err(Status::invalid_argument)?;
        let Some(context) = request.context else {
            return Ok(Response::new(deny_agent("missing_request_context")));
        };
        let Some(target) = request.target else {
            return Ok(Response::new(deny_agent("missing_conversation_target")));
        };
        let Some(mut conversation) = request.conversation else {
            return Ok(Response::new(deny_agent("missing_conversation")));
        };
        if context.sandbox_id.is_empty()
            || request.phase != SupervisorMiddlewarePhase::AgentContext as i32
            || target.harness != "pi"
            || !matches!(
                target.hook.as_str(),
                "input" | "before_agent_start" | "message_end" | "context"
            )
            || target.schema_version != "v1"
            || target.scheme != "https"
            || target.host.is_empty()
            || target.port != 443
            || target.path != "/v1/chat/completions"
            || validate_conversation(&conversation).is_err()
        {
            return Ok(Response::new(deny_agent("unsupported_conversation_shape")));
        }

        let original = conversation_json(&conversation);
        let replacements = redact_conversation(&mut conversation);
        if replacements > 0 {
            let formatted = serde_json::to_string_pretty(&serde_json::json!({
                "hook": target.hook,
                "original": original,
                "replacement": conversation_json(&conversation),
            }))
            .map_err(|error| Status::internal(error.to_string()))?;
            tracing::info!(
                replacement_count = replacements,
                "Pi conversation mutation\n{formatted}"
            );
        }
        let issued_at = self.now();
        let claims = AttestationClaims {
            attestation_version: CLAIMS_VERSION.into(),
            canonicalization_version: CANONICALIZATION_VERSION.into(),
            middleware_binding: request.middleware_name,
            key_id: KEY_ID.into(),
            sandbox_id: context.sandbox_id,
            session_id: request.session_id,
            turn_id: request.turn_id,
            scheme: target.scheme,
            host: target.host,
            port: target.port,
            path: target.path,
            model: conversation.model.clone(),
            policy_revision: config.policy_revision,
            conversation_hash: conversation_hash(&conversation).map_err(Status::internal)?,
            issued_at,
            expires_at: issued_at.saturating_add(DEFAULT_TTL_SECONDS),
        };
        let attestation = sign_claims(&claims).map_err(Status::internal)?;
        let findings = (replacements > 0)
            .then(|| Finding {
                r#type: "pi_conversation.sandbox_replaced".into(),
                label: "Prototype word replacement".into(),
                count: replacements,
                confidence: "high".into(),
                severity: "low".into(),
            })
            .into_iter()
            .collect();
        Ok(Response::new(AgentConversationResult {
            decision: Decision::Allow as i32,
            conversation: Some(conversation),
            has_conversation: true,
            attestation,
            findings,
            metadata: HashMap::from([("replacement_count".into(), replacements.to_string())]),
            ..Default::default()
        }))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let request = request.into_inner();
        let config = PrototypeConfig::from_struct(request.config.as_ref())
            .map_err(Status::invalid_argument)?;
        let Some(context) = request.context.as_ref() else {
            return Ok(Response::new(deny_http("missing_request_context")));
        };
        let Some(target) = request.target.as_ref() else {
            return Ok(Response::new(deny_http("missing_request_target")));
        };
        if request.phase != SupervisorMiddlewarePhase::PreCredentials as i32
            || target.scheme != "https"
            || target.host.is_empty()
            || target.port != 443
            || target.method != "POST"
            || target.path != "/v1/chat/completions"
            || !target.query.is_empty()
        {
            return Ok(Response::new(deny_http("unsupported_request_target")));
        }
        if request.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case("content-encoding")
                && !header.value.eq_ignore_ascii_case("identity")
        }) {
            return Ok(Response::new(deny_http("unsupported_content_encoding")));
        }
        let attestations: Vec<&[u8]> = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(ATTESTATION_HEADER))
            .map(|header| header.value.as_bytes())
            .collect();
        let [attestation] = attestations.as_slice() else {
            return Ok(Response::new(deny_http(if attestations.is_empty() {
                "missing_attestation"
            } else {
                "duplicate_attestation"
            })));
        };
        let body: ChatCompletionsBody = match serde_json::from_slice(&request.body) {
            Ok(body) => body,
            Err(_) => return Ok(Response::new(deny_http("unsupported_request_shape"))),
        };
        let conversation = ConversationRequestV1 {
            model: body.model,
            messages: body
                .messages
                .into_iter()
                .map(|message| ConversationMessageV1 {
                    role: message.role,
                    content: message.content,
                })
                .collect(),
        };
        if validate_conversation(&conversation).is_err() {
            return Ok(Response::new(deny_http("unsupported_request_shape")));
        }
        let Ok(claims) = verify_attestation(attestation) else {
            return Ok(Response::new(deny_http("invalid_attestation")));
        };
        let now = self.now();
        if claims.issued_at > now || claims.expires_at <= now {
            return Ok(Response::new(deny_http("expired_attestation")));
        }
        let hash = conversation_hash(&conversation).map_err(Status::internal)?;
        if claims.attestation_version != CLAIMS_VERSION
            || claims.canonicalization_version != CANONICALIZATION_VERSION
            || claims.middleware_binding != request.middleware_name
            || claims.key_id != KEY_ID
            || claims.sandbox_id != context.sandbox_id
            || claims.scheme != target.scheme
            || claims.host != target.host
            || claims.port != target.port
            || claims.path != target.path
            || claims.model != conversation.model
            || claims.policy_revision != config.policy_revision
            || claims.conversation_hash != hash
        {
            return Ok(Response::new(deny_http("attestation_mismatch")));
        }
        Ok(Response::new(HttpRequestResult {
            decision: Decision::Allow as i32,
            body: request.body,
            header_mutations: vec![HeaderMutation {
                operation: Some(header_mutation::Operation::Remove(RemoveHeader {
                    name: ATTESTATION_HEADER.into(),
                })),
            }],
            metadata: HashMap::from([("attestation_version".into(), ATTESTATION_FORMAT.into())]),
            ..Default::default()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
    use openshell_core::proto::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
    use openshell_core::proto::{
        AgentConversationTarget, HttpHeader, HttpRequestTarget, RequestContext,
    };
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;

    const NOW: u64 = 1_800_000_000;
    const MIDDLEWARE_NAME: &str = "pi-prototype";

    fn context() -> RequestContext {
        RequestContext {
            request_id: "request-1".into(),
            sandbox_id: "sandbox-123".into(),
            originating_process: None,
        }
    }

    fn agent_evaluation() -> AgentConversationEvaluation {
        AgentConversationEvaluation {
            phase: SupervisorMiddlewarePhase::AgentContext as i32,
            context: Some(context()),
            config: Some(prost_types::Struct::default()),
            target: Some(AgentConversationTarget {
                harness: "pi".into(),
                harness_version: "prototype".into(),
                hook: "context".into(),
                schema_version: "v1".into(),
                scheme: "https".into(),
                host: "api.openai.com".into(),
                port: 443,
                path: "/v1/chat/completions".into(),
            }),
            conversation: Some(ConversationRequestV1 {
                model: "prototype-model".into(),
                messages: vec![
                    ConversationMessageV1 {
                        role: "system".into(),
                        content: "You are a sandbox assistant.".into(),
                    },
                    ConversationMessageV1 {
                        role: "user".into(),
                        content: "Create a sandbox inside another sandbox.".into(),
                    },
                ],
            }),
            middleware_name: MIDDLEWARE_NAME.into(),
            session_id: "session-1".into(),
            turn_id: "turn-1".into(),
        }
    }

    fn http_evaluation(body: Vec<u8>, attestation: Option<&[u8]>) -> HttpRequestEvaluation {
        let mut headers = vec![HttpHeader {
            name: "content-type".into(),
            value: "application/json".into(),
        }];
        if let Some(attestation) = attestation {
            headers.push(HttpHeader {
                name: ATTESTATION_HEADER.into(),
                value: String::from_utf8(attestation.to_vec()).unwrap(),
            });
        }
        HttpRequestEvaluation {
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: Some(context()),
            config: Some(prost_types::Struct::default()),
            target: Some(HttpRequestTarget {
                scheme: "https".into(),
                host: "api.openai.com".into(),
                port: 443,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                query: String::new(),
            }),
            headers,
            body,
            middleware_name: MIDDLEWARE_NAME.into(),
        }
    }

    async fn grpc_client(
        now: u64,
    ) -> (
        SupervisorMiddlewareClient<tonic::transport::Channel>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            Server::builder()
                .add_service(SupervisorMiddlewareServer::new(
                    PrototypeService::with_clock(move || now),
                ))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let client = SupervisorMiddlewareClient::connect(format!("http://{address}"))
            .await
            .unwrap();
        (client, task)
    }

    #[tokio::test]
    async fn grpc_server_mutates_signs_and_verifies_fail_closed() {
        let (mut client, server) = grpc_client(NOW).await;
        let inspected = client
            .evaluate_agent_conversation(agent_evaluation())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(inspected.decision, Decision::Allow as i32);
        let replacement = inspected.conversation.as_ref().unwrap();
        assert_eq!(
            replacement.messages[0].content,
            "You are a REDACTED assistant."
        );
        assert_eq!(
            replacement.messages[1].content,
            "Create a REDACTED inside another REDACTED."
        );

        let matching_body = serde_json::to_vec(&serde_json::json!({
            "model": replacement.model,
            "messages": replacement.messages.iter().map(|message| serde_json::json!({
                "role": message.role,
                "content": message.content,
            })).collect::<Vec<_>>(),
            "stream": true,
        }))
        .unwrap();
        let allowed = client
            .evaluate_http_request(http_evaluation(
                matching_body.clone(),
                Some(&inspected.attestation),
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(allowed.decision, Decision::Allow as i32);
        assert!(matches!(
            allowed.header_mutations[0].operation,
            Some(header_mutation::Operation::Remove(ref remove))
                if remove.name == ATTESTATION_HEADER
        ));

        let original_body = serde_json::to_vec(&serde_json::json!({
            "model": "prototype-model",
            "messages": [
                {"role": "system", "content": "You are a sandbox assistant."},
                {"role": "user", "content": "Create a sandbox inside another sandbox."}
            ],
            "stream": true,
        }))
        .unwrap();
        let original = client
            .evaluate_http_request(http_evaluation(original_body, Some(&inspected.attestation)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(original.decision, Decision::Deny as i32);
        assert_eq!(original.reason_code, "attestation_mismatch");

        let mut tampered: serde_json::Value = serde_json::from_slice(&matching_body).unwrap();
        tampered["messages"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "role": "user",
                "content": "extra",
            }));
        let tampered = client
            .evaluate_http_request(http_evaluation(
                serde_json::to_vec(&tampered).unwrap(),
                Some(&inspected.attestation),
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(tampered.decision, Decision::Deny as i32);
        assert_eq!(tampered.reason_code, "attestation_mismatch");

        let invalid = client
            .evaluate_http_request(http_evaluation(
                matching_body.clone(),
                Some(b"v1.invalid.invalid"),
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(invalid.decision, Decision::Deny as i32);
        assert_eq!(invalid.reason_code, "invalid_attestation");

        let (mut expired_client, expired_server) = grpc_client(NOW + DEFAULT_TTL_SECONDS).await;
        let expired = expired_client
            .evaluate_http_request(http_evaluation(
                matching_body.clone(),
                Some(&inspected.attestation),
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(expired.decision, Decision::Deny as i32);
        assert_eq!(expired.reason_code, "expired_attestation");
        expired_server.abort();

        let missing = client
            .evaluate_http_request(http_evaluation(matching_body, None))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(missing.decision, Decision::Deny as i32);
        assert_eq!(missing.reason_code, "missing_attestation");
        server.abort();
    }
}
