// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stable workload-facing bridge for agent conversation middleware.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use openshell_core::proto::{
    AgentConversationEvaluation, AgentConversationTarget, ConversationMessageV1,
    ConversationRequestV1, Decision, RequestContext, SupervisorMiddlewarePhase,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{debug, warn};

pub const BRIDGE_ADDR: &str = "127.0.0.1:8193";
pub const BRIDGE_PATH: &str = "/v1/agent/conversation";
pub const BRIDGE_URL: &str = "http://127.0.0.1:8193/v1/agent/conversation";
pub const BRIDGE_URL_ENV: &str = "OPENSHELL_PI_CONVERSATION_URL";
pub const MIDDLEWARE_ENV: &str = "OPENSHELL_PI_CONVERSATION_MIDDLEWARE";
pub const PROVIDER_HOST_ENV: &str = "OPENSHELL_PI_CONVERSATION_PROVIDER_HOST";

const MAX_BRIDGE_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct BridgeConfig {
    pub middleware_name: String,
    pub sandbox_id: String,
    pub provider_host: String,
    pub middleware_config: prost_types::Struct,
}

#[derive(Clone)]
struct BridgeState {
    runner: openshell_supervisor_middleware::ChainRunner,
    config: Arc<BridgeConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeRequest {
    hook: String,
    harness_version: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    turn_id: String,
    model: String,
    messages: Vec<BridgeMessage>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct BridgeMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct BridgeResponse {
    model: String,
    messages: Vec<BridgeMessage>,
    attestation: String,
}

#[derive(Debug, Serialize)]
struct BridgeErrorResponse {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
}

pub fn spawn(
    listener: TcpListener,
    runner: openshell_supervisor_middleware::ChainRunner,
    config: BridgeConfig,
) -> tokio::task::JoinHandle<()> {
    let state = BridgeState {
        runner,
        config: Arc::new(config),
    };
    tokio::spawn(async move {
        let app = Router::new()
            .route(BRIDGE_PATH, post(evaluate))
            .layer(DefaultBodyLimit::max(MAX_BRIDGE_BODY_BYTES))
            .with_state(state);
        if let Err(error) = axum::serve(listener, app).await {
            warn!(%error, "Pi conversation bridge stopped");
        }
    })
}

async fn evaluate(State(state): State<BridgeState>, Json(input): Json<BridgeRequest>) -> Response {
    if !matches!(
        input.hook.as_str(),
        "input" | "before_agent_start" | "message_end" | "context"
    ) {
        return (
            StatusCode::BAD_REQUEST,
            Json(BridgeErrorResponse {
                error: "unsupported_hook",
                reason_code: None,
            }),
        )
            .into_response();
    }
    let evaluation = AgentConversationEvaluation {
        phase: SupervisorMiddlewarePhase::AgentContext as i32,
        context: Some(RequestContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            sandbox_id: state.config.sandbox_id.clone(),
            originating_process: None,
        }),
        config: Some(state.config.middleware_config.clone()),
        target: Some(AgentConversationTarget {
            harness: "pi".into(),
            harness_version: input.harness_version,
            hook: input.hook,
            schema_version: "v1".into(),
            scheme: "https".into(),
            host: state.config.provider_host.clone(),
            port: 443,
            path: "/v1/chat/completions".into(),
        }),
        conversation: Some(ConversationRequestV1 {
            model: input.model,
            messages: input
                .messages
                .into_iter()
                .map(|message| ConversationMessageV1 {
                    role: message.role,
                    content: message.content,
                })
                .collect(),
        }),
        middleware_name: state.config.middleware_name.clone(),
        session_id: input.session_id,
        turn_id: input.turn_id,
    };
    let result = match state.runner.evaluate_agent_conversation(evaluation).await {
        Ok(result) => result,
        Err(error) => {
            debug!(error = %error, "Pi conversation middleware evaluation failed");
            return (
                StatusCode::BAD_GATEWAY,
                Json(BridgeErrorResponse {
                    error: "middleware_unavailable",
                    reason_code: None,
                }),
            )
                .into_response();
        }
    };
    if Decision::try_from(result.decision).unwrap_or(Decision::Unspecified) != Decision::Allow {
        return (
            StatusCode::FORBIDDEN,
            Json(BridgeErrorResponse {
                error: "conversation_denied",
                reason_code: (!result.reason_code.is_empty()).then_some(result.reason_code),
            }),
        )
            .into_response();
    }
    let Some(conversation) = result.conversation else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(BridgeErrorResponse {
                error: "invalid_middleware_response",
                reason_code: None,
            }),
        )
            .into_response();
    };
    let Ok(attestation) = String::from_utf8(result.attestation) else {
        return (
            StatusCode::BAD_GATEWAY,
            Json(BridgeErrorResponse {
                error: "invalid_middleware_response",
                reason_code: None,
            }),
        )
            .into_response();
    };
    Json(BridgeResponse {
        model: conversation.model,
        messages: conversation
            .messages
            .into_iter()
            .map(|message| BridgeMessage {
                role: message.role,
                content: message.content,
            })
            .collect(),
        attestation,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_pi_conversation_middleware::PrototypeService;

    #[tokio::test]
    async fn local_http_bridge_proxies_to_agent_grpc_operation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = spawn(
            listener,
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(PrototypeService::new())),
            BridgeConfig {
                middleware_name: openshell_pi_conversation_middleware::SERVICE_NAME.into(),
                sandbox_id: "trusted-sandbox".into(),
                provider_host: "api.openai.com".into(),
                middleware_config: prost_types::Struct::default(),
            },
        );
        let response = reqwest::Client::new()
            .post(format!("http://{address}{BRIDGE_PATH}"))
            .json(&serde_json::json!({
                "hook": "context",
                "harness_version": "test",
                "session_id": "session-1",
                "turn_id": "turn-1",
                "model": "prototype-model",
                "messages": [
                    {"role": "system", "content": "sandbox assistant"},
                    {"role": "user", "content": "sandbox in a sandbox"}
                ]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response: serde_json::Value = response.json().await.unwrap();
        assert_eq!(response["messages"][0]["content"], "REDACTED assistant");
        assert_eq!(response["messages"][1]["content"], "REDACTED in a REDACTED");
        assert!(
            response["attestation"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        task.abort();
    }
}
