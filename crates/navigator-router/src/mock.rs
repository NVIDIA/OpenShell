// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::backend::ProxyResponse;
use crate::config::ResolvedRoute;

const MOCK_SCHEME: &str = "mock://";

/// Returns true if the route's endpoint uses the `mock://` scheme,
/// indicating the router should return a canned response.
pub fn is_mock_route(route: &ResolvedRoute) -> bool {
    route.endpoint.starts_with(MOCK_SCHEME)
}

/// Generate a canned HTTP response appropriate for the route's protocol.
///
/// The response is protocol-aware: for `openai_chat_completions` it returns
/// a valid `OpenAI` chat completion JSON, for `anthropic_messages` a valid
/// Anthropic response, etc. The route's `model` field is echoed in the response.
pub fn mock_response(route: &ResolvedRoute, source_protocol: &str) -> ProxyResponse {
    tracing::warn!(
        routing_hint = %route.routing_hint,
        endpoint = %route.endpoint,
        "Serving mock response — mock:// routes should only be used in development/testing"
    );

    let protocol = if route.protocols.iter().any(|p| p == source_protocol) {
        source_protocol
    } else {
        route.protocols.first().map_or("", String::as_str)
    };

    let body = match protocol {
        "openai_chat_completions" => openai_chat_completion_body(&route.model),
        "openai_completions" => openai_completion_body(&route.model),
        "anthropic_messages" => anthropic_messages_body(&route.model),
        _ => generic_body(&route.model),
    };

    let body_bytes = bytes::Bytes::from(body);
    ProxyResponse {
        status: 200,
        headers: vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-navigator-mock".to_string(), "true".to_string()),
        ],
        body: body_bytes,
    }
}

fn openai_chat_completion_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "mock-chatcmpl-001",
        "object": "chat.completion",
        "created": 1_700_000_000_i64,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello from navigator mock backend"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 5,
            "total_tokens": 6
        }
    }))
    .expect("static JSON must serialize")
}

fn openai_completion_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "mock-cmpl-001",
        "object": "text_completion",
        "created": 1_700_000_000_i64,
        "model": model,
        "choices": [{
            "index": 0,
            "text": "Hello from navigator mock backend",
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 5,
            "total_tokens": 6
        }
    }))
    .expect("static JSON must serialize")
}

fn anthropic_messages_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "id": "mock-msg-001",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{
            "type": "text",
            "text": "Hello from navigator mock backend"
        }],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": 1,
            "output_tokens": 5
        }
    }))
    .expect("static JSON must serialize")
}

fn generic_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "mock": true,
        "model": model,
        "message": "Hello from navigator mock backend"
    }))
    .expect("static JSON must serialize")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_route(endpoint: &str, protocols: &[&str], model: &str) -> ResolvedRoute {
        ResolvedRoute {
            routing_hint: "test".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: "key".to_string(),
            protocols: protocols.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn is_mock_route_detects_mock_scheme() {
        assert!(is_mock_route(&make_route(
            "mock://test",
            &["openai_chat_completions"],
            "m"
        )));
        assert!(is_mock_route(&make_route(
            "mock://",
            &["openai_chat_completions"],
            "m"
        )));
    }

    #[test]
    fn is_mock_route_rejects_real_urls() {
        assert!(!is_mock_route(&make_route(
            "https://api.openai.com",
            &["openai_chat_completions"],
            "m"
        )));
        assert!(!is_mock_route(&make_route(
            "http://localhost:8000",
            &["openai_chat_completions"],
            "m"
        )));
    }

    #[test]
    fn mock_openai_chat_completion() {
        let route = make_route("mock://test", &["openai_chat_completions"], "gpt-4");
        let resp = mock_response(&route, "openai_chat_completions");
        assert_eq!(resp.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["model"], "gpt-4");
        assert_eq!(body["object"], "chat.completion");
        assert_eq!(
            body["choices"][0]["message"]["content"],
            "Hello from navigator mock backend"
        );
    }

    #[test]
    fn mock_anthropic_messages() {
        let route = make_route("mock://test", &["anthropic_messages"], "claude-3");
        let resp = mock_response(&route, "anthropic_messages");
        assert_eq!(resp.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["model"], "claude-3");
        assert_eq!(body["type"], "message");
        assert_eq!(
            body["content"][0]["text"],
            "Hello from navigator mock backend"
        );
    }

    #[test]
    fn mock_generic_protocol() {
        let route = make_route("mock://test", &["unknown_protocol"], "some-model");
        let resp = mock_response(&route, "unknown_protocol");
        assert_eq!(resp.status, 200);

        let body: serde_json::Value = serde_json::from_slice(&resp.body).unwrap();
        assert_eq!(body["mock"], true);
        assert_eq!(body["model"], "some-model");
    }

    #[test]
    fn mock_response_includes_marker_header() {
        let route = make_route("mock://test", &["openai_chat_completions"], "m");
        let resp = mock_response(&route, "openai_chat_completions");
        assert!(
            resp.headers
                .iter()
                .any(|(k, v)| k == "x-navigator-mock" && v == "true")
        );
    }
}
