// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use navigator_router::Router;
use navigator_router::config::{ResolvedRoute, RouteConfig, RouterConfig};
use wiremock::matchers::{bearer_token, body_partial_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn mock_candidates(base_url: &str) -> Vec<ResolvedRoute> {
    vec![ResolvedRoute {
        routing_hint: "local".to_string(),
        endpoint: base_url.to_string(),
        model: "meta/llama-3.1-8b-instruct".to_string(),
        api_key: "test-api-key".to_string(),
        protocols: vec!["openai_chat_completions".to_string()],
    }]
}

#[tokio::test]
async fn proxy_forwards_request_to_backend() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "created": 1_700_000_000_i64,
        "model": "meta/llama-3.1-8b-instruct",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello! How can I help you?"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18
        }
    });

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(bearer_token("test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = mock_candidates(&mock_server.uri());

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "test",
        "messages": [{"role": "user", "content": "Hello"}]
    }))
    .unwrap();

    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["id"], "chatcmpl-123");
}

#[tokio::test]
async fn proxy_upstream_401_returns_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "Invalid API key" }
        })))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = mock_candidates(&mock_server.uri());

    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![],
            bytes::Bytes::new(),
            &candidates,
        )
        .await
        .unwrap();

    // Raw proxy returns the actual HTTP status, not a RouterError
    assert_eq!(response.status, 401);
}

#[tokio::test]
async fn proxy_no_compatible_route_returns_error() {
    let router = Router::new().unwrap();
    let candidates = vec![ResolvedRoute {
        routing_hint: "local".to_string(),
        endpoint: "http://localhost:1234".to_string(),
        model: "test".to_string(),
        api_key: "key".to_string(),
        protocols: vec!["anthropic_messages".to_string()],
    }];

    let err = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![],
            bytes::Bytes::new(),
            &candidates,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, navigator_router::RouterError::NoCompatibleRoute(_)),
        "expected NoCompatibleRoute, got: {err:?}"
    );
}

#[tokio::test]
async fn proxy_strips_auth_header() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(bearer_token("test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = mock_candidates(&mock_server.uri());

    // Client sends its own Authorization header — should be stripped and replaced
    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("authorization".to_string(), "Bearer client-key".to_string())],
            bytes::Bytes::new(),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn proxy_mock_route_returns_canned_response() {
    let router = Router::new().unwrap();
    let candidates = vec![ResolvedRoute {
        routing_hint: "local".to_string(),
        endpoint: "mock://test".to_string(),
        model: "mock/test-model".to_string(),
        api_key: "unused".to_string(),
        protocols: vec!["openai_chat_completions".to_string()],
    }];

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hello"}]
    }))
    .unwrap();

    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["model"], "mock/test-model");
    assert_eq!(
        resp_body["choices"][0]["message"]["content"],
        "Hello from navigator mock backend"
    );
}

#[tokio::test]
async fn proxy_overrides_model_in_request_body() {
    let mock_server = MockServer::start().await;

    // The mock expects the route's model, NOT the client's original model
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(serde_json::json!({
            "model": "meta/llama-3.1-8b-instruct"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = mock_candidates(&mock_server.uri());

    // Client sends "gpt-4o-mini" but route is configured with "meta/llama-3.1-8b-instruct"
    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": "Hello"}]
    }))
    .unwrap();

    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn proxy_inserts_model_when_absent_from_body() {
    let mock_server = MockServer::start().await;

    // The mock expects the route's model to be inserted even though the client didn't send one
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(body_partial_json(serde_json::json!({
            "model": "meta/llama-3.1-8b-instruct"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = mock_candidates(&mock_server.uri());

    // Client omits "model" entirely
    let body = serde_json::to_vec(&serde_json::json!({
        "messages": [{"role": "user", "content": "Hello"}]
    }))
    .unwrap();

    let response = router
        .proxy_with_candidates(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
}

#[tokio::test]
async fn proxy_uses_x_api_key_for_anthropic_protocol() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-anthropic-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        })))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = vec![ResolvedRoute {
        routing_hint: "frontier".to_string(),
        endpoint: mock_server.uri(),
        model: "claude-sonnet-4-20250514".to_string(),
        api_key: "test-anthropic-key".to_string(),
        protocols: vec!["anthropic_messages".to_string()],
    }];

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "hi"}]
    }))
    .unwrap();

    let response = router
        .proxy_with_candidates(
            "anthropic_messages",
            "POST",
            "/v1/messages",
            vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("anthropic-version".to_string(), "2023-06-01".to_string()),
            ],
            bytes::Bytes::from(body),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["type"], "message");
}

#[tokio::test]
async fn proxy_anthropic_does_not_send_bearer_auth() {
    let mock_server = MockServer::start().await;

    // This mock rejects requests that have a Bearer token — ensuring we DON'T send one
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "anthropic-key"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&mock_server)
        .await;

    // Also mount a catch-all that returns 401 if Bearer is used
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(bearer_token("anthropic-key"))
        .respond_with(ResponseTemplate::new(401).set_body_string("should not use bearer"))
        .mount(&mock_server)
        .await;

    let router = Router::new().unwrap();
    let candidates = vec![ResolvedRoute {
        routing_hint: "frontier".to_string(),
        endpoint: mock_server.uri(),
        model: "claude-sonnet-4-20250514".to_string(),
        api_key: "anthropic-key".to_string(),
        protocols: vec!["anthropic_messages".to_string()],
    }];

    let response = router
        .proxy_with_candidates(
            "anthropic_messages",
            "POST",
            "/v1/messages",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(b"{}".to_vec()),
            &candidates,
        )
        .await
        .unwrap();

    assert_eq!(response.status, 200);
}

#[test]
fn config_resolves_routes_with_protocol() {
    let config = RouterConfig {
        routes: vec![RouteConfig {
            routing_hint: "local".to_string(),
            endpoint: "http://localhost:8000".to_string(),
            model: "test-model".to_string(),
            protocols: vec!["openai_chat_completions".to_string()],
            api_key: Some("key".to_string()),
            api_key_env: None,
        }],
    };
    let routes = config.resolve_routes().unwrap();
    assert_eq!(routes[0].protocols, vec!["openai_chat_completions"]);
}
