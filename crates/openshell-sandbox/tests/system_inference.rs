// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration test for the in-process system inference API.
//!
//! Uses the router's built-in `mock://` route support to verify the full
//! in-process path: route selection → `proxy_with_candidates()` →
//! mock backend → response.

use openshell_router::Router;
use openshell_router::config::{AuthHeader, ResolvedRoute};
use openshell_sandbox::proxy::InferenceContext;

fn make_system_route() -> ResolvedRoute {
    ResolvedRoute {
        name: "sandbox-system".to_string(),
        endpoint: "mock://system-test".to_string(),
        model: "system/policy-analyzer".to_string(),
        api_key: "system-key".to_string(),
        protocols: vec!["openai_chat_completions".to_string()],
        auth: AuthHeader::Bearer,
        default_headers: Vec::new(),
        passthrough_headers: Vec::new(),
        timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
    }
}

fn make_user_route() -> ResolvedRoute {
    ResolvedRoute {
        name: "inference.local".to_string(),
        endpoint: "mock://user-test".to_string(),
        model: "user/gpt-4o".to_string(),
        api_key: "user-key".to_string(),
        protocols: vec!["openai_chat_completions".to_string()],
        auth: AuthHeader::Bearer,
        default_headers: Vec::new(),
        passthrough_headers: Vec::new(),
        timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
    }
}

#[tokio::test]
async fn system_inference_routes_to_mock_backend() {
    let router = Router::new().unwrap();
    let patterns = openshell_sandbox::l7::inference::default_patterns();

    let ctx = InferenceContext::new(
        patterns,
        router,
        vec![make_user_route()],
        vec![make_system_route()],
    );

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "anything",
        "messages": [{"role": "user", "content": "analyze this policy"}]
    }))
    .unwrap();

    let response = ctx
        .system_inference(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
        )
        .await
        .expect("system_inference should succeed");

    assert_eq!(response.status, 200);

    // Verify the mock response came back with the system model
    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["model"], "system/policy-analyzer");

    // Verify the mock header is present
    assert!(
        response
            .headers
            .iter()
            .any(|(k, v)| k == "x-openshell-mock" && v == "true")
    );
}

#[tokio::test]
async fn system_inference_uses_system_routes_not_user_routes() {
    let router = Router::new().unwrap();
    let patterns = openshell_sandbox::l7::inference::default_patterns();

    // Only user routes configured — no system routes
    let ctx = InferenceContext::new(patterns, router, vec![make_user_route()], vec![]);

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hello"}]
    }))
    .unwrap();

    let result = ctx
        .system_inference(
            "openai_chat_completions",
            "POST",
            "/v1/chat/completions",
            vec![],
            bytes::Bytes::from(body),
        )
        .await;

    // Should fail because the system route cache is empty — user routes
    // are not accessible through system_inference().
    assert!(
        result.is_err(),
        "system_inference should fail when no system routes are configured"
    );
}

#[tokio::test]
async fn system_inference_with_anthropic_protocol() {
    let router = Router::new().unwrap();
    let patterns = openshell_sandbox::l7::inference::default_patterns();

    let system_route = ResolvedRoute {
        name: "sandbox-system".to_string(),
        endpoint: "mock://anthropic-system".to_string(),
        model: "claude-sonnet-4-20250514".to_string(),
        api_key: "ant-key".to_string(),
        protocols: vec!["anthropic_messages".to_string()],
        auth: AuthHeader::Custom("x-api-key"),
        default_headers: vec![("anthropic-version".to_string(), "2023-06-01".to_string())],
        passthrough_headers: vec![
            "anthropic-version".to_string(),
            "anthropic-beta".to_string(),
        ],
        timeout: openshell_router::config::DEFAULT_ROUTE_TIMEOUT,
    };

    let ctx = InferenceContext::new(patterns, router, vec![], vec![system_route]);

    let body = serde_json::to_vec(&serde_json::json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "analyze policy"}]
    }))
    .unwrap();

    let response = ctx
        .system_inference(
            "anthropic_messages",
            "POST",
            "/v1/messages",
            vec![("content-type".to_string(), "application/json".to_string())],
            bytes::Bytes::from(body),
        )
        .await
        .expect("anthropic system_inference should succeed");

    assert_eq!(response.status, 200);
    let resp_body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(resp_body["type"], "message");
}
