use navigator_core::proto::{ChatMessage, CompletionRequest};
use navigator_router::Router;
use navigator_router::config::{RouteConfig, RouterConfig};
use wiremock::matchers::{bearer_token, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_request(routing_hint: &str) -> CompletionRequest {
    CompletionRequest {
        routing_hint: routing_hint.to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: "Hello".to_string(),
            reasoning_content: None,
        }],
        temperature: Some(0.7),
        max_tokens: Some(100),
        top_p: None,
    }
}

#[tokio::test]
async fn completion_handles_null_content_with_reasoning_content() {
    let mock_server = MockServer::start().await;

    let response_body = serde_json::json!({
        "id": "chatcmpl-456",
        "object": "chat.completion",
        "created": 1_700_000_123_i64,
        "model": "nvidia/nemotron-3-nano-30b-a3b",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "reasoning_content": "model thinking"
            },
            "finish_reason": "length"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18
        }
    });

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(bearer_token("test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let config = mock_config(&mock_server.uri());
    let router = Router::from_config(&config).unwrap();
    let response = router.completion(&make_request("local")).await.unwrap();

    let message = response.choices[0].message.as_ref().unwrap();
    assert_eq!(message.content, "");
    assert_eq!(message.reasoning_content.as_deref(), Some("model thinking"));
}

fn mock_config(base_url: &str) -> RouterConfig {
    RouterConfig {
        routes: vec![
            RouteConfig {
                routing_hint: "local".to_string(),
                endpoint: base_url.to_string(),
                model: "meta/llama-3.1-8b-instruct".to_string(),
                api_key: Some("test-api-key".to_string()),
                api_key_env: None,
            },
            RouteConfig {
                routing_hint: "frontier".to_string(),
                endpoint: base_url.to_string(),
                model: "meta/llama-3.1-70b-instruct".to_string(),
                api_key: Some("test-api-key".to_string()),
                api_key_env: None,
            },
        ],
    }
}

#[tokio::test]
async fn completion_success_roundtrip() {
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
        .and(path("/chat/completions"))
        .and(bearer_token("test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
        .mount(&mock_server)
        .await;

    let config = mock_config(&mock_server.uri());
    let router = Router::from_config(&config).unwrap();
    let response = router.completion(&make_request("local")).await.unwrap();

    assert_eq!(response.id, "chatcmpl-123");
    assert_eq!(response.model, "meta/llama-3.1-8b-instruct");
    assert_eq!(response.choices.len(), 1);
    assert_eq!(
        response.choices[0].message.as_ref().unwrap().content,
        "Hello! How can I help you?"
    );
    assert_eq!(response.choices[0].finish_reason, "stop");

    let usage = response.usage.unwrap();
    assert_eq!(usage.prompt_tokens, 10);
    assert_eq!(usage.completion_tokens, 8);
    assert_eq!(usage.total_tokens, 18);
}

#[tokio::test]
async fn completion_upstream_401_returns_unauthorized() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": { "message": "Invalid API key" }
        })))
        .mount(&mock_server)
        .await;

    let config = mock_config(&mock_server.uri());
    let router = Router::from_config(&config).unwrap();
    let err = router.completion(&make_request("local")).await.unwrap_err();

    assert!(
        matches!(err, navigator_router::RouterError::Unauthorized(_)),
        "expected Unauthorized, got: {err:?}"
    );
}

#[tokio::test]
async fn completion_upstream_500_returns_unavailable() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let config = mock_config(&mock_server.uri());
    let router = Router::from_config(&config).unwrap();
    let err = router.completion(&make_request("local")).await.unwrap_err();

    assert!(
        matches!(err, navigator_router::RouterError::UpstreamUnavailable(_)),
        "expected UpstreamUnavailable, got: {err:?}"
    );
}
