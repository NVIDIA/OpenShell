use serde::{Deserialize, Serialize};

use crate::RouterError;
use crate::config::ResolvedRoute;

#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessageRequestBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessageRequestBody {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatMessageResponseBody {
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    id: String,
    model: String,
    created: i64,
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    index: i32,
    message: ChatMessageResponseBody,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
struct ChatUsage {
    prompt_tokens: i32,
    completion_tokens: i32,
    total_tokens: i32,
}

#[derive(Debug, Deserialize)]
struct ApiErrorResponse {
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

use navigator_core::proto::{
    ChatMessage, CompletionChoice, CompletionRequest, CompletionResponse, CompletionUsage,
};

pub async fn call_backend(
    client: &reqwest::Client,
    route: &ResolvedRoute,
    request: &CompletionRequest,
) -> Result<CompletionResponse, RouterError> {
    let messages: Vec<ChatMessageRequestBody> = request
        .messages
        .iter()
        .map(|m| ChatMessageRequestBody {
            role: m.role.clone(),
            content: m.content.clone(),
        })
        .collect();

    let body = ChatCompletionRequest {
        model: route.model.clone(),
        messages,
        temperature: request.temperature,
        max_tokens: request.max_tokens,
        top_p: request.top_p,
    };

    let url = format!("{}/chat/completions", route.endpoint.trim_end_matches('/'));

    let response = client
        .post(&url)
        .bearer_auth(&route.api_key)
        .json(&body)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                RouterError::UpstreamUnavailable(format!("request to {url} timed out"))
            } else if e.is_connect() {
                RouterError::UpstreamUnavailable(format!("failed to connect to {url}: {e}"))
            } else {
                RouterError::Internal(format!("HTTP request failed: {e}"))
            }
        })?;

    let status = response.status();
    if !status.is_success() {
        let body_text = response.text().await.unwrap_or_default();
        let error_msg = serde_json::from_str::<ApiErrorResponse>(&body_text)
            .ok()
            .and_then(|e| e.error)
            .map_or_else(|| body_text.clone(), |e| e.message);

        return Err(match status.as_u16() {
            401 | 403 => RouterError::Unauthorized(error_msg),
            429 | 500..=599 => RouterError::UpstreamUnavailable(error_msg),
            _ => RouterError::UpstreamProtocol(format!("HTTP {status}: {error_msg}")),
        });
    }

    let chat_response: ChatCompletionResponse = response.json().await.map_err(|e| {
        RouterError::UpstreamProtocol(format!("failed to parse upstream response: {e}"))
    })?;

    let choices = chat_response
        .choices
        .into_iter()
        .map(|c| CompletionChoice {
            index: c.index,
            message: Some(ChatMessage {
                role: c.message.role,
                content: c.message.content.unwrap_or_default(),
                reasoning_content: c.message.reasoning_content,
            }),
            finish_reason: c.finish_reason.unwrap_or_default(),
        })
        .collect();

    let usage = chat_response.usage.map_or_else(
        || CompletionUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
        |u| CompletionUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
        },
    );

    Ok(CompletionResponse {
        id: chat_response.id,
        model: chat_response.model,
        created: chat_response.created,
        choices,
        usage: Some(usage),
    })
}
