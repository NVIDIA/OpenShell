//! `OpenAI` chat completions protocol translation and SSE streaming.

use futures::StreamExt;
use navigator_core::proto::{
    ChatMessage, ChatStreamEvent, ChatStreamRequest, ContentDelta, SandboxResolvedRoute, Tool,
    ToolCall, chat_stream_event::Event,
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tonic::Status;
use tracing::debug;

/// Translate proto messages to `OpenAI` JSON message format.
fn translate_messages(messages: &[ChatMessage]) -> Vec<Value> {
    messages
        .iter()
        .map(|m| {
            let mut msg = json!({
                "role": m.role,
            });

            match m.role.as_str() {
                "assistant" if !m.tool_calls.is_empty() => {
                    // Assistant message with tool calls — may have empty content.
                    if m.content.is_empty() {
                        msg["content"] = Value::Null;
                    } else {
                        msg["content"] = json!(m.content);
                    }
                    msg["tool_calls"] = json!(
                        m.tool_calls
                            .iter()
                            .map(|tc| {
                                json!({
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {
                                        "name": tc.name,
                                        "arguments": tc.arguments,
                                    }
                                })
                            })
                            .collect::<Vec<_>>()
                    );
                }
                "tool" => {
                    msg["content"] = json!(m.content);
                    msg["tool_call_id"] = json!(m.tool_call_id);
                }
                _ => {
                    msg["content"] = json!(m.content);
                }
            }

            msg
        })
        .collect()
}

/// Translate proto Tool definitions to `OpenAI` tool format.
fn translate_tools(tools: &[Tool]) -> Vec<Value> {
    tools
        .iter()
        .map(|t| {
            let parameters: Value =
                serde_json::from_str(&t.parameters_schema).unwrap_or_else(|_| json!({}));
            json!({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": parameters,
                }
            })
        })
        .collect()
}

/// Build the `OpenAI` request body.
fn build_request_body(request: &ChatStreamRequest, model: &str) -> Value {
    let mut body = json!({
        "model": model,
        "messages": translate_messages(&request.messages),
        "stream": true,
    });

    if !request.tools.is_empty() {
        body["tools"] = json!(translate_tools(&request.tools));
    }

    body
}

/// Stream a chat completion from an OpenAI-compatible backend.
pub async fn stream_chat(
    client: &reqwest::Client,
    route: &SandboxResolvedRoute,
    request: &ChatStreamRequest,
    tx: &mpsc::Sender<Result<ChatStreamEvent, Status>>,
) -> Result<(), Status> {
    let base = route.base_url.trim_end_matches('/');
    let url = format!("{base}/v1/chat/completions");
    let body = build_request_body(request, &route.model_id);

    debug!(url = %url, "sending OpenAI chat request");

    let response = client
        .post(&url)
        .bearer_auth(&route.api_key)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .json(&body)
        .send()
        .await
        .map_err(|e| Status::unavailable(format!("failed to connect to LLM backend: {e}")))?;

    let status = response.status();
    if !status.is_success() {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "failed to read error body".to_string());
        return Err(Status::internal(format!(
            "LLM backend returned {status}: {error_body}"
        )));
    }

    // Parse SSE stream and accumulate the full response.
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCallAccumulator> = Vec::new();
    let mut stream = response.bytes_stream();

    let mut buffer = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Status::internal(format!("stream read error: {e}")))?;
        let text = String::from_utf8_lossy(&chunk);
        buffer.push_str(&text);

        // Process complete SSE lines from the buffer.
        while let Some(line_end) = buffer.find('\n') {
            let line = buffer[..line_end].trim_end_matches('\r').to_string();
            buffer = buffer[line_end + 1..].to_string();

            if line.is_empty() || line.starts_with(':') {
                continue;
            }

            if let Some(data) = line.strip_prefix("data: ") {
                if data.trim() == "[DONE]" {
                    break;
                }

                let parsed: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                if let Some(choices) = parsed.get("choices").and_then(|c| c.as_array()) {
                    for choice in choices {
                        let Some(delta) = choice.get("delta") else {
                            continue;
                        };

                        // Content delta.
                        if let Some(text) = delta
                            .get("content")
                            .and_then(|c| c.as_str())
                            .filter(|t| !t.is_empty())
                        {
                            content.push_str(text);
                            let _ = tx
                                .send(Ok(ChatStreamEvent {
                                    event: Some(Event::ContentDelta(ContentDelta {
                                        text: text.to_string(),
                                    })),
                                }))
                                .await;
                        }

                        // Tool call deltas (streamed incrementally).
                        if let Some(tcs) = delta.get("tool_calls").and_then(|tc| tc.as_array()) {
                            for tc_delta in tcs {
                                let index =
                                    tc_delta.get("index").and_then(Value::as_u64).unwrap_or(0);
                                let index = usize::try_from(index).unwrap_or(0);

                                // Grow the accumulator vec as needed.
                                while tool_calls.len() <= index {
                                    tool_calls.push(ToolCallAccumulator::default());
                                }

                                let acc = &mut tool_calls[index];

                                if let Some(id) = tc_delta.get("id").and_then(|v| v.as_str()) {
                                    acc.id = id.to_string();
                                }

                                if let Some(func) = tc_delta.get("function") {
                                    if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                                        acc.name = name.to_string();
                                    }
                                    if let Some(args) =
                                        func.get("arguments").and_then(|a| a.as_str())
                                    {
                                        acc.arguments.push_str(args);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Send the final complete message.
    let final_tool_calls: Vec<ToolCall> = tool_calls
        .into_iter()
        .map(|acc| ToolCall {
            id: acc.id,
            name: acc.name,
            arguments: acc.arguments,
        })
        .collect();

    let final_message = ChatMessage {
        role: "assistant".to_string(),
        content,
        tool_calls: final_tool_calls,
        tool_call_id: String::new(),
    };

    let _ = tx
        .send(Ok(ChatStreamEvent {
            event: Some(Event::Message(final_message)),
        }))
        .await;

    Ok(())
}

/// Accumulates streamed tool call fragments.
#[derive(Default)]
struct ToolCallAccumulator {
    id: String,
    name: String,
    arguments: String,
}
