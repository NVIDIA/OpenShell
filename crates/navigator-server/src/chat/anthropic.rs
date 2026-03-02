//! Anthropic messages protocol translation and SSE streaming.

use futures::StreamExt;
use navigator_core::proto::{
    ChatMessage, ChatStreamEvent, ChatStreamRequest, ContentDelta, SandboxResolvedRoute, Tool,
    ToolCall, chat_stream_event::Event,
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tonic::Status;
use tracing::debug;

/// Translate proto messages to Anthropic messages API format.
///
/// Anthropic separates the system prompt from the messages array.
/// Returns `(system_text, messages)`.
fn translate_messages(messages: &[ChatMessage]) -> (Option<String>, Vec<Value>) {
    let mut system = None;
    let mut out = Vec::new();

    for m in messages {
        match m.role.as_str() {
            "system" => {
                system = Some(m.content.clone());
            }
            "assistant" if !m.tool_calls.is_empty() => {
                // Assistant message with tool_use content blocks.
                let mut content_blocks: Vec<Value> = Vec::new();

                if !m.content.is_empty() {
                    content_blocks.push(json!({
                        "type": "text",
                        "text": m.content,
                    }));
                }

                for tc in &m.tool_calls {
                    let input: Value =
                        serde_json::from_str(&tc.arguments).unwrap_or_else(|_| json!({}));
                    content_blocks.push(json!({
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": input,
                    }));
                }

                out.push(json!({
                    "role": "assistant",
                    "content": content_blocks,
                }));
            }
            "tool" => {
                // Tool result block.
                out.push(json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": m.content,
                    }],
                }));
            }
            role => {
                out.push(json!({
                    "role": role,
                    "content": m.content,
                }));
            }
        }
    }

    (system, out)
}

/// Translate proto Tool definitions to Anthropic tool format.
fn translate_tools(tools: &[Tool]) -> Vec<Value> {
    tools
        .iter()
        .map(|t| {
            let input_schema: Value =
                serde_json::from_str(&t.parameters_schema).unwrap_or_else(|_| {
                    json!({
                        "type": "object",
                        "properties": {},
                    })
                });
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": input_schema,
            })
        })
        .collect()
}

/// Build the Anthropic request body.
fn build_request_body(request: &ChatStreamRequest, model: &str) -> Value {
    let (system, messages) = translate_messages(&request.messages);

    let mut body = json!({
        "model": model,
        "messages": messages,
        "max_tokens": 8192,
        "stream": true,
    });

    if let Some(sys) = system {
        body["system"] = json!(sys);
    }

    if !request.tools.is_empty() {
        body["tools"] = json!(translate_tools(&request.tools));
    }

    body
}

/// Stream a chat completion from an Anthropic backend.
pub async fn stream_chat(
    client: &reqwest::Client,
    route: &SandboxResolvedRoute,
    request: &ChatStreamRequest,
    tx: &mpsc::Sender<Result<ChatStreamEvent, Status>>,
) -> Result<(), Status> {
    let base = route.base_url.trim_end_matches('/');
    let url = format!("{base}/v1/messages");
    let body = build_request_body(request, &route.model_id);

    debug!(url = %url, "sending Anthropic chat request");

    let response = client
        .post(&url)
        .header("x-api-key", &route.api_key)
        .header("anthropic-version", "2023-06-01")
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

    // Parse SSE stream.
    let mut content = String::new();
    let mut tool_calls: Vec<ToolCallAccumulator> = Vec::new();
    let mut current_tool_index: Option<usize> = None;
    let mut stream = response.bytes_stream();
    let mut buffer = String::new();
    let mut current_event_type = String::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Status::internal(format!("stream read error: {e}")))?;
        let text = String::from_utf8_lossy(&chunk);
        buffer.push_str(&text);

        while let Some(line_end) = buffer.find('\n') {
            let line = buffer[..line_end].trim_end_matches('\r').to_string();
            buffer = buffer[line_end + 1..].to_string();

            if line.is_empty() {
                // End of event — reset event type.
                current_event_type.clear();
                continue;
            }

            if line.starts_with(':') {
                continue;
            }

            if let Some(event_type) = line.strip_prefix("event: ") {
                current_event_type = event_type.trim().to_string();
                continue;
            }

            if let Some(data) = line.strip_prefix("data: ") {
                let parsed: Value = match serde_json::from_str(data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                match current_event_type.as_str() {
                    "content_block_start" => {
                        // May start a tool_use block.
                        if let Some(cb) = parsed.get("content_block").filter(|cb| {
                            cb.get("type").and_then(|t| t.as_str()) == Some("tool_use")
                        }) {
                            let id = cb
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = cb
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            tool_calls.push(ToolCallAccumulator {
                                id,
                                name,
                                arguments: String::new(),
                            });
                            current_tool_index = Some(tool_calls.len() - 1);
                        }
                    }
                    "content_block_delta" => {
                        if let Some(delta) = parsed.get("delta") {
                            let delta_type =
                                delta.get("type").and_then(|t| t.as_str()).unwrap_or("");

                            match delta_type {
                                "text_delta" => {
                                    if let Some(text) = delta
                                        .get("text")
                                        .and_then(|t| t.as_str())
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
                                }
                                "input_json_delta" => {
                                    if let (Some(idx), Some(partial)) = (
                                        current_tool_index,
                                        delta.get("partial_json").and_then(|p| p.as_str()),
                                    ) && let Some(acc) = tool_calls.get_mut(idx)
                                    {
                                        acc.arguments.push_str(partial);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    "content_block_stop" => {
                        current_tool_index = None;
                    }
                    // message_stop and other events — handled after the loop.
                    _ => {}
                }
            }
        }
    }

    // Send final complete message.
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
struct ToolCallAccumulator {
    id: String,
    name: String,
    arguments: String,
}
