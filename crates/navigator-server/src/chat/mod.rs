//! Chat gRPC service — streaming LLM completions with tool calling.
//!
//! Resolves an inference route by `routing_hint` (default `"agent"`),
//! translates the request to the backend's native protocol, and streams
//! token deltas back to the caller.

mod anthropic;
mod openai;

use navigator_core::proto::{
    ChatStreamEvent, ChatStreamRequest, SandboxResolvedRoute, chat_server::Chat,
    chat_stream_event::Event,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{error, info};

use crate::{ServerState, inference::list_sandbox_routes};

const DEFAULT_ROUTING_HINT: &str = "agent";

#[derive(Debug)]
pub struct ChatService {
    state: Arc<ServerState>,
    http_client: reqwest::Client,
}

impl ChatService {
    pub fn new(state: Arc<ServerState>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .expect("failed to build reqwest client");
        Self { state, http_client }
    }
}

#[tonic::async_trait]
impl Chat for ChatService {
    type ChatStreamStream = ReceiverStream<Result<ChatStreamEvent, Status>>;

    async fn chat_stream(
        &self,
        request: Request<ChatStreamRequest>,
    ) -> Result<Response<Self::ChatStreamStream>, Status> {
        let req = request.into_inner();

        let routing_hint = if req.routing_hint.is_empty() {
            DEFAULT_ROUTING_HINT.to_string()
        } else {
            req.routing_hint.clone()
        };

        // Resolve the inference route.
        let routes = list_sandbox_routes(
            self.state.store.as_ref(),
            std::slice::from_ref(&routing_hint),
        )
        .await?;

        if routes.is_empty() {
            return Err(Status::failed_precondition(format!(
                "no enabled inference route with routing_hint '{routing_hint}'. \
                 Create one with: nav inference create --routing-hint {routing_hint} ..."
            )));
        }

        // Pick the first route that has a supported chat protocol.
        let (route, protocol) = pick_chat_route(&routes).ok_or_else(|| {
            Status::failed_precondition(
                "no inference route supports openai_chat_completions or anthropic_messages",
            )
        })?;

        info!(
            routing_hint = %routing_hint,
            protocol = %protocol,
            model = %route.model_id,
            "starting chat stream"
        );

        let (tx, rx) = mpsc::channel(256);
        let client = self.http_client.clone();
        let route = route.clone();
        let protocol = protocol.to_string();

        tokio::spawn(async move {
            let result = match protocol.as_str() {
                "openai_chat_completions" => openai::stream_chat(&client, &route, &req, &tx).await,
                "anthropic_messages" => anthropic::stream_chat(&client, &route, &req, &tx).await,
                _ => Err(Status::internal(format!(
                    "unsupported protocol: {protocol}"
                ))),
            };

            if let Err(e) = result {
                error!(error = %e, "chat stream failed");
                let _ = tx
                    .send(Ok(ChatStreamEvent {
                        event: Some(Event::Error(navigator_core::proto::ChatError {
                            message: e.message().to_string(),
                            status_code: e.code() as u32,
                        })),
                    }))
                    .await;
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

/// Pick the first route that supports a chat protocol.
///
/// Returns the route and the protocol string.
fn pick_chat_route(routes: &[SandboxResolvedRoute]) -> Option<(&SandboxResolvedRoute, &str)> {
    // Prefer openai_chat_completions, then anthropic_messages.
    for route in routes {
        for proto in &route.protocols {
            if proto == "openai_chat_completions" || proto == "anthropic_messages" {
                return Some((route, proto.as_str()));
            }
        }
    }
    None
}
