// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public gateway image-build stream validation and dispatch.

use std::sync::Arc;

use openshell_core::proto::{
    BuildSandboxImageEvent, BuildSandboxImageRequest, build_sandbox_image_event,
    build_sandbox_image_request,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::ServerState;

pub type BuildSandboxImageStream = ReceiverStream<Result<BuildSandboxImageEvent, Status>>;

pub fn handle_build_sandbox_image(
    state: Arc<ServerState>,
    request: Request<tonic::Streaming<BuildSandboxImageRequest>>,
) -> Response<BuildSandboxImageStream> {
    const MAX_CHUNK_BYTES: usize = 1024 * 1024;
    const MAX_CONTEXT_BYTES: usize = 512 * 1024 * 1024;

    let mut inbound = request.into_inner();
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    tokio::spawn(async move {
        let result = async {
            let first = inbound
                .message()
                .await?
                .ok_or_else(|| Status::invalid_argument("image build stream is empty"))?;
            let Some(build_sandbox_image_request::Payload::Start(start)) = first.payload else {
                return Err(Status::invalid_argument(
                    "first image build frame must contain build metadata",
                ));
            };
            if start.tag.is_empty() || !start.tag.starts_with("openshell/sandbox-from:") {
                return Err(Status::invalid_argument(
                    "image build tag must use the openshell/sandbox-from namespace",
                ));
            }
            let dockerfile = std::path::Path::new(&start.dockerfile);
            if start.dockerfile.is_empty()
                || dockerfile.is_absolute()
                || dockerfile
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(Status::invalid_argument(
                    "Dockerfile path must be relative to the build context",
                ));
            }

            state.compute.validate_image_build()?;

            let mut context = Vec::new();
            while let Some(frame) = inbound.message().await? {
                let chunk = match frame.payload {
                    Some(build_sandbox_image_request::Payload::ContextChunk(chunk)) => chunk,
                    Some(build_sandbox_image_request::Payload::Start(_)) => {
                        return Err(Status::invalid_argument(
                            "image build metadata may only be sent once",
                        ));
                    }
                    None => return Err(Status::invalid_argument("empty image build frame")),
                };
                if chunk.len() > MAX_CHUNK_BYTES {
                    return Err(Status::invalid_argument("image build chunk exceeds 1 MiB"));
                }
                if context.len().saturating_add(chunk.len()) > MAX_CONTEXT_BYTES {
                    return Err(Status::resource_exhausted(
                        "image build context exceeds 512 MiB",
                    ));
                }
                context.extend_from_slice(&chunk);
            }
            if context.is_empty() {
                return Err(Status::invalid_argument("image build context is empty"));
            }

            let (progress_tx, mut progress_rx) = tokio::sync::mpsc::channel(32);
            let event_tx = tx.clone();
            let progress_task = tokio::spawn(async move {
                while let Some(line) = progress_rx.recv().await {
                    if event_tx
                        .send(Ok(BuildSandboxImageEvent {
                            payload: Some(build_sandbox_image_event::Payload::Progress(line)),
                        }))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
            state
                .compute
                .build_image(&start.dockerfile, &start.tag, context, progress_tx)
                .await?;
            let _ = progress_task.await;
            tx.send(Ok(BuildSandboxImageEvent {
                payload: Some(build_sandbox_image_event::Payload::Image(start.tag)),
            }))
            .await
            .map_err(|_| Status::cancelled("image build client disconnected"))?;
            Ok::<(), Status>(())
        }
        .await;
        if let Err(status) = result {
            let _ = tx.send(Err(status)).await;
        }
    });
    Response::new(ReceiverStream::new(rx))
}
