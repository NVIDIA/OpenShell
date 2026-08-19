// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned Dockerfile build client.

use std::path::Path;

use miette::{Result, miette};
use openshell_core::proto::{
    BuildSandboxImageRequest, BuildSandboxImageStart, build_sandbox_image_event,
    build_sandbox_image_request,
};
use owo_colors::OwoColorize;

use crate::tls::GrpcClient;

/// Stream a Dockerfile build context to the gateway-selected compute runtime.
pub async fn build_from_dockerfile(
    client: &mut GrpcClient,
    dockerfile: &Path,
    context: &Path,
    gateway_name: &str,
) -> Result<String> {
    const CHUNK_BYTES: usize = 256 * 1024;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tag = format!("openshell/sandbox-from:{timestamp}");
    let dockerfile = dockerfile
        .strip_prefix(context)
        .map_err(|_| miette!("Dockerfile must be inside the build context"))?
        .to_str()
        .ok_or_else(|| miette!("Dockerfile path is not valid UTF-8"))?
        .to_string();
    let archive = openshell_bootstrap::build::create_build_context_tar(context)?;

    eprintln!(
        "Building image {} through gateway '{}'",
        tag.cyan(),
        gateway_name
    );
    eprintln!("  {} {}", "Context:".dimmed(), context.display());
    eprintln!();

    let mut frames = Vec::with_capacity(1 + archive.len().div_ceil(CHUNK_BYTES));
    frames.push(BuildSandboxImageRequest {
        payload: Some(build_sandbox_image_request::Payload::Start(
            BuildSandboxImageStart {
                dockerfile,
                tag: tag.clone(),
            },
        )),
    });
    frames.extend(
        archive
            .chunks(CHUNK_BYTES)
            .map(|chunk| BuildSandboxImageRequest {
                payload: Some(build_sandbox_image_request::Payload::ContextChunk(
                    chunk.to_vec(),
                )),
            }),
    );

    let mut events = client
        .build_sandbox_image(tokio_stream::iter(frames))
        .await
        .map_err(|status| miette!(status.to_string()))?
        .into_inner();
    let mut result = None;
    while let Some(event) = events
        .message()
        .await
        .map_err(|status| miette!(status.to_string()))?
    {
        match event.payload {
            Some(build_sandbox_image_event::Payload::Progress(line)) => {
                eprintln!("  {line}");
            }
            Some(build_sandbox_image_event::Payload::Image(image)) => result = Some(image),
            None => {}
        }
    }
    let image = result.ok_or_else(|| miette!("gateway image build ended without an image"))?;

    eprintln!();
    eprintln!(
        "{} Image {} is available to the gateway's selected compute runtime.",
        "✓".green().bold(),
        image.cyan(),
    );
    eprintln!();
    Ok(image)
}
