// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-owned image builds for the Podman compute driver.

use bollard::Docker;
use bollard::query_parameters::BuildImageOptionsBuilder;
use bytes::Bytes;
use futures::StreamExt;
use openshell_core::ComputeDriverError;
use tokio::sync::mpsc;
use tracing::info;

use crate::PodmanComputeDriver;

impl PodmanComputeDriver {
    /// Return whether the operator allows gateway-owned image builds.
    #[must_use]
    pub fn image_builds_enabled(&self) -> bool {
        self.config.enable_image_builds
    }

    /// Build a Dockerfile context in the exact image store selected by this driver.
    #[tracing::instrument(
        name = "podman.image_build",
        skip_all,
        fields(image.tag = %tag, dockerfile = %dockerfile, context.bytes = context.len())
    )]
    pub async fn build_image(
        &self,
        dockerfile: &str,
        tag: &str,
        context: Vec<u8>,
        progress: mpsc::Sender<String>,
    ) -> Result<(), ComputeDriverError> {
        if !self.image_builds_enabled() {
            return Err(ComputeDriverError::Precondition(
                "Podman image builds are disabled by the gateway operator; set enable_image_builds = true in [openshell.drivers.podman], or use a registry image reference with --from"
                    .to_string(),
            ));
        }
        info!("Starting Podman image build");
        let socket = self
            .config
            .socket_path
            .as_ref()
            .and_then(|path| path.to_str())
            .ok_or_else(|| {
                ComputeDriverError::Precondition("Podman socket path is invalid".into())
            })?;
        let engine = Docker::connect_with_unix(socket, 120, bollard::API_DEFAULT_VERSION)
            .map_err(|err| {
                ComputeDriverError::Message(format!("connect to Podman build API: {err}"))
            })?
            .negotiate_version()
            .await
            .map_err(|err| {
                ComputeDriverError::Message(format!("negotiate Podman build API: {err}"))
            })?;
        let options = BuildImageOptionsBuilder::default()
            .dockerfile(dockerfile)
            .t(tag)
            .rm(true)
            .build();
        let body = bollard::body_full(Bytes::from(context));
        let mut events = engine.build_image(options, None, Some(body));
        while let Some(event) = events.next().await {
            let event = event.map_err(|err| {
                ComputeDriverError::Message(format!("Podman image build failed: {err}"))
            })?;
            if let Some(detail) = event.error_detail {
                return Err(ComputeDriverError::InvalidArgument(format!(
                    "Podman image build failed: {}",
                    detail
                        .message
                        .unwrap_or_else(|| "unknown build error".to_string())
                )));
            }
            if let Some(line) = event.stream.or(event.status) {
                let line = line.trim_end();
                if !line.is_empty() && progress.send(line.to_string()).await.is_err() {
                    return Err(ComputeDriverError::Message(
                        "image build client disconnected".to_string(),
                    ));
                }
            }
        }
        info!("Podman image build completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PodmanComputeConfig;

    #[tokio::test]
    async fn image_builds_are_disabled_by_default() {
        let driver = PodmanComputeDriver::for_tests(PodmanComputeConfig::default());
        let (progress, _rx) = mpsc::channel(1);
        let error = driver
            .build_image(
                "Dockerfile",
                "openshell/sandbox-from:test",
                Vec::new(),
                progress,
            )
            .await
            .expect_err("default configuration must reject image builds");
        assert!(matches!(error, ComputeDriverError::Precondition(_)));
        assert!(error.to_string().contains("enable_image_builds = true"));
    }
}
