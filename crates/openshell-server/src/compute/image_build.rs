// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Optional gateway-local image-builder boundary for compute runtimes.

use tokio::sync::mpsc;
use tonic::Status;

use super::ComputeRuntime;

#[tonic::async_trait]
pub(super) trait ImageBuilder: Send + Sync {
    fn enabled(&self) -> bool;

    async fn build_image(
        &self,
        dockerfile: &str,
        tag: &str,
        context: Vec<u8>,
        progress: mpsc::Sender<String>,
    ) -> Result<(), Status>;
}

#[cfg(not(target_os = "windows"))]
#[tonic::async_trait]
impl ImageBuilder for openshell_driver_podman::PodmanComputeDriver {
    fn enabled(&self) -> bool {
        self.image_builds_enabled()
    }

    async fn build_image(
        &self,
        dockerfile: &str,
        tag: &str,
        context: Vec<u8>,
        progress: mpsc::Sender<String>,
    ) -> Result<(), Status> {
        Self::build_image(self, dockerfile, tag, context, progress)
            .await
            .map_err(Into::into)
    }
}

impl ComputeRuntime {
    pub(crate) fn validate_image_build(&self) -> Result<(), Status> {
        let builder = self.image_builder.as_ref().ok_or_else(|| {
            Status::unimplemented(format!(
                "compute driver '{}' does not support local Dockerfile builds; use a registry image reference with --from",
                self.driver_info.name
            ))
        })?;
        if !builder.enabled() {
            return Err(Status::failed_precondition(
                "Podman image builds are disabled by the gateway operator; set enable_image_builds = true in [openshell.drivers.podman], or use a registry image reference with --from",
            ));
        }
        Ok(())
    }

    pub(crate) async fn build_image(
        &self,
        dockerfile: &str,
        tag: &str,
        context: Vec<u8>,
        progress: mpsc::Sender<String>,
    ) -> Result<(), Status> {
        self.validate_image_build()?;
        let builder = self
            .image_builder
            .as_ref()
            .expect("validated image builder must remain configured");
        builder
            .build_image(dockerfile, tag, context, progress)
            .await
    }
}
