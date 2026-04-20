// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end orchestrator: image ref → cached squashfs + launch metadata.
//!
//! On a cache hit this is a zero-I/O path that returns the cached descriptor.
//! On a miss it pulls the image, flattens its layers, injects compat files,
//! builds a squashfs, and installs it into the cache under the manifest digest.

use std::collections::BTreeMap;

use tracing::{debug, info};

use super::cache::{CacheLayout, CachedImage};
use super::client::{OciPuller, PullError};
use super::compat;
use super::flatten;
use super::fs_image::{self, BuildOptions};
use super::metadata::{BuildError, LaunchMetadata};

/// Sandbox- and template-level env overrides that the pipeline merges into
/// the final launch metadata.
#[derive(Debug, Default, Clone)]
pub struct EnvOverrides {
    pub template: BTreeMap<String, String>,
    pub spec: BTreeMap<String, String>,
}

/// Prepare an OCI image into a cache-backed [`CachedImage`] descriptor.
///
/// Idempotent: if the image (keyed by manifest digest + platform) is already
/// built and its metadata exists, no network or disk work happens.
pub async fn prepare(
    puller: &OciPuller,
    cache: &CacheLayout,
    build_opts: &BuildOptions,
    image_ref: &str,
    env_overrides: &EnvOverrides,
) -> Result<CachedImage, PipelineError> {
    cache.ensure_dirs().map_err(PipelineError::Cache)?;

    let platform = puller.platform();

    debug!(image = image_ref, %platform, "resolving OCI image");
    let pulled = puller.pull(image_ref).await.map_err(PipelineError::Pull)?;
    let manifest_digest = pulled.manifest_digest.clone();

    if let Some(hit) = cache.lookup(&manifest_digest, platform) {
        info!(digest = %manifest_digest, %platform, "OCI cache hit, skipping build");
        return Ok(hit);
    }

    debug!(digest = %manifest_digest, "flattening OCI layers");
    let staging = cache
        .tmp_dir()
        .join(format!("stage-{}", strip_prefix(&manifest_digest)));
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(PipelineError::Cache)?;
    }
    std::fs::create_dir_all(&staging).map_err(PipelineError::Cache)?;

    for layer in &pulled.layers {
        flatten::apply_layer_bytes(&staging, &layer.media_type, &layer.data)
            .map_err(PipelineError::Flatten)?;
    }

    debug!("injecting OpenShell compatibility files");
    compat::inject(&staging).map_err(PipelineError::Compat)?;

    let metadata = LaunchMetadata::build(
        pulled.image_config,
        &env_overrides.template,
        &env_overrides.spec,
    )
    .map_err(PipelineError::Metadata)?;

    let built = cache
        .tmp_dir()
        .join(format!("build-{}.squashfs", strip_prefix(&manifest_digest)));
    debug!(output = %built.display(), "building squashfs");
    fs_image::build(&staging, &built, build_opts).map_err(PipelineError::Build)?;

    // Staging tree is no longer needed once the fs image is built.
    let _ = std::fs::remove_dir_all(&staging);

    let installed = cache
        .install_fs_image(&manifest_digest, platform, &built)
        .map_err(PipelineError::Cache)?;
    cache
        .write_metadata(&manifest_digest, platform, &metadata)
        .map_err(PipelineError::Cache)?;

    info!(digest = %manifest_digest, %platform, path = %installed.display(), "OCI image prepared");
    Ok(CachedImage {
        fs_image: installed,
        metadata,
    })
}

/// Validate that an image reference is structurally OK before we bother the
/// registry. Useful for `validate_sandbox_create`.
pub fn validate_reference(image_ref: &str) -> Result<(), PipelineError> {
    use std::str::FromStr;
    oci_client::Reference::from_str(image_ref)
        .map(|_| ())
        .map_err(|err| PipelineError::Pull(PullError::InvalidReference(err.to_string())))
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("cache I/O: {0}")]
    Cache(#[source] std::io::Error),
    #[error(transparent)]
    Pull(PullError),
    #[error("flatten layer: {0}")]
    Flatten(#[source] std::io::Error),
    #[error("inject compat files: {0}")]
    Compat(#[source] std::io::Error),
    #[error(transparent)]
    Metadata(BuildError),
    #[error("build fs image: {0}")]
    Build(#[source] std::io::Error),
}

fn strip_prefix(digest: &str) -> &str {
    digest.split_once(':').map_or(digest, |(_, hex)| hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_reference_accepts_canonical_image_ref() {
        validate_reference("docker.io/library/alpine:3.20").expect("valid");
        validate_reference(
            "ghcr.io/org/image@sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .expect("digest ref");
    }

    #[test]
    fn validate_reference_rejects_empty_string() {
        validate_reference("").expect_err("empty ref should fail");
    }
}
