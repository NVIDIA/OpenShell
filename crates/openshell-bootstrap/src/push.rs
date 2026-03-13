// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push locally-built images into a k3s gateway's containerd runtime.
//!
//! This module implements the "push" path for local development: images are
//! exported from the local Docker daemon (equivalent to `docker save`),
//! uploaded into the gateway container as a tar file via the Docker
//! `put_archive` API, and then imported into containerd via `ctr images import`.
//!
//! The standalone `ctr` binary is used (not `k3s ctr` which may not work in
//! all k3s versions) with the k3s containerd socket. The default containerd
//! namespace in k3s is already `k8s.io`, which is what kubelet uses.

use bollard::Docker;
use bollard::query_parameters::UploadToContainerOptionsBuilder;
use bytes::Bytes;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};

use crate::runtime::exec_capture_with_exit;

/// Containerd socket path inside a k3s container.
const CONTAINERD_SOCK: &str = "/run/k3s/containerd/containerd.sock";

/// Path inside the container where the image tar is staged.
const IMPORT_TAR_PATH: &str = "/tmp/openshell-images.tar";

/// Push a list of images from the local Docker daemon into a k3s gateway's
/// containerd runtime.
///
/// All images are exported as a single tar (shared layers are deduplicated),
/// uploaded to the container filesystem, and imported into containerd.
pub async fn push_local_images(
    local_docker: &Docker,
    gateway_docker: &Docker,
    container_name: &str,
    images: &[&str],
    on_log: &mut impl FnMut(String),
) -> Result<()> {
    if images.is_empty() {
        return Ok(());
    }

    // 1. Export all images from the local Docker daemon as a single tar.
    let image_tar = collect_export(local_docker, images).await?;
    on_log(format!(
        "[progress] Exported {} MiB",
        image_tar.len() / (1024 * 1024)
    ));

    // 2. Wrap the image tar as a file inside an outer tar archive and upload
    //    it into the container filesystem via the Docker put_archive API.
    let outer_tar = wrap_in_tar(IMPORT_TAR_PATH, &image_tar)?;
    upload_archive(gateway_docker, container_name, &outer_tar).await?;
    on_log("[progress] Uploaded to gateway".to_string());

    // 3. Import the tar into containerd via ctr.
    let (output, exit_code) = exec_capture_with_exit(
        gateway_docker,
        container_name,
        vec![
            "ctr".to_string(),
            "-a".to_string(),
            CONTAINERD_SOCK.to_string(),
            "-n".to_string(),
            "k8s.io".to_string(),
            "images".to_string(),
            "import".to_string(),
            IMPORT_TAR_PATH.to_string(),
        ],
    )
    .await?;

    if exit_code != 0 {
        return Err(miette::miette!(
            "ctr images import exited with code {exit_code}\n{output}"
        ));
    }

    // 4. Clean up the staged tar file.
    let _ = exec_capture_with_exit(
        gateway_docker,
        container_name,
        vec![
            "rm".to_string(),
            "-f".to_string(),
            IMPORT_TAR_PATH.to_string(),
        ],
    )
    .await;

    Ok(())
}

/// Collect the full export tar from `docker.export_images()` into memory.
async fn collect_export(docker: &Docker, images: &[&str]) -> Result<Vec<u8>> {
    let mut stream = docker.export_images(images);
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let bytes = chunk
            .into_diagnostic()
            .wrap_err("failed to read image export stream")?;
        buf.extend_from_slice(&bytes);
    }
    Ok(buf)
}

/// Wrap raw bytes as a single file inside a tar archive.
///
/// The Docker `put_archive` API expects a tar that is extracted at a target
/// directory. We create a tar containing one entry whose name is the basename
/// of `file_path`, and upload it to the parent directory.
fn wrap_in_tar(file_path: &str, data: &[u8]) -> Result<Vec<u8>> {
    let file_name = file_path.rsplit('/').next().unwrap_or(file_path);

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(file_name).into_diagnostic()?;
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, data)
        .into_diagnostic()
        .wrap_err("failed to build tar archive for image upload")?;
    builder
        .into_inner()
        .into_diagnostic()
        .wrap_err("failed to finalize tar archive")
}

/// Upload a tar archive into the container at the parent directory of
/// [`IMPORT_TAR_PATH`].
async fn upload_archive(docker: &Docker, container_name: &str, archive: &[u8]) -> Result<()> {
    let parent_dir = IMPORT_TAR_PATH.rsplit_once('/').map_or("/", |(dir, _)| dir);

    let options = UploadToContainerOptionsBuilder::default()
        .path(parent_dir)
        .build();

    docker
        .upload_to_container(
            container_name,
            Some(options),
            bollard::body_full(Bytes::copy_from_slice(archive)),
        )
        .await
        .into_diagnostic()
        .wrap_err("failed to upload image tar into container")
}
