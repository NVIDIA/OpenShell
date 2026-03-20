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

    // 2. Upload the image tar into the container filesystem.
    //    Try the Docker put_archive API first; fall back to `docker cp` for
    //    Podman compatibility with large payloads.
    let outer_tar = wrap_in_tar(IMPORT_TAR_PATH, &image_tar)?;
    let api_ok = upload_archive_api(gateway_docker, container_name, &outer_tar).await;
    if api_ok.is_err() {
        on_log("[progress] API upload failed, falling back to docker cp...".to_string());
        upload_via_docker_cp(container_name, &image_tar).await?;
    }
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

/// Upload a tar archive via the bollard `put_archive` API.
async fn upload_archive_api(
    docker: &Docker,
    container_name: &str,
    archive: &[u8],
) -> std::result::Result<(), bollard::errors::Error> {
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
}

/// Fallback upload: write the raw image tar to a temp file on the host, then
/// use `docker cp` to copy it into the container. This streams in chunks and
/// is more reliable with Podman for large payloads.
async fn upload_via_docker_cp(container_name: &str, image_tar: &[u8]) -> Result<()> {
    use std::io::Write;

    let tmp_dir = std::env::temp_dir();
    let tmp_path = tmp_dir.join("openshell-images.tar");
    {
        let mut f = std::fs::File::create(&tmp_path)
            .into_diagnostic()
            .wrap_err("failed to create temp file for image upload")?;
        f.write_all(image_tar)
            .into_diagnostic()
            .wrap_err("failed to write image tar to temp file")?;
    }

    let target = format!("{container_name}:{IMPORT_TAR_PATH}");
    let status = tokio::process::Command::new("docker")
        .args(["cp", tmp_path.to_str().unwrap_or(""), &target])
        .status()
        .await
        .into_diagnostic()
        .wrap_err("failed to run `docker cp`")?;

    let _ = std::fs::remove_file(&tmp_path);

    if !status.success() {
        return Err(miette::miette!(
            "`docker cp` failed with exit code {}",
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- wrap_in_tar tests --

    #[test]
    fn wrap_in_tar_produces_valid_archive() {
        let data = b"hello world";
        let result = wrap_in_tar("/tmp/test-file.tar", data);
        assert!(result.is_ok(), "wrap_in_tar should succeed");

        let tar_bytes = result.unwrap();
        assert!(!tar_bytes.is_empty(), "tar archive should not be empty");

        // Verify the archive contains exactly one entry with the correct name
        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 1, "tar should contain exactly one entry");
    }

    #[test]
    fn wrap_in_tar_uses_basename() {
        let data = b"payload";
        let tar_bytes = wrap_in_tar("/some/deep/path/image.tar", data).unwrap();

        let mut archive = tar::Archive::new(tar_bytes.as_slice());
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        let path = entry.path().unwrap();
        assert_eq!(
            path.to_str().unwrap(),
            "image.tar",
            "tar entry should use basename only"
        );
    }

    // -- upload_via_docker_cp tests --
    //
    // This function writes a temp file, invokes `docker cp`, then cleans up.
    // We can test the temp-file lifecycle even though `docker cp` will fail
    // (docker daemon is not available in unit tests).

    #[tokio::test]
    async fn upload_via_docker_cp_creates_and_cleans_up_temp_file() {
        let image_tar = b"fake image tar content";
        let tmp_path = std::env::temp_dir().join("openshell-images.tar");

        // The function will fail because `docker cp` won't find a real
        // container, but we can verify cleanup behavior.
        let result = upload_via_docker_cp("nonexistent-container-12345", image_tar).await;

        // The call should fail because docker cp will either not find docker
        // or fail to reach the container.
        assert!(result.is_err(), "should fail with a nonexistent container");

        // The temp file should have been cleaned up even on failure.
        assert!(
            !tmp_path.exists(),
            "temp file should be removed after docker cp (even on failure)"
        );
    }

    #[tokio::test]
    async fn upload_via_docker_cp_error_message_is_descriptive() {
        let result = upload_via_docker_cp("fake-container", b"data").await;
        let err_msg = format!("{:?}", result.unwrap_err());
        // The error should mention either "docker cp" or the underlying failure
        assert!(
            err_msg.contains("docker cp") || err_msg.contains("docker"),
            "error should reference docker cp, got: {err_msg}"
        );
    }
}
