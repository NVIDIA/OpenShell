// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Push locally-built images into a k3s gateway's containerd runtime.
//!
//! This module implements the "push" path for local development: images are
//! exported from the local Docker daemon (equivalent to `docker save`),
//! uploaded into the gateway container as a tar file via the Docker
//! `put_archive` API, and then imported into containerd via `ctr images import`.
//!
//! To avoid unbounded memory usage with large images, the export is streamed
//! to a temporary file on disk, then streamed back through a tar wrapper into
//! the Docker upload API. Peak memory usage is `O(chunk_size)` regardless of
//! image size.
//!
//! The standalone `ctr` binary is used (not `k3s ctr` which may not work in
//! all k3s versions) with the k3s containerd socket. The default containerd
//! namespace in k3s is already `k8s.io`, which is what kubelet uses.

use std::pin::Pin;

use bollard::Docker;
use bollard::query_parameters::UploadToContainerOptionsBuilder;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use miette::{IntoDiagnostic, Result, WrapErr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::runtime::exec_capture_with_exit;

/// Containerd socket path inside a k3s container.
const CONTAINERD_SOCK: &str = "/run/k3s/containerd/containerd.sock";

/// Path inside the container where the image tar is staged.
const IMPORT_TAR_PATH: &str = "/tmp/openshell-images.tar";

/// Size of chunks read from the temp file during streaming upload (8 MiB).
const UPLOAD_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// Report export progress every N bytes (100 MiB).
const PROGRESS_INTERVAL_BYTES: u64 = 100 * 1024 * 1024;

/// Push a list of images from the local Docker daemon into a k3s gateway's
/// containerd runtime.
///
/// All images are exported as a single tar (shared layers are deduplicated),
/// streamed to a temporary file, then uploaded to the container filesystem
/// and imported into containerd. Memory usage is bounded to `O(chunk_size)`
/// regardless of image size.
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

    // 1. Export all images from the local Docker daemon to a temp file.
    let (tmp_file, file_size) = export_to_tempfile(local_docker, images, on_log).await?;
    on_log(format!(
        "[progress] Exported {} MiB",
        file_size / (1024 * 1024)
    ));

    // 2. Stream the image tar wrapped in an outer tar archive into the
    //    container filesystem via the Docker put_archive API.
    let parent_dir = IMPORT_TAR_PATH.rsplit_once('/').map_or("/", |(dir, _)| dir);
    let options = UploadToContainerOptionsBuilder::default()
        .path(parent_dir)
        .build();

    let upload_stream = streaming_tar_upload(IMPORT_TAR_PATH, tmp_file, file_size);
    gateway_docker
        .upload_to_container(
            container_name,
            Some(options),
            bollard::body_try_stream(upload_stream),
        )
        .await
        .into_diagnostic()
        .wrap_err("failed to upload image tar into container")?;
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

/// Stream the Docker image export directly to a temporary file.
///
/// Returns the temp file handle and the total number of bytes written.
/// Memory usage is `O(chunk_size)` — only one chunk is held at a time.
/// Progress is reported every [`PROGRESS_INTERVAL_BYTES`] bytes.
async fn export_to_tempfile(
    docker: &Docker,
    images: &[&str],
    on_log: &mut impl FnMut(String),
) -> Result<(tempfile::NamedTempFile, u64)> {
    let tmp = tempfile::NamedTempFile::new()
        .into_diagnostic()
        .wrap_err("failed to create temp file for image export")?;

    // Open a second handle for async writing; the NamedTempFile retains
    // ownership and ensures cleanup on drop.
    let std_file = tmp
        .reopen()
        .into_diagnostic()
        .wrap_err("failed to reopen temp file for writing")?;
    let mut async_file = tokio::fs::File::from_std(std_file);

    let mut stream = docker.export_images(images);
    let mut total_bytes: u64 = 0;
    let mut last_reported: u64 = 0;

    while let Some(chunk) = stream.next().await {
        let bytes = chunk
            .into_diagnostic()
            .wrap_err("failed to read image export stream")?;
        async_file
            .write_all(&bytes)
            .await
            .into_diagnostic()
            .wrap_err("failed to write image data to temp file")?;
        total_bytes += bytes.len() as u64;

        // Report progress periodically.
        if total_bytes >= last_reported + PROGRESS_INTERVAL_BYTES {
            let mb = total_bytes / (1024 * 1024);
            on_log(format!("[progress] Exported {mb} MiB"));
            last_reported = total_bytes;
        }
    }

    async_file
        .flush()
        .await
        .into_diagnostic()
        .wrap_err("failed to flush temp file")?;

    Ok((tmp, total_bytes))
}

/// Create a stream that yields an outer tar archive containing the image tar
/// as a single entry, reading the image data from the temp file in chunks.
///
/// The Docker `put_archive` API expects a tar that is extracted at a target
/// directory. We construct a tar with one entry whose name is the basename
/// of `file_path`. The stream yields:
/// 1. A 512-byte GNU tar header
/// 2. The file content in [`UPLOAD_CHUNK_SIZE`] chunks
/// 3. Padding to a 512-byte boundary + two 512-byte zero EOF blocks
///
/// Memory usage is O([`UPLOAD_CHUNK_SIZE`]) regardless of file size.
fn streaming_tar_upload(
    file_path: &str,
    tmp_file: tempfile::NamedTempFile,
    file_size: u64,
) -> Pin<Box<dyn Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>> {
    let file_name = file_path
        .rsplit('/')
        .next()
        .unwrap_or(file_path)
        .to_string();

    Box::pin(async_stream::try_stream! {
        // 1. Build and yield the tar header.
        let mut header = tar::Header::new_gnu();
        header.set_path(&file_name)?;
        header.set_size(file_size);
        header.set_mode(0o644);
        header.set_cksum();
        yield Bytes::copy_from_slice(header.as_bytes());

        // 2. Stream the temp file content in chunks.
        let std_file = tmp_file.reopen()?;
        let mut async_file = tokio::fs::File::from_std(std_file);
        let mut buf = vec![0u8; UPLOAD_CHUNK_SIZE];
        loop {
            let n = async_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            yield Bytes::copy_from_slice(&buf[..n]);
        }

        // 3. Yield tar padding and EOF blocks.
        //    Tar entries must be padded to a 512-byte boundary, followed by
        //    two 512-byte zero blocks to signal end-of-archive.
        let padding_len = if file_size.is_multiple_of(512) {
            0
        } else {
            512 - (file_size % 512) as usize
        };
        let footer = vec![0u8; padding_len + 1024];
        yield Bytes::from(footer);

        // The NamedTempFile is dropped here, cleaning up the temp file.
        drop(tmp_file);
    })
}
