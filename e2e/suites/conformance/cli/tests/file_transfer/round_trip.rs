// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    LARGE_FILE_SIZE, delete_sandbox, download, exec, fs_error, prepare_sandbox, require_text,
    upload, upload_result,
};
use openshell_e2e_support::OpenShellRunner;
use std::fs;
use std::path::Path;

/// Verify file and directory upload and download round trips.
#[tokio::test]
async fn transfers_files_and_directories() {
    let mut runner = OpenShellRunner::from_env("file-transfer/round-trip")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "round-trip").await?;
        round_trip(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_file(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_directory(runner, &sandbox_name, &remote_root, local.path()).await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/round-trip conformance story failed:\n{error}");
    }
}

async fn round_trip(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let source = local_root.join("roundtrip-upload");
    fs::create_dir_all(source.join("subdir")).map_err(fs_error("create round-trip source"))?;
    fs::write(source.join("greeting.txt"), "hello-from-local")
        .map_err(fs_error("write greeting.txt"))?;
    fs::write(source.join("subdir/nested.txt"), "nested-content")
        .map_err(fs_error("write nested.txt"))?;

    let large = (0u8..=250)
        .cycle()
        .take(LARGE_FILE_SIZE)
        .collect::<Vec<_>>();
    fs::write(source.join("large.bin"), &large).map_err(fs_error("write large.bin"))?;

    let remote = format!("{remote_root}/roundtrip");
    let result =
        upload_result(runner, sandbox, "roundtrip/upload", &source, &remote, false).await?;
    result.require_success()?;
    if !result.stderr().contains("outside a Git work tree")
        || !result.stderr().contains(".gitignore rules are not applied")
    {
        return Err(
            result.failure_diagnostic("upload outside Git warns that filtering is disabled")
        );
    }

    let destination = local_root.join("roundtrip-download");
    fs::create_dir(&destination).map_err(fs_error("create round-trip destination"))?;
    let remote_source = format!("{remote}/roundtrip-upload");
    download(
        runner,
        sandbox,
        "roundtrip/download",
        &remote_source,
        &destination,
    )
    .await?;

    require_text(
        &destination.join("greeting.txt"),
        "hello-from-local",
        "round-trip greeting",
    )?;
    require_text(
        &destination.join("subdir/nested.txt"),
        "nested-content",
        "round-trip nested file",
    )?;
    let actual = fs::read(destination.join("large.bin")).map_err(fs_error("read large.bin"))?;
    if actual != large {
        return Err(format!(
            "large file changed during round trip: expected {} bytes, received {} bytes",
            large.len(),
            actual.len()
        ));
    }

    let single = local_root.join("single.txt");
    fs::write(&single, "single-file-payload").map_err(fs_error("write single.txt"))?;
    let remote_single = format!("{remote_root}/single.txt");
    upload(
        runner,
        sandbox,
        "single/upload",
        &single,
        &remote_single,
        false,
    )
    .await?;
    let single_destination = local_root.join("single-download");
    fs::create_dir(&single_destination).map_err(fs_error("create single-file destination"))?;
    download(
        runner,
        sandbox,
        "single/download",
        &remote_single,
        &single_destination,
    )
    .await?;
    require_text(
        &single_destination.join("single.txt"),
        "single-file-payload",
        "single-file round trip",
    )
}

async fn download_file(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote = format!("{remote_root}/download-file.txt");
    exec(
        runner,
        sandbox,
        "download-file/seed",
        &format!("printf greeting-payload > '{remote}'"),
    )
    .await?;
    let destination = local_root.join("download-file");
    fs::create_dir(&destination).map_err(fs_error("create file-download destination"))?;
    download(
        runner,
        sandbox,
        "download-file/download",
        &remote,
        &destination,
    )
    .await?;
    require_text(
        &destination.join("download-file.txt"),
        "greeting-payload",
        "downloaded file",
    )
}

async fn download_directory(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote = format!("{remote_root}/tree");
    exec(
        runner,
        sandbox,
        "download-directory/seed",
        &format!(
            "mkdir -p '{remote}/sub' && printf top-level > '{remote}/root.txt' && printf nested > '{remote}/sub/child.txt'"
        ),
    )
    .await?;
    let destination = local_root.join("download-directory");
    fs::create_dir(&destination).map_err(fs_error("create directory-download destination"))?;
    download(
        runner,
        sandbox,
        "download-directory/download",
        &remote,
        &destination,
    )
    .await?;
    require_text(
        &destination.join("root.txt"),
        "top-level",
        "downloaded directory root file",
    )?;
    require_text(
        &destination.join("sub/child.txt"),
        "nested",
        "downloaded directory nested file",
    )
}
