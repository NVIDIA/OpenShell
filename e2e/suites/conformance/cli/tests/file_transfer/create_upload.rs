// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stories for `sandbox create --upload`.
//!
//! Preconditions: the target supplies the default sandbox image. Each story
//! writes its upload sources to a local temporary directory.
//!
//! Permissions: an identity allowed to create, execute in, and delete sandboxes.
//!
//! Side effects: each story creates one sandbox named from the run id and
//! deletes it.
//!
//! Known limitation: `--upload` cannot be combined with a command, so stories
//! check the files once `create` returns, not that they arrived before a main
//! process started.

use super::helpers::{create_with_uploads, delete_sandbox, expect_stdout, fs_error};
use openshell_e2e_support::OpenShellRunner;
use std::fs;

/// Verify `sandbox create --upload <directory>:<destination>` keeps the
/// directory's basename under the destination.
#[tokio::test]
async fn create_with_upload_directory_preserves_source_basename() {
    let mut runner = OpenShellRunner::from_env("file-transfer/create-upload-directory")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let local = tempfile::tempdir().map_err(fs_error("create temporary directory"))?;
        let source = local.path().join("project");
        fs::create_dir_all(source.join("src")).map_err(fs_error("create project/src"))?;
        fs::write(source.join("marker.txt"), "upload-create-marker")
            .map_err(fs_error("write marker.txt"))?;
        fs::write(source.join("src/main.py"), "print('hello')")
            .map_err(fs_error("write main.py"))?;

        let sandbox_name = format!("ct-{}-cu1", runner.id());
        create_with_uploads(
            runner,
            "create-upload-directory/create",
            &sandbox_name,
            &[(&source, "/sandbox/data")],
        )
        .await?;

        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-directory/marker",
            "cat /sandbox/data/project/marker.txt",
            "upload-create-marker",
        )
        .await?;
        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-directory/nested",
            "cat /sandbox/data/project/src/main.py",
            "print('hello')",
        )
        .await?;
        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-directory/not-flattened",
            "test ! -e /sandbox/data/marker.txt && echo absent",
            "absent\n",
        )
        .await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/create-upload-directory conformance story failed:\n{error}");
    }
}

/// Verify several `--upload` flags on one `sandbox create` all place their
/// files at their own destinations.
#[tokio::test]
async fn create_with_multiple_uploads() {
    let mut runner = OpenShellRunner::from_env("file-transfer/create-upload-multiple")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let local = tempfile::tempdir().map_err(fs_error("create temporary directory"))?;
        let alpha = local.path().join("alpha");
        let beta = local.path().join("beta");
        fs::create_dir_all(&alpha).map_err(fs_error("create alpha"))?;
        fs::create_dir_all(&beta).map_err(fs_error("create beta"))?;
        fs::write(alpha.join("a.txt"), "content-alpha").map_err(fs_error("write a.txt"))?;
        fs::write(beta.join("b.txt"), "content-beta").map_err(fs_error("write b.txt"))?;

        let sandbox_name = format!("ct-{}-cu2", runner.id());
        create_with_uploads(
            runner,
            "create-upload-multiple/create",
            &sandbox_name,
            &[(&alpha, "/sandbox/alpha"), (&beta, "/sandbox/beta")],
        )
        .await?;

        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-multiple/alpha",
            "cat /sandbox/alpha/alpha/a.txt",
            "content-alpha",
        )
        .await?;
        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-multiple/beta",
            "cat /sandbox/beta/beta/b.txt",
            "content-beta",
        )
        .await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/create-upload-multiple conformance story failed:\n{error}");
    }
}

/// Verify `sandbox create --upload <file>:<destination>` places a single file
/// at the destination.
#[tokio::test]
async fn create_with_upload_single_file() {
    let mut runner = OpenShellRunner::from_env("file-transfer/create-upload-file")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let local = tempfile::tempdir().map_err(fs_error("create temporary directory"))?;
        let source = local.path().join("config.txt");
        fs::write(&source, "single-file-upload-test").map_err(fs_error("write config.txt"))?;

        let sandbox_name = format!("ct-{}-cu3", runner.id());
        create_with_uploads(
            runner,
            "create-upload-file/create",
            &sandbox_name,
            &[(&source, "/sandbox")],
        )
        .await?;

        expect_stdout(
            runner,
            &sandbox_name,
            "create-upload-file/read",
            "cat /sandbox/config.txt",
            "single-file-upload-test",
        )
        .await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/create-upload-file conformance story failed:\n{error}");
    }
}
