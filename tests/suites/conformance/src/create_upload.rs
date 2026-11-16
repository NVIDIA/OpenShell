// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `sandbox create --upload`.
//!
//! Ported from `e2e/rust/tests/upload_create.rs`, reworked in
//! NVIDIA/OpenShell#4606 by politerealism. The behavior is not driver-specific.
//!
//! `--upload` cannot be combined with a command, so these tests create the
//! sandbox with the target's default image and workload and check the files
//! once `create` returns.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use testkit::{Context, ResultExt as _, Sandbox};

/// `--upload <directory>:<destination>` keeps the directory's basename under
/// the destination, preserves nested files, and does not flatten the directory.
#[testkit::test]
async fn create_with_upload_directory_preserves_source_basename(
    cx: &mut Context,
) -> testkit::Result {
    let local = scratch()?;
    let source = local.path().join("project");
    write(&source.join("marker.txt"), "upload-create-marker")?;
    write(&source.join("src/main.py"), "print('hello')")?;

    let sandbox = create_with_uploads(cx, "cu1", &[(&source, "/sandbox/data")]).await?;
    sandbox
        .exec(["cat", "/sandbox/data/project/marker.txt"])
        .await?
        .expect_stdout("upload-create-marker")?;
    sandbox
        .exec(["cat", "/sandbox/data/project/src/main.py"])
        .await?
        .expect_stdout("print('hello')")?;
    sandbox
        .exec(["sh", "-c", "test ! -e /sandbox/data/marker.txt"])
        .await?
        .success()?;
    sandbox.delete().await
}

/// Several `--upload` flags on one `sandbox create` each place their files at
/// their own destination.
#[testkit::test]
async fn create_with_multiple_uploads(cx: &mut Context) -> testkit::Result {
    let local = scratch()?;
    let alpha = local.path().join("alpha");
    let beta = local.path().join("beta");
    write(&alpha.join("a.txt"), "content-alpha")?;
    write(&beta.join("b.txt"), "content-beta")?;

    let sandbox = create_with_uploads(
        cx,
        "cu2",
        &[(&alpha, "/sandbox/alpha"), (&beta, "/sandbox/beta")],
    )
    .await?;
    sandbox
        .exec(["cat", "/sandbox/alpha/alpha/a.txt"])
        .await?
        .expect_stdout("content-alpha")?;
    sandbox
        .exec(["cat", "/sandbox/beta/beta/b.txt"])
        .await?
        .expect_stdout("content-beta")?;
    sandbox.delete().await
}

/// `--upload <file>:<destination>` places a single file at the destination.
#[testkit::test]
async fn create_with_upload_single_file(cx: &mut Context) -> testkit::Result {
    let local = scratch()?;
    let source = local.path().join("config.txt");
    write(&source, "single-file-upload-test")?;

    let sandbox = create_with_uploads(cx, "cu3", &[(&source, "/sandbox")]).await?;
    sandbox
        .exec(["cat", "/sandbox/config.txt"])
        .await?
        .expect_stdout("single-file-upload-test")?;
    sandbox.delete().await
}

fn scratch() -> testkit::Result<TempDir> {
    tempfile::tempdir().context("create a local scratch directory")
}

fn write(path: &Path, content: &str) -> testkit::Result {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(format!("create {}", parent.display()))?;
    }
    fs::write(path, content).context(format!("write {}", path.display()))
}

/// Create a detached sandbox with one `--upload <source>:<destination>` flag
/// per entry and wait until it is Ready.
async fn create_with_uploads(
    cx: &Context,
    suffix: &str,
    uploads: &[(&Path, &str)],
) -> testkit::Result<Sandbox> {
    let args = uploads.iter().flat_map(|(source, destination)| {
        [
            "--upload".to_string(),
            format!("{}:{destination}", source.display()),
        ]
    });
    cx.cli_sandbox(suffix).args(args).create_ready().await
}
