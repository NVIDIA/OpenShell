// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `sandbox create --upload`.
//!
//! Migrated from `e2e/rust/tests/upload_create.rs`. The behavior is not
//! driver-specific, so it runs against any prepared gateway.
//!
//! `--upload` cannot be combined with a command, so these tests check the files
//! once `create` returns, not that they arrived before a main process started.

use std::fs;
use std::path::Path;

use testkit::{Context, Error, Sandbox};

/// `--upload <directory>:<destination>` keeps the directory's basename under
/// the destination and preserves nested files.
#[testkit::test]
async fn create_with_upload_directory_preserves_source_basename(
    cx: &mut Context,
) -> testkit::Result {
    let local = scratch()?;
    let source = local.path().join("project");
    write(&source.join("marker.txt"), "upload-create-marker")?;
    write(&source.join("src/main.py"), "print('hello')")?;

    let sandbox = create_with_uploads(cx, "cu1", &[(&source, "/sandbox/data")]).await?;
    expect_file(
        &sandbox,
        "/sandbox/data/project/marker.txt",
        "upload-create-marker",
    )
    .await?;
    expect_file(
        &sandbox,
        "/sandbox/data/project/src/main.py",
        "print('hello')",
    )
    .await?;
    sandbox
        .sh("test ! -e /sandbox/data/marker.txt")
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
    expect_file(&sandbox, "/sandbox/alpha/alpha/a.txt", "content-alpha").await?;
    expect_file(&sandbox, "/sandbox/beta/beta/b.txt", "content-beta").await?;
    sandbox.delete().await
}

/// `--upload <file>:<destination>` places a single file at the destination.
#[testkit::test]
async fn create_with_upload_single_file(cx: &mut Context) -> testkit::Result {
    let local = scratch()?;
    let source = local.path().join("config.txt");
    write(&source, "single-file-upload-test")?;

    let sandbox = create_with_uploads(cx, "cu3", &[(&source, "/sandbox")]).await?;
    expect_file(&sandbox, "/sandbox/config.txt", "single-file-upload-test").await?;
    sandbox.delete().await
}

fn scratch() -> testkit::Result<tempfile::TempDir> {
    tempfile::tempdir()
        .map_err(|error| Error::msg(format!("create a local scratch directory: {error}")))
}

fn write(path: &Path, content: &str) -> testkit::Result {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| Error::msg(format!("create {}: {error}", parent.display())))?;
    }
    fs::write(path, content)
        .map_err(|error| Error::msg(format!("write {}: {error}", path.display())))
}

/// Create a detached sandbox with one `--upload <source>:<destination>` flag
/// per entry and return a handle to it.
async fn create_with_uploads(
    cx: &Context,
    suffix: &str,
    uploads: &[(&Path, &str)],
) -> testkit::Result<Sandbox> {
    let name = cx.name(suffix);
    // Track before the CLI runs so cleanup deletes the sandbox even if the
    // create succeeds but a later step fails.
    cx.track(&name);
    let mut args = vec![
        "sandbox".to_string(),
        "create".to_string(),
        "--name".to_string(),
        name.clone(),
        "--detach".to_string(),
    ];
    for (source, destination) in uploads {
        args.push("--upload".to_string());
        args.push(format!("{}:{destination}", source.display()));
    }
    cx.cli(args).await?.success()?;
    cx.adopt(&name).await
}

/// Require the sandbox file at `path` to contain exactly `expected`.
async fn expect_file(sandbox: &Sandbox, path: &str, expected: &str) -> testkit::Result {
    let output = sandbox.sh(&format!("cat '{path}'")).await?.success()?;
    testkit::ensure!(
        output.stdout == expected,
        "{path} contains {:?}; expected {expected:?}",
        output.stdout
    );
    Ok(())
}
