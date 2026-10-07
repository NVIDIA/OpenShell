// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    delete_sandbox, download, download_result, exec, fs_error, prepare_sandbox, require_absent,
    require_text,
};
use openshell_e2e_support::OpenShellRunner;
use std::fs;
use std::path::Path;

/// Verify workspace boundary enforcement and safe filename handling.
#[tokio::test]
async fn enforces_workspace_boundary_and_handles_filenames() {
    let mut runner = OpenShellRunner::from_env("file-transfer/path-safety")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "path-safety").await?;
        reject_workspace_escape(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_dash_leading_name(runner, &sandbox_name, &remote_root, local.path()).await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/path-safety conformance story failed:\n{error}");
    }
}

async fn reject_workspace_escape(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let etc_link = format!("{remote_root}/etc-link");
    let passwd_link = format!("{remote_root}/passwd-link");
    exec(
        runner,
        sandbox,
        "workspace-escape/seed",
        &format!("ln -s /etc '{etc_link}' && ln -s /etc/passwd '{passwd_link}'"),
    )
    .await?;
    let destination = local_root.join("workspace-escape");
    fs::create_dir(&destination).map_err(fs_error("create workspace-escape destination"))?;

    for (step, source) in [
        ("directory-link", etc_link.clone()),
        ("file-link", passwd_link),
        ("linked-component", format!("{etc_link}/passwd")),
    ] {
        let result = download_result(
            runner,
            sandbox,
            &format!("workspace-escape/{step}"),
            &source,
            &destination,
        )
        .await?;
        if result.success() {
            return Err(format!(
                "download unexpectedly accepted sandbox path {source:?} that resolves outside the workspace"
            ));
        }
        let diagnostic = format!("{}\n{}", result.stdout(), result.stderr());
        if !diagnostic.contains("resolves to")
            || !diagnostic.contains("outside the")
            || !diagnostic.contains("sandbox workspace")
        {
            return Err(result.failure_diagnostic(
                "download is rejected because the resolved source is outside the sandbox workspace",
            ));
        }
    }
    require_absent(&destination.join("passwd"), "escaped passwd file")?;
    require_absent(&destination.join("etc-link"), "escaped /etc directory")
}

async fn download_dash_leading_name(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote = format!("{remote_root}/--checkpoint-action=evil");
    exec(
        runner,
        sandbox,
        "dash-leading/seed",
        &format!("printf dash-payload > '{remote}'"),
    )
    .await?;
    let destination = local_root.join("dash-leading");
    fs::create_dir(&destination).map_err(fs_error("create dash-leading destination"))?;
    download(
        runner,
        sandbox,
        "dash-leading/download",
        &remote,
        &destination,
    )
    .await?;
    require_text(
        &destination.join("--checkpoint-action=evil"),
        "dash-payload",
        "dash-leading file",
    )
}
