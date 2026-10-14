// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_e2e_support::CommandResult;
use openshell_e2e_support::OpenShellRunner;
use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
pub const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
pub const TRANSFER_TIMEOUT: Duration = Duration::from_mins(5);
pub const LARGE_FILE_SIZE: usize = 512 * 1024;

pub async fn prepare_sandbox(
    runner: &mut OpenShellRunner,
    group: &str,
) -> Result<(String, String, tempfile::TempDir), String> {
    let suffix = match group {
        "round-trip" => "fr",
        "git-filtering" => "fg",
        "path-safety" => "fs",
        _ => return Err(format!("unknown file-transfer group {group:?}")),
    };
    let sandbox_name = format!("ct-{}-{suffix}", runner.id());
    let remote_root = format!("/sandbox/file-transfer-{}-{suffix}", runner.id());
    let local =
        tempfile::tempdir().map_err(|error| format!("create temporary directory: {error}"))?;

    runner.track_sandbox(&sandbox_name);
    let create = runner
        .step(format!("{group}/create"))
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&["sandbox", "create", "--name", &sandbox_name, "--detach"])
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    exec(
        runner,
        &sandbox_name,
        &format!("{group}/prepare"),
        &format!("mkdir -p '{remote_root}'"),
    )
    .await?;

    Ok((sandbox_name, remote_root, local))
}

pub async fn delete_sandbox(
    runner: &mut OpenShellRunner,
    sandbox_name: &str,
) -> Result<(), String> {
    let delete = runner
        .step("delete")
        .description(format!("sandbox '{sandbox_name}' is deleted"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&["sandbox", "delete", sandbox_name])
        .await
        .map_err(|error| error.to_string())?;
    delete.require_success()?;
    runner.forget_sandbox(sandbox_name);
    Ok(())
}

pub async fn upload(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    source: &Path,
    destination: &str,
    no_git_ignore: bool,
) -> Result<(), String> {
    let result = upload_result(runner, sandbox, step, source, destination, no_git_ignore).await?;
    result.require_success()
}

pub async fn upload_result(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    source: &Path,
    destination: &str,
    no_git_ignore: bool,
) -> Result<CommandResult, String> {
    let source = source
        .to_str()
        .ok_or_else(|| format!("local upload path is not UTF-8: {}", source.display()))?;
    let mut args = vec!["sandbox", "upload", sandbox, source, destination];
    if no_git_ignore {
        args.push("--no-git-ignore");
    }
    runner
        .step(step)
        .description(format!("upload {source:?} to {destination:?}"))
        .with_timeout(TRANSFER_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())
}

pub async fn download(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    source: &str,
    destination: &Path,
) -> Result<(), String> {
    let result = download_result(runner, sandbox, step, source, destination).await?;
    result.require_success()
}

pub async fn download_result(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    source: &str,
    destination: &Path,
) -> Result<CommandResult, String> {
    let destination = destination.to_str().ok_or_else(|| {
        format!(
            "local download path is not UTF-8: {}",
            destination.display()
        )
    })?;
    runner
        .step(step)
        .description(format!(
            "download {source:?} to {destination:?} has the expected disposition"
        ))
        .with_timeout(TRANSFER_TIMEOUT)
        .run(&["sandbox", "download", sandbox, source, destination])
        .await
        .map_err(|error| error.to_string())
}

pub async fn exec(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    script: &str,
) -> Result<(), String> {
    let result = runner
        .step(step)
        .description(format!("sandbox fixture setup for {step} succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", script,
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()
}

pub async fn git_init(repository: &Path) -> Result<(), String> {
    git(repository, &["init", "--quiet"]).await
}

pub async fn git(repository: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| format!("failed to run git in {}: {error}", repository.display()))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} failed in {} with status {}\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        repository.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ))
}

pub fn require_text(path: &Path, expected: &str, label: &str) -> Result<(), String> {
    let actual = fs::read_to_string(path)
        .map_err(|error| format!("read {label} at {}: {error}", path.display()))?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} content mismatch at {}: expected {expected:?}, received {actual:?}",
            path.display()
        ))
    }
}

pub fn require_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!("{label} does not exist at {}", path.display()))
    }
}

pub fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        Err(format!("{label} unexpectedly exists at {}", path.display()))
    } else {
        Ok(())
    }
}

pub fn fs_error(context: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("{context}: {error}")
}
