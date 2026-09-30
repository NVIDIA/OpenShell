// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable CLI file-transfer conformance scenario.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::platform::{self, SandboxFixture};
use crate::{CommandResult, OpenShellRunner, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSFER_TIMEOUT: Duration = Duration::from_mins(5);
const LARGE_FILE_SIZE: usize = 512 * 1024;

/// Certify portable upload and download behavior through the public CLI.
/// Certify basic file and directory upload and download behavior.
pub const FILE_TRANSFER_ROUND_TRIP_SCENARIO: Scenario = Scenario {
    name: "file-transfer/round-trip",
    description: "Verify file and directory upload and download round trips.",
    run: run_round_trip,
};

/// Certify Git-aware upload filtering and fallback behavior.
pub const FILE_TRANSFER_GIT_FILTERING_SCENARIO: Scenario = Scenario {
    name: "file-transfer/git-filtering",
    description: "Verify Git-aware upload selection and unfiltered fallback behavior.",
    run: run_git_filtering,
};

/// Certify file-transfer workspace boundary and filename safety behavior.
pub const FILE_TRANSFER_PATH_SAFETY_SCENARIO: Scenario = Scenario {
    name: "file-transfer/path-safety",
    description: "Verify workspace boundary enforcement and safe filename handling.",
    run: run_path_safety,
};

fn run_round_trip(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let prepared = prepare_sandbox(runner, "round-trip").await?;
        round_trip(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        download_file(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        download_directory(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        delete_sandbox(runner, &prepared.sandbox_name).await
    })
}

fn run_git_filtering(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let prepared = prepare_sandbox(runner, "git-filtering").await?;
        gitignore_filtering(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        single_file_from_git_repo(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        gitignored_directory_fallback(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        delete_sandbox(runner, &prepared.sandbox_name).await
    })
}

fn run_path_safety(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let prepared = prepare_sandbox(runner, "path-safety").await?;
        download_dash_leading_name(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        reject_workspace_escape(
            runner,
            &prepared.sandbox_name,
            &prepared.remote_root,
            prepared.local.path(),
        )
        .await?;
        delete_sandbox(runner, &prepared.sandbox_name).await
    })
}

struct PreparedSandbox {
    sandbox_name: String,
    remote_root: String,
    local: tempfile::TempDir,
    _fixture: SandboxFixture,
}

async fn prepare_sandbox(
    runner: &mut OpenShellRunner,
    group: &str,
) -> Result<PreparedSandbox, String> {
    let suffix = match group {
        "round-trip" => "fr",
        "git-filtering" => "fg",
        "path-safety" => "fs",
        _ => return Err(format!("unknown file-transfer group {group:?}")),
    };
    let sandbox_name = format!("ct-{}-{suffix}", runner.id());
    let fixture = platform::file_transfer_fixture()?;
    let remote_root = fixture.path(&format!("file-transfer-{}-{suffix}", runner.id()));
    let local =
        tempfile::tempdir().map_err(|error| format!("create temporary directory: {error}"))?;

    runner.track_sandbox(&sandbox_name);
    let mut args = vec![
        "sandbox".to_string(),
        "create".to_string(),
        "--name".to_string(),
        sandbox_name.clone(),
        "--detach".to_string(),
        "--no-tty".to_string(),
    ];
    args.extend(fixture.create_args().iter().cloned());
    args.push("--".to_string());
    args.extend(platform::keep_alive(&fixture));
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
    let create = runner
        .step(format!("{group}/create"))
        .description(format!("sandbox '{sandbox_name}' is created"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?;
    create.require_success()?;

    Ok(PreparedSandbox {
        sandbox_name,
        remote_root,
        local,
        _fixture: fixture,
    })
}

async fn delete_sandbox(runner: &mut OpenShellRunner, sandbox_name: &str) -> Result<(), String> {
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

    let remote = remote_path(remote_root, "roundtrip");
    upload(runner, sandbox, "roundtrip/upload", &source, &remote, true).await?;

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
    let remote_single = remote_path(remote_root, "single.txt");
    upload(
        runner,
        sandbox,
        "single/upload",
        &single,
        &remote_single,
        true,
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

async fn gitignore_filtering(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let repository = local_root.join("filter-repo");
    fs::create_dir(&repository).map_err(fs_error("create filter repository"))?;
    git_init(&repository).await?;
    fs::write(repository.join(".gitignore"), "*.log\nbuild/\n")
        .map_err(fs_error("write filter .gitignore"))?;
    fs::write(repository.join("tracked.txt"), "i-am-tracked")
        .map_err(fs_error("write tracked.txt"))?;
    fs::write(repository.join("ignored.log"), "i-should-be-filtered")
        .map_err(fs_error("write ignored.log"))?;
    fs::create_dir(repository.join("build")).map_err(fs_error("create ignored build directory"))?;
    fs::write(repository.join("build/output.bin"), "build-artifact")
        .map_err(fs_error("write ignored build artifact"))?;
    git(&repository, &["add", "."]).await?;

    let remote = remote_path(remote_root, "filtered");
    upload(
        runner,
        sandbox,
        "gitignore/upload",
        &repository,
        &remote,
        false,
    )
    .await?;

    let destination = local_root.join("filter-download");
    fs::create_dir(&destination).map_err(fs_error("create filter destination"))?;
    download(runner, sandbox, "gitignore/download", &remote, &destination).await?;
    let uploaded = destination.join("filter-repo");
    require_text(
        &uploaded.join("tracked.txt"),
        "i-am-tracked",
        "Git-aware tracked file",
    )?;
    require_exists(&uploaded.join(".gitignore"), "uploaded .gitignore")?;
    require_absent(&uploaded.join("ignored.log"), "Git-ignored file")?;
    require_absent(&uploaded.join("build"), "Git-ignored directory")
}

async fn single_file_from_git_repo(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let repository = local_root.join("single-repo");
    fs::create_dir_all(repository.join("nested"))
        .map_err(fs_error("create single-file repository"))?;
    git_init(&repository).await?;
    fs::write(repository.join(".gitignore"), "*.log\n")
        .map_err(fs_error("write single-file .gitignore"))?;
    fs::write(
        repository.join("nested/config.txt"),
        "single-file-from-repo",
    )
    .map_err(fs_error("write repository config.txt"))?;
    fs::write(repository.join("tracked.txt"), "should-not-upload")
        .map_err(fs_error("write unrelated tracked.txt"))?;
    fs::write(repository.join("ignored.log"), "ignored")
        .map_err(fs_error("write repository ignored.log"))?;

    let remote = remote_path(remote_root, "single-from-repo");
    upload(
        runner,
        sandbox,
        "single-from-repo/upload",
        &repository.join("nested/config.txt"),
        &remote,
        false,
    )
    .await?;
    let destination = local_root.join("single-repo-download");
    fs::create_dir(&destination).map_err(fs_error("create single-repo destination"))?;
    download(
        runner,
        sandbox,
        "single-from-repo/download",
        &remote,
        &destination,
    )
    .await?;
    require_text(
        &destination.join("config.txt"),
        "single-file-from-repo",
        "single file selected from repository",
    )?;
    require_absent(
        &destination.join("tracked.txt"),
        "unselected repository file",
    )?;
    require_absent(&destination.join("ignored.log"), "ignored repository file")
}

async fn download_file(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote = remote_path(remote_root, "download-file.txt");
    let seed = local_root.join("download-file.txt");
    fs::write(&seed, "greeting-payload").map_err(fs_error("write download-file seed"))?;
    upload(
        runner,
        sandbox,
        "download-file/upload-seed",
        &seed,
        &remote,
        true,
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
    let remote = remote_path(remote_root, "tree");
    let seed = local_root.join("tree");
    fs::create_dir_all(seed.join("sub")).map_err(fs_error("create directory-download seed"))?;
    fs::write(seed.join("root.txt"), "top-level")
        .map_err(fs_error("write directory-download root file"))?;
    fs::write(seed.join("sub/child.txt"), "nested")
        .map_err(fs_error("write directory-download nested file"))?;
    upload(
        runner,
        sandbox,
        "download-directory/upload-seed",
        &seed,
        remote_root,
        true,
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

async fn reject_workspace_escape(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let etc_link = remote_path(remote_root, "etc-link");
    let passwd_link = remote_path(remote_root, "passwd-link");
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
        ("linked-component", remote_path(&etc_link, "passwd")),
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
    let remote = remote_path(remote_root, "--checkpoint-action=evil");
    let seed = local_root.join("--checkpoint-action=evil");
    fs::write(&seed, "dash-payload").map_err(fs_error("write dash-leading seed"))?;
    upload(
        runner,
        sandbox,
        "dash-leading/upload-seed",
        &seed,
        remote_root,
        true,
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

async fn gitignored_directory_fallback(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote_seed = remote_path(remote_root, "runs/test.json");
    let seed = local_root.join("fallback-seed.json");
    fs::write(&seed, "downloaded-payload").map_err(fs_error("write fallback seed"))?;
    upload(
        runner,
        sandbox,
        "gitignored-fallback/upload-seed",
        &seed,
        &remote_seed,
        true,
    )
    .await?;

    let repository = local_root.join("fallback-repo");
    fs::create_dir(&repository).map_err(fs_error("create fallback repository"))?;
    git_init(&repository).await?;
    fs::write(repository.join(".gitignore"), "runs/\n")
        .map_err(fs_error("write fallback .gitignore"))?;
    let runs = repository.join("runs");
    fs::create_dir(&runs).map_err(fs_error("create ignored runs directory"))?;
    download(
        runner,
        sandbox,
        "gitignored-fallback/download-seed",
        &remote_seed,
        &runs,
    )
    .await?;
    require_exists(&runs.join("test.json"), "downloaded ignored file")?;

    let remote = remote_path(remote_root, "reuploaded");
    let upload_result = upload_result(
        runner,
        sandbox,
        "gitignored-fallback/upload",
        &runs,
        &remote,
        false,
    )
    .await?;
    upload_result.require_success()?;
    let output = format!("{}\n{}", upload_result.stdout(), upload_result.stderr());
    if !output.contains(".gitignore filtering excluded all files") {
        return Err(upload_result.failure_diagnostic(
            "upload warns that Git filtering excluded every file and falls back to an unfiltered transfer",
        ));
    }

    let destination = local_root.join("fallback-download");
    fs::create_dir(&destination).map_err(fs_error("create fallback destination"))?;
    download(
        runner,
        sandbox,
        "gitignored-fallback/download",
        &remote,
        &destination,
    )
    .await?;
    require_text(
        &destination.join("runs/test.json"),
        "downloaded-payload",
        "re-uploaded Git-ignored file",
    )
}

async fn upload(
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

async fn upload_result(
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
        .description(format!("upload {source:?} to {destination:?} succeeds"))
        .with_timeout(TRANSFER_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())
}

async fn download(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    source: &str,
    destination: &Path,
) -> Result<(), String> {
    let result = download_result(runner, sandbox, step, source, destination).await?;
    result.require_success()
}

async fn download_result(
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

async fn exec(
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

async fn git_init(repository: &Path) -> Result<(), String> {
    git(repository, &["init", "--quiet"]).await
}

async fn git(repository: &Path, args: &[&str]) -> Result<(), String> {
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

fn remote_path(root: &str, path: &str) -> String {
    Path::new(root).join(path).to_string_lossy().into_owned()
}

fn require_text(path: &Path, expected: &str, label: &str) -> Result<(), String> {
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

fn require_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        Ok(())
    } else {
        Err(format!("{label} does not exist at {}", path.display()))
    }
}

fn require_absent(path: &Path, label: &str) -> Result<(), String> {
    if path.exists() {
        Err(format!("{label} unexpectedly exists at {}", path.display()))
    } else {
        Ok(())
    }
}

fn fs_error(context: &'static str) -> impl FnOnce(std::io::Error) -> String {
    move |error| format!("{context}: {error}")
}
