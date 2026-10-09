// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Portable CLI file-transfer conformance scenario.

use std::fs;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;

use crate::{CommandResult, OpenShellRunner, Scenario, ScenarioFuture};

const CREATE_TIMEOUT: Duration = Duration::from_mins(10);
const COMMAND_TIMEOUT: Duration = Duration::from_mins(2);
const TRANSFER_TIMEOUT: Duration = Duration::from_mins(5);
const LARGE_FILE_SIZE: usize = 512 * 1024;

/// Certify portable upload and download behavior through the public CLI.
pub const FILE_TRANSFER_SCENARIO: Scenario = Scenario {
    name: "file-transfer",
    description: "Verify sandbox uploads, downloads, Git filtering, and path safety.",
    run: run_file_transfer,
};

/// Certify basic file and directory upload and download behavior.
pub const FILE_TRANSFER_ROUND_TRIP_SCENARIO: Scenario = Scenario {
    name: "file-transfer/round-trip",
    description: "Verify file and directory upload and download round trips.",
    run: run_round_trip,
};

/// Certify Git-aware upload filtering and explicit unfiltered uploads.
pub const FILE_TRANSFER_GIT_FILTERING_SCENARIO: Scenario = Scenario {
    name: "file-transfer/git-filtering",
    description: "Verify Git-aware upload selection and explicit unfiltered uploads.",
    run: run_git_filtering,
};

/// Certify file-transfer workspace boundary and filename safety behavior.
pub const FILE_TRANSFER_PATH_SAFETY_SCENARIO: Scenario = Scenario {
    name: "file-transfer/path-safety",
    description: "Verify workspace boundary enforcement and safe filename handling.",
    run: run_path_safety,
};

/// Certify that `sandbox create --upload` pre-loads files before the
/// sandbox's command runs.
pub const FILE_TRANSFER_CREATE_UPLOAD_SCENARIO: Scenario = Scenario {
    name: "file-transfer/create-upload",
    description: "Verify `sandbox create --upload` pre-loads files before the command runs.",
    run: run_create_upload,
};

fn run_file_transfer(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        FILE_TRANSFER_ROUND_TRIP_SCENARIO.run(runner).await?;
        FILE_TRANSFER_GIT_FILTERING_SCENARIO.run(runner).await?;
        FILE_TRANSFER_PATH_SAFETY_SCENARIO.run(runner).await?;
        FILE_TRANSFER_CREATE_UPLOAD_SCENARIO.run(runner).await
    })
}

fn run_round_trip(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "round-trip").await?;
        upload_existing_directories(runner, &sandbox_name, &remote_root, local.path()).await?;
        round_trip(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_file(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_directory(runner, &sandbox_name, &remote_root, local.path()).await?;
        delete_sandbox(runner, &sandbox_name).await
    })
}

fn run_git_filtering(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "git-filtering").await?;
        gitignore_filtering(runner, &sandbox_name, &remote_root, local.path()).await?;
        single_file_from_git_repo(runner, &sandbox_name, &remote_root, local.path()).await?;
        gitignored_directory_requires_override(runner, &sandbox_name, &remote_root, local.path())
            .await?;
        delete_sandbox(runner, &sandbox_name).await
    })
}

fn run_path_safety(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "path-safety").await?;
        reject_workspace_escape(runner, &sandbox_name, &remote_root, local.path()).await?;
        download_dash_leading_name(runner, &sandbox_name, &remote_root, local.path()).await?;
        delete_sandbox(runner, &sandbox_name).await
    })
}

fn run_create_upload(runner: &mut OpenShellRunner) -> ScenarioFuture<'_> {
    Box::pin(async move {
        create_upload_directory_preserves_source_basename(runner).await?;
        create_with_multiple_uploads(runner).await?;
        create_upload_single_file(runner).await
    })
}

/// A sandbox created with `--upload <dir>:<dest>` preserves the source
/// directory's basename under `<dest>`.
async fn create_upload_directory_preserves_source_basename(
    runner: &mut OpenShellRunner,
) -> Result<(), String> {
    let local =
        tempfile::tempdir().map_err(fs_error("create create-upload/directory temporary dir"))?;
    let source = local.path().join("project");
    fs::create_dir_all(source.join("src")).map_err(fs_error("create project/src"))?;
    fs::write(source.join("marker.txt"), "upload-create-marker")
        .map_err(fs_error("write marker.txt"))?;
    fs::write(source.join("src/main.py"), "print('hello')").map_err(fs_error("write main.py"))?;

    let sandbox_name = format!("ct-{}-cu1", runner.id());
    create_with_uploads(
        runner,
        "create-upload/directory",
        &sandbox_name,
        &[(&source, "/sandbox/data")],
    )
    .await?;

    let output = exec_capture(
        runner,
        &sandbox_name,
        "create-upload/directory/verify",
        "cat /sandbox/data/project/marker.txt",
    )
    .await?;
    if !output.contains("upload-create-marker") {
        return Err(format!(
            "expected uploaded marker content in sandbox output:\n{output}"
        ));
    }

    delete_sandbox(runner, &sandbox_name).await
}

/// Two `--upload` specs in a single `sandbox create` call both land in the
/// sandbox before the command runs.
async fn create_with_multiple_uploads(runner: &mut OpenShellRunner) -> Result<(), String> {
    let local = tempfile::tempdir().map_err(fs_error("create multiple-uploads temporary dir"))?;
    let dir_a = local.path().join("alpha");
    let dir_b = local.path().join("beta");
    fs::create_dir_all(&dir_a).map_err(fs_error("create alpha"))?;
    fs::create_dir_all(&dir_b).map_err(fs_error("create beta"))?;
    fs::write(dir_a.join("a.txt"), "content-alpha").map_err(fs_error("write a.txt"))?;
    fs::write(dir_b.join("b.txt"), "content-beta").map_err(fs_error("write b.txt"))?;

    let sandbox_name = format!("ct-{}-cu2", runner.id());
    create_with_uploads(
        runner,
        "create-upload/multiple",
        &sandbox_name,
        &[(&dir_a, "/sandbox/alpha"), (&dir_b, "/sandbox/beta")],
    )
    .await?;

    let output = exec_capture(
        runner,
        &sandbox_name,
        "create-upload/multiple/verify",
        "cat /sandbox/alpha/alpha/a.txt /sandbox/beta/beta/b.txt",
    )
    .await?;
    if !output.contains("content-alpha") || !output.contains("content-beta") {
        return Err(format!(
            "expected both uploaded contents in sandbox output:\n{output}"
        ));
    }

    delete_sandbox(runner, &sandbox_name).await
}

/// `--upload` with a single file (not a directory) works.
async fn create_upload_single_file(runner: &mut OpenShellRunner) -> Result<(), String> {
    let local = tempfile::tempdir().map_err(fs_error("create single-file temporary dir"))?;
    let file_path = local.path().join("config.txt");
    fs::write(&file_path, "single-file-upload-test").map_err(fs_error("write config.txt"))?;

    let sandbox_name = format!("ct-{}-cu3", runner.id());
    create_with_uploads(
        runner,
        "create-upload/single-file",
        &sandbox_name,
        &[(&file_path, "/sandbox")],
    )
    .await?;

    let output = exec_capture(
        runner,
        &sandbox_name,
        "create-upload/single-file/verify",
        "cat /sandbox/config.txt",
    )
    .await?;
    if !output.contains("single-file-upload-test") {
        return Err(format!(
            "expected single-file content in sandbox output:\n{output}"
        ));
    }

    delete_sandbox(runner, &sandbox_name).await
}

/// Run `sandbox create --detach --upload <local>:<dest>... --no-git-ignore`.
async fn create_with_uploads(
    runner: &mut OpenShellRunner,
    step: &str,
    sandbox_name: &str,
    uploads: &[(&Path, &str)],
) -> Result<(), String> {
    runner.track_sandbox(sandbox_name);
    let mut args = vec![
        "sandbox".to_string(),
        "create".to_string(),
        "--name".to_string(),
        sandbox_name.to_string(),
        "--detach".to_string(),
    ];
    for (local, dest) in uploads {
        let local = local
            .to_str()
            .ok_or_else(|| format!("local upload path is not UTF-8: {}", local.display()))?;
        args.push("--upload".to_string());
        args.push(format!("{local}:{dest}"));
    }
    args.push("--no-git-ignore".to_string());
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = runner
        .step(step)
        .description(format!("sandbox '{sandbox_name}' is created with uploads"))
        .with_timeout(CREATE_TIMEOUT)
        .run(&args)
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()
}

/// Exec a command in the sandbox and return its combined stdout+stderr.
async fn exec_capture(
    runner: &OpenShellRunner,
    sandbox: &str,
    step: &str,
    script: &str,
) -> Result<String, String> {
    let result = runner
        .step(step)
        .description(format!("sandbox '{sandbox}' exec for {step} succeeds"))
        .with_timeout(COMMAND_TIMEOUT)
        .run(&[
            "sandbox", "exec", "--name", sandbox, "--no-tty", "--", "sh", "-c", script,
        ])
        .await
        .map_err(|error| error.to_string())?;
    result.require_success()?;
    Ok(format!("{}{}", result.stdout(), result.stderr()))
}

async fn prepare_sandbox(
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

/// Check remote destination types, not just successful transfer status: tar
/// can report success after replacing an empty directory with a regular file.
async fn upload_existing_directories(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let source = local_root.join("config.json");
    fs::write(&source, "upload-destination-payload")
        .map_err(fs_error("write destination fixture"))?;
    let root = format!("{remote_root}/upload destinations");
    exec(
        runner,
        sandbox,
        "upload-destinations/prepare",
        &format!(
            "mkdir -p '{root}/empty' '{root}/populated' '{root}/target' '{root}/slash' && \
             printf keep > '{root}/populated/keep.txt' && \
             ln -s target '{root}/link'"
        ),
    )
    .await?;

    for directory in ["empty", "populated", "link", "slash/"] {
        let destination = format!("{root}/{directory}");
        upload(
            runner,
            sandbox,
            &format!("upload-destinations/{directory}/upload"),
            &source,
            &destination,
            true,
        )
        .await?;
        exec(
            runner,
            sandbox,
            &format!("upload-destinations/{directory}/verify"),
            &format!(
                "test -d '{destination}' && \
                 test \"$(cat '{destination}/config.json')\" = upload-destination-payload && \
                 test \"$(cat '{root}/populated/keep.txt')\" = keep && \
                 test -L '{root}/link'"
            ),
        )
        .await?;
    }

    // A missing destination remains an intentional rename; uploading again
    // must replace that file rather than treating it as a directory.
    let renamed = format!("{root}/renamed.json");
    for pass in ["rename", "overwrite"] {
        upload(
            runner,
            sandbox,
            &format!("upload-destinations/{pass}/upload"),
            &source,
            &renamed,
            true,
        )
        .await?;
        exec(
            runner,
            sandbox,
            &format!("upload-destinations/{pass}/verify"),
            &format!(
                "test -f '{renamed}' && test \"$(cat '{renamed}')\" = upload-destination-payload"
            ),
        )
        .await?;
    }
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

    let remote = format!("{remote_root}/filtered");
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

    let remote = format!("{remote_root}/single-from-repo");
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

async fn gitignored_directory_requires_override(
    runner: &OpenShellRunner,
    sandbox: &str,
    remote_root: &str,
    local_root: &Path,
) -> Result<(), String> {
    let remote_seed = format!("{remote_root}/runs/test.json");
    exec(
        runner,
        sandbox,
        "gitignored-override/seed",
        &format!("mkdir -p '{remote_root}/runs' && printf downloaded-payload > '{remote_seed}'"),
    )
    .await?;

    let repository = local_root.join("override-repo");
    fs::create_dir(&repository).map_err(fs_error("create override repository"))?;
    git_init(&repository).await?;
    fs::write(repository.join(".gitignore"), "runs/\n")
        .map_err(fs_error("write override .gitignore"))?;
    let runs = repository.join("runs");
    fs::create_dir(&runs).map_err(fs_error("create ignored runs directory"))?;
    download(
        runner,
        sandbox,
        "gitignored-override/download-seed",
        &remote_seed,
        &runs,
    )
    .await?;
    require_exists(&runs.join("test.json"), "downloaded ignored file")?;

    let remote = format!("{remote_root}/reuploaded");
    let rejected = upload_result(
        runner,
        sandbox,
        "gitignored-override/reject-upload",
        &runs,
        &remote,
        false,
    )
    .await?;
    let output = format!("{}\n{}", rejected.stdout(), rejected.stderr());
    if rejected.success()
        || !output.contains("filtering selected no files")
        || !output.contains("--no-git-ignore")
    {
        return Err(rejected.failure_diagnostic(
            "upload rejects an empty Git selection and explains the explicit override",
        ));
    }
    exec(
        runner,
        sandbox,
        "gitignored-override/no-transfer",
        &format!("test ! -e '{remote}'"),
    )
    .await?;
    upload(
        runner,
        sandbox,
        "gitignored-override/upload",
        &runs,
        &remote,
        true,
    )
    .await?;

    let destination = local_root.join("override-download");
    fs::create_dir(&destination).map_err(fs_error("create override destination"))?;
    download(
        runner,
        sandbox,
        "gitignored-override/download",
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
        .description(format!("upload {source:?} to {destination:?}"))
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
