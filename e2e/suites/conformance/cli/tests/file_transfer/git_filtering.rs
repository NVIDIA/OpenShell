// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::helpers::{
    delete_sandbox, download, exec, fs_error, git, git_init, prepare_sandbox, require_absent,
    require_exists, require_text, upload, upload_result,
};
use openshell_e2e_support::OpenShellRunner;
use std::fs;
use std::path::Path;

/// Verify Git-aware upload selection and explicit unfiltered uploads.
#[tokio::test]
async fn respects_git_selection_and_explicit_override() {
    let mut runner = OpenShellRunner::from_env("file-transfer/git-filtering")
        .expect("candidate openshell CLI is available");
    let result = async {
        runner.check_gateway_status().await?;
        let runner = &mut runner;
        let (sandbox_name, remote_root, local) = prepare_sandbox(runner, "git-filtering").await?;
        gitignore_filtering(runner, &sandbox_name, &remote_root, local.path()).await?;
        single_file_from_git_repo(runner, &sandbox_name, &remote_root, local.path()).await?;
        gitignored_directory_requires_override(runner, &sandbox_name, &remote_root, local.path())
            .await?;
        delete_sandbox(runner, &sandbox_name).await
    }
    .await;
    if let Err(error) = runner.finish(result).await {
        panic!("file-transfer/git-filtering conformance story failed:\n{error}");
    }
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
