// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: file-transfer.
//!
//! Upload and download exist only in the CLI, which moves files over the
//! sandbox's SSH session, so these tests act through `cx.cli`. They depend on
//! the supervisor, the sandbox image, and the driver's filesystem, which is
//! why they run in every environment.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;
use testkit::{CliOutput, Context, Error, Sandbox};

const LARGE_FILE_SIZE: usize = 512 * 1024;

/// Files and directories round-trip through upload and download unchanged,
/// uploads into existing directories land inside them, and downloads of
/// single files and directories reproduce them locally.
#[testkit::test(id = "t-ifeaivyq")]
async fn upload_download_round_trip(cx: &mut Context) -> testkit::Result {
    let ft = Transfer::new(cx, "fr").await?;
    ft.upload_into_existing_directories().await?;
    ft.round_trip().await?;
    ft.download_file().await?;
    ft.download_directory().await?;
    ft.sandbox.delete().await
}

/// Uploads from a Git work tree skip ignored files, a single file uploads
/// alone, and an upload whose selection is entirely ignored is rejected
/// unless `--no-git-ignore` is given.
#[testkit::test(id = "t-0no9ex2m")]
async fn upload_respects_gitignore(cx: &mut Context) -> testkit::Result {
    let ft = Transfer::new(cx, "fg").await?;
    ft.gitignore_filtering().await?;
    ft.single_file_from_git_repo().await?;
    ft.ignored_directory_requires_override().await?;
    ft.sandbox.delete().await
}

/// Downloads refuse sandbox paths that resolve outside the workspace, and
/// file names that look like command-line options download as plain files.
#[testkit::test(id = "t-9gr3oxym")]
async fn download_stays_inside_workspace(cx: &mut Context) -> testkit::Result {
    let ft = Transfer::new(cx, "fs").await?;
    ft.reject_workspace_escape().await?;
    ft.download_dash_leading_name().await?;
    ft.sandbox.delete().await
}

/// A sandbox, a directory in its workspace, and a local scratch directory.
struct Transfer<'a> {
    cx: &'a Context,
    sandbox: Sandbox,
    remote_root: String,
    local: TempDir,
}

impl<'a> Transfer<'a> {
    async fn new(cx: &'a Context, suffix: &str) -> testkit::Result<Self> {
        let sandbox = cx
            .sandbox(suffix)
            .command(["sleep", "infinity"])
            .create()
            .await?;
        sandbox.wait_ready().await?;
        let remote_root = format!("/sandbox/file-transfer-{}-{suffix}", cx.run_id());
        let local = tempfile::tempdir()
            .map_err(|error| Error::msg(format!("create a local scratch directory: {error}")))?;
        let ft = Self {
            cx,
            sandbox,
            remote_root,
            local,
        };
        ft.sh(&format!("mkdir -p '{}'", ft.remote_root)).await?;
        Ok(ft)
    }

    fn local(&self, name: &str) -> PathBuf {
        self.local.path().join(name)
    }

    /// Run a shell script in the sandbox and require it to succeed.
    async fn sh(&self, script: &str) -> testkit::Result {
        let output = self.sandbox.exec(["sh", "-c", script]).await?;
        testkit::ensure!(
            output.exit_code == 0,
            "`{script}` exited with {}; stderr: {}",
            output.exit_code,
            output.stderr
        );
        Ok(())
    }

    async fn upload(
        &self,
        source: &Path,
        destination: &str,
        no_git_ignore: bool,
    ) -> testkit::Result<CliOutput> {
        let mut args = vec![
            "sandbox".to_string(),
            "upload".to_string(),
            self.sandbox.name().to_string(),
            source.display().to_string(),
            destination.to_string(),
        ];
        if no_git_ignore {
            args.push("--no-git-ignore".to_string());
        }
        self.cx.cli(args).await
    }

    async fn download(&self, source: &str, destination: &Path) -> testkit::Result<CliOutput> {
        self.cx
            .cli([
                "sandbox",
                "download",
                self.sandbox.name(),
                source,
                &destination.display().to_string(),
            ])
            .await
    }

    /// Upload into existing directories, including a symlink to one and one
    /// named with a trailing slash; the file must land inside each. Check the
    /// destination's type, not only the exit status: tar can succeed after
    /// replacing an empty directory with a file.
    async fn upload_into_existing_directories(&self) -> testkit::Result {
        let source = self.local("config.json");
        write(&source, "upload-destination-payload")?;
        let root = format!("{}/upload destinations", self.remote_root);
        self.sh(&format!(
            "mkdir -p '{root}/empty' '{root}/populated' '{root}/target' '{root}/slash' && \
             printf keep > '{root}/populated/keep.txt' && \
             ln -s target '{root}/link'"
        ))
        .await?;

        for directory in ["empty", "populated", "link", "slash/"] {
            let destination = format!("{root}/{directory}");
            self.upload(&source, &destination, true).await?.success()?;
            self.sh(&format!(
                "test -d '{destination}' && \
                 test \"$(cat '{destination}/config.json')\" = upload-destination-payload && \
                 test \"$(cat '{root}/populated/keep.txt')\" = keep && \
                 test -L '{root}/link'"
            ))
            .await?;
        }

        // A missing destination is a rename; uploading again must replace
        // that file rather than treat it as a directory.
        let renamed = format!("{root}/renamed.json");
        for _ in ["rename", "overwrite"] {
            self.upload(&source, &renamed, true).await?.success()?;
            self.sh(&format!(
                "test -f '{renamed}' && test \"$(cat '{renamed}')\" = upload-destination-payload"
            ))
            .await?;
        }
        Ok(())
    }

    /// A directory with a nested file and a large binary file, and a single
    /// file, survive upload then download.
    async fn round_trip(&self) -> testkit::Result {
        let source = self.local("roundtrip-upload");
        create_dir_all(&source.join("subdir"))?;
        write(&source.join("greeting.txt"), "hello-from-local")?;
        write(&source.join("subdir/nested.txt"), "nested-content")?;
        let large: Vec<u8> = (0u8..=250).cycle().take(LARGE_FILE_SIZE).collect();
        fs::write(source.join("large.bin"), &large)
            .map_err(|error| Error::msg(format!("write large.bin: {error}")))?;

        let remote = format!("{}/roundtrip", self.remote_root);
        let uploaded = self.upload(&source, &remote, false).await?.success()?;
        let warning = message(&uploaded);
        testkit::ensure!(
            warning.contains("outside a Git work tree")
                && warning.contains(".gitignore rules are not applied"),
            "upload outside a Git work tree did not warn that filtering is off: {warning}"
        );

        let destination = self.local("roundtrip-download");
        create_dir_all(&destination)?;
        self.download(&format!("{remote}/roundtrip-upload"), &destination)
            .await?
            .success()?;
        require_text(&destination.join("greeting.txt"), "hello-from-local")?;
        require_text(&destination.join("subdir/nested.txt"), "nested-content")?;
        let actual = fs::read(destination.join("large.bin"))
            .map_err(|error| Error::msg(format!("read large.bin: {error}")))?;
        testkit::ensure!(
            actual == large,
            "large file changed in the round trip: sent {} bytes, received {}",
            large.len(),
            actual.len()
        );

        let single = self.local("single.txt");
        write(&single, "single-file-payload")?;
        let remote_single = format!("{}/single.txt", self.remote_root);
        self.upload(&single, &remote_single, false)
            .await?
            .success()?;
        let single_destination = self.local("single-download");
        create_dir_all(&single_destination)?;
        self.download(&remote_single, &single_destination)
            .await?
            .success()?;
        require_text(
            &single_destination.join("single.txt"),
            "single-file-payload",
        )
    }

    async fn download_file(&self) -> testkit::Result {
        let remote = format!("{}/download-file.txt", self.remote_root);
        self.sh(&format!("printf greeting-payload > '{remote}'"))
            .await?;
        let destination = self.local("download-file");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        require_text(&destination.join("download-file.txt"), "greeting-payload")
    }

    async fn download_directory(&self) -> testkit::Result {
        let remote = format!("{}/tree", self.remote_root);
        self.sh(&format!(
            "mkdir -p '{remote}/sub' && printf top-level > '{remote}/root.txt' && \
             printf nested > '{remote}/sub/child.txt'"
        ))
        .await?;
        let destination = self.local("download-directory");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        require_text(&destination.join("root.txt"), "top-level")?;
        require_text(&destination.join("sub/child.txt"), "nested")
    }

    async fn gitignore_filtering(&self) -> testkit::Result {
        let repository = self.local("filter-repo");
        create_dir_all(&repository.join("build"))?;
        git(&repository, &["init", "--quiet"])?;
        write(&repository.join(".gitignore"), "*.log\nbuild/\n")?;
        write(&repository.join("tracked.txt"), "i-am-tracked")?;
        write(&repository.join("ignored.log"), "i-should-be-filtered")?;
        write(&repository.join("build/output.bin"), "build-artifact")?;
        git(&repository, &["add", "."])?;

        let remote = format!("{}/filtered", self.remote_root);
        self.upload(&repository, &remote, false).await?.success()?;
        let destination = self.local("filter-download");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        let uploaded = destination.join("filter-repo");
        require_text(&uploaded.join("tracked.txt"), "i-am-tracked")?;
        require_exists(&uploaded.join(".gitignore"))?;
        require_absent(&uploaded.join("ignored.log"))?;
        require_absent(&uploaded.join("build"))
    }

    async fn single_file_from_git_repo(&self) -> testkit::Result {
        let repository = self.local("single-repo");
        create_dir_all(&repository.join("nested"))?;
        git(&repository, &["init", "--quiet"])?;
        write(&repository.join(".gitignore"), "*.log\n")?;
        write(
            &repository.join("nested/config.txt"),
            "single-file-from-repo",
        )?;
        write(&repository.join("tracked.txt"), "should-not-upload")?;
        write(&repository.join("ignored.log"), "ignored")?;

        let remote = format!("{}/single-from-repo", self.remote_root);
        self.upload(&repository.join("nested/config.txt"), &remote, false)
            .await?
            .success()?;
        let destination = self.local("single-repo-download");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        require_text(&destination.join("config.txt"), "single-file-from-repo")?;
        require_absent(&destination.join("tracked.txt"))?;
        require_absent(&destination.join("ignored.log"))
    }

    async fn ignored_directory_requires_override(&self) -> testkit::Result {
        let remote_seed = format!("{}/runs/test.json", self.remote_root);
        self.sh(&format!(
            "mkdir -p '{}/runs' && printf downloaded-payload > '{remote_seed}'",
            self.remote_root
        ))
        .await?;

        let repository = self.local("override-repo");
        let runs = repository.join("runs");
        create_dir_all(&runs)?;
        git(&repository, &["init", "--quiet"])?;
        write(&repository.join(".gitignore"), "runs/\n")?;
        self.download(&remote_seed, &runs).await?.success()?;
        require_exists(&runs.join("test.json"))?;

        let remote = format!("{}/reuploaded", self.remote_root);
        let rejected = self.upload(&runs, &remote, false).await?.failure()?;
        let output = message(&rejected);
        testkit::ensure!(
            output.contains("filtering selected no files") && output.contains("--no-git-ignore"),
            "the rejected upload did not explain the --no-git-ignore override: {output}"
        );
        self.sh(&format!("test ! -e '{remote}'")).await?;

        self.upload(&runs, &remote, true).await?.success()?;
        let destination = self.local("override-download");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        require_text(&destination.join("runs/test.json"), "downloaded-payload")
    }

    async fn reject_workspace_escape(&self) -> testkit::Result {
        let etc_link = format!("{}/etc-link", self.remote_root);
        let passwd_link = format!("{}/passwd-link", self.remote_root);
        self.sh(&format!(
            "ln -s /etc '{etc_link}' && ln -s /etc/passwd '{passwd_link}'"
        ))
        .await?;
        let destination = self.local("workspace-escape");
        create_dir_all(&destination)?;

        for source in [etc_link.clone(), passwd_link, format!("{etc_link}/passwd")] {
            let rejected = self.download(&source, &destination).await?.failure()?;
            let output = message(&rejected);
            testkit::ensure!(
                output.contains("resolves to")
                    && output.contains("outside the")
                    && output.contains("sandbox workspace"),
                "download of {source:?} was not rejected as outside the workspace: {output}"
            );
        }
        require_absent(&destination.join("passwd"))?;
        require_absent(&destination.join("etc-link"))
    }

    async fn download_dash_leading_name(&self) -> testkit::Result {
        let remote = format!("{}/--checkpoint-action=evil", self.remote_root);
        self.sh(&format!("printf dash-payload > '{remote}'"))
            .await?;
        let destination = self.local("dash-leading");
        create_dir_all(&destination)?;
        self.download(&remote, &destination).await?.success()?;
        require_text(
            &destination.join("--checkpoint-action=evil"),
            "dash-payload",
        )
    }
}

/// The CLI's stdout and stderr as one line of words. Error reports wrap to
/// the terminal width and draw a gutter, so match against this instead.
fn message(output: &CliOutput) -> String {
    format!("{} {}", output.stdout, output.stderr)
        .replace(['│', '×', '╰', '─', '╭', '├'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn git(repository: &Path, args: &[&str]) -> testkit::Result {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .map_err(|error| Error::msg(format!("run git {}: {error}", args.join(" "))))?;
    testkit::ensure!(
        output.status.success(),
        "git {} failed in {}: {}",
        args.join(" "),
        repository.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn write(path: &Path, contents: &str) -> testkit::Result {
    fs::write(path, contents)
        .map_err(|error| Error::msg(format!("write {}: {error}", path.display())))
}

fn create_dir_all(path: &Path) -> testkit::Result {
    fs::create_dir_all(path)
        .map_err(|error| Error::msg(format!("create {}: {error}", path.display())))
}

fn require_text(path: &Path, expected: &str) -> testkit::Result {
    let actual = fs::read_to_string(path)
        .map_err(|error| Error::msg(format!("read {}: {error}", path.display())))?;
    testkit::ensure!(
        actual == expected,
        "{} contains {actual:?}; expected {expected:?}",
        path.display()
    );
    Ok(())
}

fn require_exists(path: &Path) -> testkit::Result {
    testkit::ensure!(path.exists(), "{} does not exist", path.display());
    Ok(())
}

fn require_absent(path: &Path) -> testkit::Result {
    testkit::ensure!(!path.exists(), "{} exists but should not", path.display());
    Ok(())
}
