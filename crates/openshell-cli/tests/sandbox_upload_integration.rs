// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output};

fn run_upload(
    local_path: &Path,
    config_dir: &Path,
    path: Option<&OsStr>,
    git_marker: Option<&Path>,
    no_git_ignore: bool,
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args([
            "--gateway",
            "test-gateway",
            "--gateway-endpoint",
            "http://127.0.0.1:0",
            "sandbox",
            "upload",
            "test-sandbox",
        ])
        .arg(local_path)
        .arg("/sandbox/uploaded")
        .current_dir(config_dir)
        .env("XDG_CONFIG_HOME", config_dir)
        .env("NO_COLOR", "1");

    if no_git_ignore {
        command.arg("--no-git-ignore");
    }

    if let Some(path) = path {
        command.env("PATH", path);
    }
    if let Some(marker) = git_marker {
        command.env("OPENSHELL_TEST_GIT_MARKER", marker);
    }

    command.output().expect("run openshell sandbox upload")
}

#[test]
fn sandbox_upload_command_filters_bare_relative_filenames() {
    let repo = tempfile::tempdir().expect("create repository");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .current_dir(repo.path())
            .status()
            .expect("initialize repository")
            .success()
    );
    fs::write(repo.path().join("keep.txt"), "keep").expect("write included file");
    fs::write(repo.path().join("skip.log"), "skip").expect("write ignored file");
    fs::write(repo.path().join(".gitignore"), "*.log\n").expect("write .gitignore");

    for path in ["keep.txt", "./keep.txt"] {
        let output = run_upload(Path::new(path), repo.path(), None, None, false);
        assert_reached_transport(&output);
    }
    for path in ["skip.log", "./skip.log"] {
        let output = run_upload(Path::new(path), repo.path(), None, None, false);
        assert_filtering_stopped(&output, "filtering selected no files");
    }
}

#[test]
fn sandbox_upload_command_accepts_dangling_symlink_preflight() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let link = tmpdir.path().join("dangling-link");
    symlink("missing-target", &link).expect("create dangling symlink");

    let output = run_upload(&link, tmpdir.path(), None, None, false);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "the test gateway is unreachable");
    assert!(
        stderr.contains("Uploading "),
        "dangling symlink should pass local preflight before the gateway error: {stderr}"
    );
    assert!(
        !stderr.contains("local path does not exist"),
        "dangling symlink was rejected as missing: {stderr}"
    );
}

#[test]
fn sandbox_upload_command_skips_git_filtering_for_symlink_source() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let repo = tmpdir.path().join("repo");
    fs::create_dir(&repo).expect("create repo");
    let git_status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("run git init");
    assert!(git_status.success(), "git init failed");

    let target = repo.join("real-dir");
    fs::create_dir(&target).expect("create symlink target");
    fs::write(target.join("file.txt"), "hello").expect("write target file");
    let link = repo.join("link-dir");
    symlink("real-dir", &link).expect("create symlink");

    let fake_bin = tmpdir.path().join("bin");
    fs::create_dir(&fake_bin).expect("create fake bin directory");
    let fake_git = fake_bin.join("git");
    fs::write(
        &fake_git,
        "#!/bin/sh\n: > \"$OPENSHELL_TEST_GIT_MARKER\"\nexit 1\n",
    )
    .expect("write fake git");
    let mut permissions = fs::metadata(&fake_git)
        .expect("stat fake git")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_git, permissions).expect("make fake git executable");

    let marker = tmpdir.path().join("git-invoked");
    let mut path_entries = vec![fake_bin];
    if let Some(current_path) = std::env::var_os("PATH") {
        path_entries.extend(std::env::split_paths(&current_path));
    }
    let path = std::env::join_paths(path_entries).expect("build test PATH");

    let output = run_upload(&link, tmpdir.path(), Some(&path), Some(&marker), false);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "the test gateway is unreachable");
    assert!(
        stderr.contains("Uploading "),
        "symlink should reach the upload transport: {stderr}"
    );
    assert!(
        !marker.exists(),
        "standalone sandbox upload invoked Git-aware filtering for a symlink source"
    );
}

#[test]
fn sandbox_upload_command_stops_when_git_is_unavailable() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let source = tmpdir.path().join("source");
    fs::create_dir(&source).expect("create source");
    fs::write(source.join("file.txt"), "hello").expect("write file");
    let empty_bin = tmpdir.path().join("bin");
    fs::create_dir(&empty_bin).expect("create empty PATH directory");

    let output = run_upload(
        &source,
        tmpdir.path(),
        Some(empty_bin.as_os_str()),
        None,
        false,
    );
    assert_filtering_stopped(&output, "failed to run git rev-parse");

    let output = run_upload(
        &source,
        tmpdir.path(),
        Some(empty_bin.as_os_str()),
        None,
        true,
    );
    assert_reached_transport(&output);
}

#[test]
fn sandbox_upload_command_warns_outside_git_repository() {
    let source = tempfile::tempdir().expect("create source");
    fs::create_dir(source.path().join("nested")).expect("create nested directory");
    fs::write(source.path().join(".gitignore"), ".env\n").expect("write ignore rules");
    fs::write(source.path().join("nested/.env"), "dummy").expect("write ignored name");

    for path in [".", "nested", "nested/.env"] {
        let output = run_upload(Path::new(path), source.path(), None, None, false);
        assert_reached_transport(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("outside a Git work tree"), "{stderr}");
        assert!(
            stderr.contains(".gitignore rules are not applied"),
            "{stderr}"
        );
    }
    let output = run_upload(source.path(), source.path(), None, None, true);
    assert_reached_transport(&output);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Warning:"));
}

#[test]
fn sandbox_upload_command_rejects_broken_repository_markers_in_ancestors() {
    let source = tempfile::tempdir().expect("create source");
    let nested = source.path().join("nested");
    fs::create_dir(&nested).expect("create nested directory");
    fs::write(nested.join(".env"), "dummy").expect("write file");
    let marker = source.path().join(".git");

    // Git reports the same "not a git repository" error for an empty .git
    // directory and a source that has never been a repository.
    fs::create_dir(&marker).expect("create corrupt repository");
    let output = run_upload(&nested, source.path(), None, None, false);
    assert_filtering_stopped(&output, "existing .git entry");
    fs::remove_dir(&marker).expect("remove corrupt repository");

    for contents in [
        "invalid gitfile\n",
        "gitdir: /nonexistent/openshell-test-gitdir\n",
    ] {
        fs::write(&marker, contents).expect("write invalid gitfile");
        let output = run_upload(&nested, source.path(), None, None, false);
        assert_filtering_stopped(&output, "Git filtering failed");
    }
    fs::remove_file(&marker).expect("remove gitfile");
    symlink("missing-git-dir", &marker).expect("create dangling repository marker");
    let output = run_upload(&nested, source.path(), None, None, false);
    assert_filtering_stopped(&output, "existing .git entry");

    let output = run_upload(&nested, source.path(), None, None, true);
    assert_reached_transport(&output);
}

#[test]
fn sandbox_upload_command_rejects_unreadable_repository() {
    let source = tempfile::tempdir().expect("create source");
    let marker = source.path().join(".git");
    fs::create_dir(&marker).expect("create repository marker");
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o000)).expect("deny access");
    let output = run_upload(source.path(), source.path(), None, None, false);
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o700)).expect("restore access");
    assert_filtering_stopped(&output, "Git filtering failed");
}

#[test]
fn sandbox_upload_command_rejects_bare_repository() {
    let source = tempfile::tempdir().expect("create source");
    assert!(
        Command::new("git")
            .args(["init", "--bare", "-q"])
            .current_dir(source.path())
            .status()
            .expect("create bare repository")
            .success()
    );
    let output = run_upload(source.path(), source.path(), None, None, false);
    assert_filtering_stopped(&output, "Git filtering failed");
}

#[test]
fn sandbox_upload_command_stops_on_git_failures_and_empty_selection() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let source = tmpdir.path().join("source");
    fs::create_dir(&source).expect("create source");
    fs::write(source.join("file.txt"), "hello").expect("write file");
    let bin = tmpdir.path().join("bin");
    fs::create_dir(&bin).expect("create fake PATH directory");
    let fake_git = bin.join("git");
    let marker = tmpdir.path().join("git-invoked");

    for (script, expected_error) in [
        ("exit 17\n", "git rev-parse --show-toplevel failed"),
        ("exit 128\n", "git rev-parse --show-toplevel failed"),
        (
            "echo 'fatal: detected dubious ownership in repository' >&2; exit 128\n",
            "git rev-parse --show-toplevel failed",
        ),
        (
            "if [ \"$1\" = rev-parse ]; then pwd; else exit 18; fi\n",
            "git ls-files failed",
        ),
        (
            "if [ \"$1\" = rev-parse ]; then pwd; fi\n",
            "filtering selected no files",
        ),
    ] {
        fs::write(
            &fake_git,
            format!("#!/bin/sh\n: > \"$OPENSHELL_TEST_GIT_MARKER\"\n{script}"),
        )
        .expect("write fake git");
        fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o755))
            .expect("make fake git executable");
        let output = run_upload(
            &source,
            tmpdir.path(),
            Some(bin.as_os_str()),
            Some(&marker),
            false,
        );
        assert_filtering_stopped(&output, expected_error);
        assert!(marker.exists(), "Git filtering should have been attempted");
        fs::remove_file(&marker).expect("remove invocation marker");

        let output = run_upload(
            &source,
            tmpdir.path(),
            Some(bin.as_os_str()),
            Some(&marker),
            true,
        );
        assert_reached_transport(&output);
        assert!(!marker.exists(), "explicit override must not invoke Git");
    }
}

fn assert_filtering_stopped(output: &Output, expected_error: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "filtering must stop the upload");
    assert!(stderr.contains(expected_error), "{stderr}");
    assert!(stderr.contains("--no-git-ignore"), "{stderr}");
    assert!(
        !stderr.contains("Uploading "),
        "transport started: {stderr}"
    );
}

fn assert_reached_transport(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the test gateway is unreachable");
    assert!(stderr.contains("Uploading "), "{stderr}");
    assert!(!stderr.contains("upload stopped"), "{stderr}");
}
