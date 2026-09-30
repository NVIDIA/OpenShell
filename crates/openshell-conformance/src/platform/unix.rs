// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use super::{CommandExpectation, SandboxFixture, SmokeFixture};

// Match the fallible Windows fixture constructor behind the platform boundary.
#[allow(clippy::unnecessary_wraps)]
pub fn smoke_fixture() -> Result<SmokeFixture, String> {
    // Unix runtimes resolve their image-appropriate default shell when the
    // canonical command is empty, so the smoke scenario needs no override.
    Ok(SmokeFixture::new(Vec::new(), None, None))
}

pub fn marker_command(marker: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec!["echo".to_string(), marker.to_string()],
        format!("{marker}\n"),
    )
}

// Match the fallible Windows fixture constructor behind the platform boundary.
#[allow(clippy::unnecessary_wraps)]
pub fn lifecycle_fixture() -> Result<SandboxFixture, String> {
    Ok(SandboxFixture::new(
        "/sandbox".to_string(),
        Vec::new(),
        None,
    ))
}

pub fn file_transfer_fixture() -> Result<SandboxFixture, String> {
    lifecycle_fixture()
}

pub fn policy_fixture() -> Result<SandboxFixture, String> {
    lifecycle_fixture()
}

pub fn restricted_network_policy_fixture() -> Result<SandboxFixture, String> {
    let temp_dir = tempfile::Builder::new()
        .prefix("openshell-conformance-policy-")
        .tempdir()
        .map_err(|error| format!("create Unix policy fixture directory: {error}"))?;
    let policy_path = temp_dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "version: 1\nfilesystem_policy:\n  include_workdir: true\n  read_only: [/usr, /bin, /lib, /lib64, /proc, /dev/urandom, /app, /etc, /var/log]\n  read_write: [/sandbox, /tmp, /dev/null]\nlandlock: { compatibility: best_effort }\nnetwork_policies: {}\n",
    )
    .map_err(|error| format!("write Unix conformance policy: {error}"))?;
    Ok(SandboxFixture::new(
        "/sandbox".to_string(),
        vec![
            "--policy".to_string(),
            policy_path.to_string_lossy().into_owned(),
        ],
        Some(temp_dir),
    ))
}

pub fn keep_alive(_fixture: &SandboxFixture) -> Vec<String> {
    vec![
        "sh".to_string(),
        "-lc".to_string(),
        "exec sleep infinity".to_string(),
    ]
}

pub fn increment_then_wait(path: &str) -> Vec<String> {
    let path = shell_quote(path);
    vec![
        "sh".to_string(),
        "-lc".to_string(),
        format!(
            "count=0; test ! -f {path} || count=$(cat {path}); \
             count=$((count + 1)); printf '%s\\n' \"$count\" > {path}; \
             exec sleep infinity"
        ),
    ]
}

pub fn write_text(path: &str, value: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec![
            "sh".to_string(),
            "-lc".to_string(),
            format!(
                "printf '%s\\n' {} > {} && sync",
                shell_quote(value),
                shell_quote(path)
            ),
        ],
        String::new(),
    )
}

pub fn read_text(path: &str, value: &str) -> CommandExpectation {
    CommandExpectation::new(
        vec!["cat".to_string(), path.to_string()],
        format!("{value}\n"),
    )
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_fixture_uses_the_runtime_default_workload() {
        let fixture = smoke_fixture().unwrap();
        assert!(fixture.create_args().is_empty());
        assert!(fixture.command().is_none());
    }

    #[test]
    fn lifecycle_commands_use_unix_tools() {
        let fixture = lifecycle_fixture().unwrap();
        let path = fixture.path("sentinel");
        assert_eq!(path, "/sandbox/sentinel");
        assert_eq!(keep_alive(&fixture)[0], "sh");
        assert_eq!(write_text(&path, "value").expected_stdout(), "");
        assert_eq!(read_text(&path, "value").expected_stdout(), "value\n");
    }

    #[test]
    fn restricted_network_policy_fixture_adds_an_empty_network_policy() {
        let fixture = restricted_network_policy_fixture().unwrap();
        let policy = fs::read_to_string(&fixture.create_args()[1]).unwrap();
        assert!(policy.contains("network_policies: {}"));
        assert!(policy.contains("read_write: [/sandbox, /tmp, /dev/null]"));
    }
}
