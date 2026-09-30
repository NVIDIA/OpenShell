// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Target-specific fixtures used by portable conformance scenarios.

use tempfile::TempDir;

#[cfg(unix)]
mod unix;
#[cfg(any(test, target_os = "windows"))]
mod windows;

#[cfg(unix)]
pub use unix::{
    file_transfer_fixture, increment_then_wait, keep_alive, lifecycle_fixture, marker_command,
    policy_fixture, read_text, restricted_network_policy_fixture, smoke_fixture, write_text,
};
#[cfg(target_os = "windows")]
pub use windows::{
    file_transfer_fixture, increment_then_wait, keep_alive, lifecycle_fixture, marker_command,
    policy_fixture, read_text, restricted_network_policy_fixture, smoke_fixture, write_text,
};

#[cfg(not(any(unix, target_os = "windows")))]
compile_error!("OpenShell conformance does not support this target platform");

/// One platform-specific command and its exact successful stdout.
pub struct CommandExpectation {
    argv: Vec<String>,
    expected_stdout: String,
}

impl CommandExpectation {
    fn new(argv: Vec<String>, expected_stdout: String) -> Self {
        Self {
            argv,
            expected_stdout,
        }
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn expected_stdout(&self) -> &str {
        &self.expected_stdout
    }
}

/// Writable sandbox location and create options for platform-neutral scenarios.
pub struct SandboxFixture {
    root: String,
    create_args: Vec<String>,
    // Keep generated policy and workload paths alive until the scenario ends.
    _temp_dir: Option<TempDir>,
}

impl SandboxFixture {
    fn new(root: String, create_args: Vec<String>, temp_dir: Option<TempDir>) -> Self {
        Self {
            root,
            create_args,
            _temp_dir: temp_dir,
        }
    }

    pub fn path(&self, name: &str) -> String {
        std::path::Path::new(&self.root)
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    pub fn create_args(&self) -> &[String] {
        &self.create_args
    }
}

/// Platform-specific inputs needed to keep a smoke-test sandbox alive.
pub struct SmokeFixture {
    create_args: Vec<String>,
    command: Option<Vec<String>>,
    // Keep generated policy and workload paths alive until the scenario ends.
    _temp_dir: Option<TempDir>,
}

impl SmokeFixture {
    fn new(
        create_args: Vec<String>,
        command: Option<Vec<String>>,
        temp_dir: Option<TempDir>,
    ) -> Self {
        Self {
            create_args,
            command,
            _temp_dir: temp_dir,
        }
    }

    pub fn create_args(&self) -> &[String] {
        &self.create_args
    }

    pub fn command(&self) -> Option<&[String]> {
        self.command.as_deref()
    }
}
