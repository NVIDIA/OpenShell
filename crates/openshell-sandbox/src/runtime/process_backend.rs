// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process-based sandbox backend using Linux kernel isolation.
//!
//! This is the default backend. It spawns the agent as a direct OS process
//! and applies Landlock, seccomp, and network namespace isolation.

use crate::ProcessHandle;
use crate::policy::SandboxPolicy;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::netns::NetworkNamespace;
use miette::Result;
use std::collections::HashMap;
use std::path::PathBuf;

use super::SandboxedProcess;

/// Process-based sandbox backend.
///
/// Delegates to [`ProcessHandle::spawn`] with kernel-level isolation.
pub struct ProcessBackend;

impl ProcessBackend {
    /// Spawn a sandboxed process using OS-level isolation.
    ///
    /// # Errors
    ///
    /// Returns an error if the process fails to start.
    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        netns: Option<&NetworkNamespace>,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<SandboxedProcess> {
        let handle = ProcessHandle::spawn(
            program,
            args,
            workdir,
            interactive,
            policy,
            netns,
            ca_paths,
            provider_env,
        )?;
        Ok(SandboxedProcess::Process(handle))
    }

    /// Spawn a sandboxed process (non-Linux fallback).
    ///
    /// # Errors
    ///
    /// Returns an error if the process fails to start.
    #[cfg(not(target_os = "linux"))]
    pub fn spawn(
        program: &str,
        args: &[String],
        workdir: Option<&str>,
        interactive: bool,
        policy: &SandboxPolicy,
        ca_paths: Option<&(PathBuf, PathBuf)>,
        provider_env: &HashMap<String, String>,
    ) -> Result<SandboxedProcess> {
        let handle = ProcessHandle::spawn(
            program,
            args,
            workdir,
            interactive,
            policy,
            ca_paths,
            provider_env,
        )?;
        Ok(SandboxedProcess::Process(handle))
    }
}
