// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime backend abstraction for sandboxed process execution.
//!
//! OpenShell supports multiple isolation backends:
//!
//! - **Process** (default): Uses Linux kernel primitives (Landlock, seccomp,
//!   network namespaces) for isolation. Lightweight but Linux-only.
//!
//! - **BoxLite** (feature `boxlite`): Runs the agent inside a hardware-isolated
//!   lightweight VM via libkrun (KVM on Linux, Hypervisor.framework on macOS).
//!   Provides stronger isolation and cross-platform support.

mod process_backend;

#[cfg(feature = "boxlite")]
mod boxlite_backend;

pub use process_backend::ProcessBackend;

#[cfg(feature = "boxlite")]
pub use boxlite_backend::{BoxliteBackend, BoxliteProcess};

use crate::process::ProcessStatus;
use miette::Result;
use std::collections::HashMap;

/// Configuration for spawning a sandboxed process.
#[derive(Debug, Clone)]
pub struct SpawnConfig {
    pub program: String,
    pub args: Vec<String>,
    pub workdir: Option<String>,
    pub interactive: bool,
    pub env: HashMap<String, String>,
    /// Container image for VM-based backends. Ignored by the process backend.
    pub image: Option<String>,
}

/// A running sandboxed process, abstracting over different isolation backends.
pub enum SandboxedProcess {
    /// OS process with kernel-level isolation (Landlock, seccomp, netns).
    Process(crate::ProcessHandle),
    /// BoxLite VM with hardware-level isolation.
    #[cfg(feature = "boxlite")]
    Boxlite(BoxliteProcess),
}

impl SandboxedProcess {
    /// Get the process or VM identifier.
    #[must_use]
    pub fn id(&self) -> u32 {
        match self {
            Self::Process(h) => h.pid(),
            #[cfg(feature = "boxlite")]
            Self::Boxlite(b) => b.id(),
        }
    }

    /// Wait for the sandboxed process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if waiting fails.
    pub async fn wait(&mut self) -> std::io::Result<ProcessStatus> {
        match self {
            Self::Process(h) => h.wait().await,
            #[cfg(feature = "boxlite")]
            Self::Boxlite(b) => b.wait().await,
        }
    }

    /// Send a signal to the sandboxed process.
    ///
    /// # Errors
    ///
    /// Returns an error if the signal cannot be sent.
    pub fn signal(&self, sig: nix::sys::signal::Signal) -> Result<()> {
        match self {
            Self::Process(h) => h.signal(sig),
            #[cfg(feature = "boxlite")]
            Self::Boxlite(b) => b.signal(sig),
        }
    }

    /// Kill the sandboxed process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process cannot be killed.
    pub fn kill(&mut self) -> Result<()> {
        match self {
            Self::Process(h) => h.kill(),
            #[cfg(feature = "boxlite")]
            Self::Boxlite(b) => b.kill(),
        }
    }
}

/// Supported runtime backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeKind {
    /// OS process with kernel-level isolation (Landlock, seccomp, netns).
    #[default]
    Process,
    /// BoxLite VM with hardware-level isolation (KVM / Hypervisor.framework).
    #[cfg(feature = "boxlite")]
    Boxlite,
}

impl RuntimeKind {
    /// Parse a runtime kind from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a recognized runtime.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "process" | "linux" => Ok(Self::Process),
            #[cfg(feature = "boxlite")]
            "boxlite" | "vm" => Ok(Self::Boxlite),
            #[cfg(not(feature = "boxlite"))]
            "boxlite" | "vm" => Err(miette::miette!(
                "BoxLite runtime requested but the 'boxlite' feature is not enabled. \
                 Rebuild with `--features boxlite`."
            )),
            other => Err(miette::miette!("Unknown runtime backend: {other}")),
        }
    }

    /// Whether this backend provides its own network isolation,
    /// making kernel-level network namespaces unnecessary.
    #[must_use]
    pub const fn provides_network_isolation(self) -> bool {
        match self {
            Self::Process => false,
            #[cfg(feature = "boxlite")]
            Self::Boxlite => true,
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Process => "process",
            #[cfg(feature = "boxlite")]
            Self::Boxlite => "boxlite",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_process_variants() {
        assert_eq!(RuntimeKind::parse("process").unwrap(), RuntimeKind::Process);
        assert_eq!(RuntimeKind::parse("linux").unwrap(), RuntimeKind::Process);
    }

    #[test]
    fn parse_unknown_returns_error() {
        assert!(RuntimeKind::parse("unknown").is_err());
    }

    #[cfg(feature = "boxlite")]
    #[test]
    fn parse_boxlite_variants() {
        assert_eq!(RuntimeKind::parse("boxlite").unwrap(), RuntimeKind::Boxlite);
        assert_eq!(RuntimeKind::parse("vm").unwrap(), RuntimeKind::Boxlite);
    }

    #[cfg(not(feature = "boxlite"))]
    #[test]
    fn parse_boxlite_without_feature_returns_error() {
        let err = RuntimeKind::parse("boxlite").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("feature"), "expected feature error: {msg}");
    }

    #[test]
    fn default_is_process() {
        assert_eq!(RuntimeKind::default(), RuntimeKind::Process);
    }

    #[test]
    fn process_does_not_provide_network_isolation() {
        assert!(!RuntimeKind::Process.provides_network_isolation());
    }
}
