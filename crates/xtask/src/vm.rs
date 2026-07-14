// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::ExitStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestOs {
    pub distribution: &'static str,
    pub version: &'static str,
}

impl GuestOs {
    pub const fn new(distribution: &'static str, version: &'static str) -> Self {
        Self {
            distribution,
            version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeDriver {
    PodmanRootless,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmSpec {
    pub guest_os: GuestOs,
    pub arch: Arch,
    pub compute_driver: ComputeDriver,
}

#[derive(Debug, Clone, Copy)]
pub struct ProvisionOptions {
    pub snapshot: bool,
    pub rebuild: bool,
}

pub trait VmProvider {
    type Instance: VmInstance;

    fn provision(
        &self,
        spec: VmSpec,
        options: ProvisionOptions,
        setup_script: &str,
    ) -> Result<Self::Instance, String>;
}

pub trait VmInstance {
    fn name(&self) -> &str;

    fn copy_file(&self, source: &Path, destination: &str) -> Result<(), String>;

    fn run_script(&self, script: &str, description: &str) -> Result<ExitStatus, String>;

    fn cleanup(&self) -> Result<(), String>;
}
