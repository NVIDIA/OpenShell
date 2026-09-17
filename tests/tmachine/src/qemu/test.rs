// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use tempfile::tempdir;

use crate::config::{Machine, Scenario, Testsuite};
use anyhow::Result;

use super::img::QemuImage;
use super::install::install;
use super::layer::run_playbooks;
use super::vm::QemuVm;

pub async fn test(machine: &Machine, scenario: &Scenario, testsuite: &Testsuite) -> Result<()> {
    let install_disk = install(machine, scenario).await?;
    let test_dir = tempdir().unwrap();
    let test_disk = test_dir.path().join("test.qcow2");
    let image = QemuImage::create(&install_disk, test_disk).await;
    let vm = QemuVm::start(&image).await;

    run_playbooks(&testsuite.playbooks, &testsuite.inputs).await?;

    vm.shutdown().await;
    vm.wait().await;
    Ok(())
}
