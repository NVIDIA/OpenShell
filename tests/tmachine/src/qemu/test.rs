// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::process::Stdio;

use anyhow::{Context, Result};
use tempfile::tempdir;
use tokio::process::Command;

use crate::config::{Environment, Installer, Machine, Testsuite};

use super::img::QemuImage;
use super::install::install;
use super::layer::run_playbooks;
use super::vm::QemuVm;

pub async fn test(
    machine: &Machine,
    environment: &Environment,
    installer: &Installer,
    testsuite: &Testsuite,
) -> Result<()> {
    let install_disk = install(machine, environment, installer).await?;
    let test_dir = tempdir().unwrap();
    let test_disk = test_dir.path().join("test.qcow2");
    let image = QemuImage::create(&install_disk, test_disk).await;
    let vm = QemuVm::start(&image).await;

    run_playbooks(&testsuite.playbooks, &testsuite.inputs).await?;

    if testsuite.interactive {
        println!("Opening an SSH shell in the tmachine VM.");
        let ssh_status = Command::new("sshpass")
            .env("SSHPASS", "tmachine")
            .args([
                "-e",
                "ssh",
                "-tt",
                "-p",
                "2222",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "tmachine@127.0.0.1",
            ])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .context("open SSH shell in tmachine VM")?;

        vm.shutdown().await;
        vm.wait().await;
        anyhow::ensure!(ssh_status.success(), "SSH shell exited with {ssh_status}");
        return Ok(());
    }

    vm.shutdown().await;
    vm.wait().await;
    Ok(())
}
