// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
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
    if environment.ephemeral {
        return test_ephemeral(machine, environment, installer, testsuite).await;
    }
    let install_disk = install(machine, environment, installer).await?;
    let test_dir = tempdir().unwrap();
    let test_disk = test_dir.path().join("test.qcow2");
    let image = QemuImage::create(&install_disk, test_disk).await;
    let vm = QemuVm::start(&image).await;

    let result = run_playbooks(
        &testsuite.playbooks,
        &testsuite.inputs,
        &environment.variables,
    )
    .await;
    if let Err(error) = result {
        vm.stop().await?;
        return Err(error);
    }

    if testsuite.interactive {
        let shell_result = open_shell().await;
        vm.stop().await?;
        return shell_result;
    }

    vm.stop().await?;
    Ok(())
}

async fn test_ephemeral(
    machine: &Machine,
    environment: &Environment,
    installer: &Installer,
    testsuite: &Testsuite,
) -> Result<()> {
    let run_dir = tempdir().context("create disposable tmachine run directory")?;
    let image = QemuImage::create(&machine.base_image, run_dir.path().join("run.qcow2")).await;
    let vm = QemuVm::start(&image).await;
    let run = async {
        if environment.setup.use_galaxy || installer.use_galaxy {
            crate::ansible::install_roles().await;
        }
        run_playbooks(
            &environment.setup.playbooks,
            &BTreeMap::new(),
            &environment.variables,
        )
        .await
        .context("prepare ephemeral environment")?;
        run_playbooks(
            &installer.playbooks,
            &installer.inputs,
            &environment.variables,
        )
        .await
        .context("install in ephemeral environment")?;
        run_playbooks(
            &testsuite.playbooks,
            &testsuite.inputs,
            &environment.variables,
        )
        .await
        .context("run ephemeral testsuite")?;
        if testsuite.interactive {
            open_shell().await?;
        }
        Ok(())
    };
    let result = tokio::select! {
        result = run => result,
        result = wait_for_interrupt() => {
            Err(result.err().unwrap_or_else(|| anyhow::anyhow!("tmachine run interrupted")))
        }
    };
    if result.is_err() {
        let diagnostics = std::path::Path::new("ansible/playbooks/diagnostics/k3s.yaml");
        if let Err(error) = tokio::time::timeout(
            std::time::Duration::from_secs(90),
            crate::ansible::collect_diagnostics(diagnostics, &environment.variables),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("diagnostics timed out")))
        {
            eprintln!("failed to collect k3s diagnostics: {error:#}");
        }
    }
    let cleanup = vm.stop().await;
    cleanup.context("stop disposable tmachine guest")?;
    result
}

async fn wait_for_interrupt() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("register SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("wait for SIGINT")?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

async fn open_shell() -> Result<()> {
    println!("Opening an SSH shell in the tmachine VM.");
    let mut command = Command::new("sshpass");
    command
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
        .stderr(Stdio::inherit());
    command.kill_on_drop(true);
    let ssh_status = command
        .status()
        .await
        .context("open SSH shell in tmachine VM")?;
    anyhow::ensure!(ssh_status.success(), "SSH shell exited with {ssh_status}");
    Ok(())
}
