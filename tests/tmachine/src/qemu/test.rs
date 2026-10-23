// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::config::{Environment, Installer, Machine, Testsuite};

use super::session::Session;

pub async fn test(
    machine: &Machine,
    environment: &Environment,
    installer: &Installer,
    testsuite: &Testsuite,
) -> Result<()> {
    let session = Session::up(machine, environment, installer).await?;
    session
        .run_playbooks(&testsuite.playbooks, &testsuite.inputs)
        .await?;

    if testsuite.interactive {
        println!("Opening an SSH shell in the tmachine VM.");
        let ssh_status = session.shell().await;
        session.down().await;
        let ssh_status = ssh_status?;
        anyhow::ensure!(ssh_status.success(), "SSH shell exited with {ssh_status}");
        return Ok(());
    }

    session.down().await;
    Ok(())
}
