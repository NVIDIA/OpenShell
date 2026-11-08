// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! A provider profile serves read-only config on each workload open.

use std::io::Write as _;
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_bin;
use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::time::sleep;

struct ProviderGuard {
    profile: String,
    provider: String,
}

impl Drop for ProviderGuard {
    fn drop(&mut self) {
        let binary = openshell_bin();
        for _ in 0..20 {
            let deleted = std::process::Command::new(&binary)
                .args(["provider", "delete", &self.provider])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if deleted.is_ok_and(|status| status.success()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let _ = std::process::Command::new(&binary)
            .args(["profile", "delete", &self.profile])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

async fn cli_ok(args: &[&str]) -> Result<(), String> {
    let (output, code) = run_cli(args).await;
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} failed (exit {code}):\n{output}",
            args.join(" ")
        ))
    }
}

#[tokio::test]
async fn provider_file_open_update_and_detach() -> Result<(), String> {
    let suffix = format!("{}-{:08x}", std::process::id(), rand::random::<u32>());
    let profile_id = format!("pf-{suffix}");
    let provider = format!("pf-{suffix}");
    let profile_yaml = include_str!("../../../examples/provider-managed-files/acme-config.yaml")
        .replace("id: acme-config", &format!("id: {profile_id}"));
    let mut profile_file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| error.to_string())?;
    profile_file
        .write_all(profile_yaml.as_bytes())
        .map_err(|error| error.to_string())?;
    cli_ok(&[
        "profile",
        "import",
        "--file",
        profile_file
            .path()
            .to_str()
            .ok_or("profile path is not UTF-8")?,
    ])
    .await?;
    let _provider_guard = ProviderGuard {
        profile: profile_id.clone(),
        provider: provider.clone(),
    };
    cli_ok(&[
        "provider",
        "create",
        "--name",
        &provider,
        "--type",
        &profile_id,
        "--config",
        "endpoint=https://api.acme.example",
        "--config",
        "project=production",
    ])
    .await?;

    let mut sandbox = SandboxGuard::create(&["--provider", &provider, "--no-tty"]).await?;
    let path = format!("/run/openshell/providers/{provider}/client.toml");
    let environment_path = sandbox.exec(&["printenv", "ACME_CONFIG_FILE"]).await?;
    if !environment_path.contains(&path) {
        return Err(format!(
            "provider path environment variable missing: {environment_path}"
        ));
    }
    let before = sandbox.exec(&["cat", &path]).await?;
    if !before.contains("project = \"production\"") {
        return Err(format!("initial provider file content missing:\n{before}"));
    }
    let permissions = sandbox
        .exec(&[
            "sh",
            "-c",
            &format!(
                "set -eu; exec 3<{path}; test \"$(stat -Lc %a /proc/self/fd/3)\" = 600; \
                 test \"$(stat -Lc %F /proc/self/fd/3)\" = 'regular file'; \
                 if (printf x >&3) 2>/dev/null; then exit 1; fi; \
                 echo provider-file-permissions-ok"
            ),
        ])
        .await?;
    if !permissions.contains("provider-file-permissions-ok") {
        return Err(format!(
            "provider file permission assertion did not complete:\n{permissions}"
        ));
    }

    cli_ok(&[
        "provider",
        "update",
        &provider,
        "--config",
        "project=staging",
        "--wait",
        "--timeout",
        "90",
    ])
    .await?;
    let after = sandbox.exec(&["cat", &path]).await?;
    if !after.contains("project = \"staging\"") {
        return Err(format!("updated provider file content missing:\n{after}"));
    }

    cli_ok(&[
        "sandbox",
        "provider",
        "detach",
        &sandbox.name,
        &provider,
        "--wait",
        "--timeout",
        "90",
    ])
    .await?;
    let (detached, code) = run_cli(&[
        "sandbox",
        "exec",
        "--name",
        &sandbox.name,
        "--no-tty",
        "--",
        "cat",
        &path,
    ])
    .await;
    if code == 0 || !detached.contains("No such file or directory") {
        return Err(format!(
            "detached provider path remained readable: {detached}"
        ));
    }
    sandbox.cleanup().await;
    // Let the asynchronous sandbox deletion release the provider before
    // ProviderGuard removes the provider record and its profile.
    sleep(Duration::from_millis(250)).await;
    Ok(())
}
