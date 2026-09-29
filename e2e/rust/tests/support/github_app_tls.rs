// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only CA trust for the managed gateway's supervisor image.

use openshell_e2e::harness::{
    cli::wait_for_healthy, container::ImageGuard, gateway::ManagedGateway,
};
use std::path::PathBuf;
use std::time::Duration;

pub struct SupervisorTrust {
    config_path: PathBuf,
    original: String,
    // Drop the image only after restoring the gateway configuration.
    _image: ImageGuard,
}

impl SupervisorTrust {
    pub async fn install(ca_pem: &str) -> Result<Self, String> {
        let args_path = std::env::var("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .map_err(|_| "GitHub HTTPS fixture requires a harness-managed gateway".to_string())?;
        let raw = std::fs::read(&args_path).map_err(|e| e.to_string())?;
        let args: Vec<_> = raw.split(|b| *b == 0).collect();
        let config_path = args
            .windows(2)
            .find(|pair| pair[0] == b"--config")
            .map(|pair| PathBuf::from(String::from_utf8_lossy(pair[1]).into_owned()))
            .ok_or_else(|| "managed gateway has no --config".to_string())?;
        let original = std::fs::read_to_string(&config_path).map_err(|e| e.to_string())?;
        let line = original
            .lines()
            .find(|line| line.starts_with("supervisor_image = "))
            .ok_or_else(|| "managed Podman gateway has no supervisor_image".to_string())?;
        let base = line
            .trim_start_matches("supervisor_image = ")
            .trim_matches('"');
        let context = tempfile::tempdir().map_err(|e| e.to_string())?;
        std::fs::write(context.path().join("ca.crt"), ca_pem).map_err(|e| e.to_string())?;
        let dockerfile = context.path().join("Dockerfile");
        // The test supervisor trusts the fixture CA. TLS and hostname checks
        // remain enabled; the workload gets the normal supervisor trust bundle.
        std::fs::write(
            &dockerfile,
            format!("FROM {base}\nCOPY ca.crt /etc/ssl/certs/ca-certificates.crt\n"),
        )
        .map_err(|e| e.to_string())?;
        let image = ImageGuard::build("github-app-trust", &dockerfile, context.path())?;
        let updated = original.replace(line, &format!("supervisor_image = \"{}\"", image.tag()));
        let guard = Self {
            config_path,
            original,
            _image: image,
        };
        std::fs::write(&guard.config_path, updated).map_err(|e| e.to_string())?;
        restart().await?;
        Ok(guard)
    }

    pub async fn restore(self) -> Result<(), String> {
        std::fs::write(&self.config_path, &self.original).map_err(|e| e.to_string())?;
        restart().await?;
        Ok(())
    }
}

impl Drop for SupervisorTrust {
    fn drop(&mut self) {
        // Also restore on early returns or panics, before the image guard drops.
        if std::fs::read_to_string(&self.config_path).ok().as_ref() != Some(&self.original) {
            let _ = std::fs::write(&self.config_path, &self.original);
            if let Ok(Some(gateway)) = ManagedGateway::from_env() {
                let _ = gateway.stop();
                let _ = gateway.start();
            }
        }
    }
}

async fn restart() -> Result<(), String> {
    let gateway = ManagedGateway::from_env()?
        .ok_or_else(|| "GitHub HTTPS fixture requires a harness-managed gateway".to_string())?;
    gateway.stop()?;
    gateway.start()?;
    wait_for_healthy(Duration::from_secs(120)).await
}
