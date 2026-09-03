// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Context;
use directories::BaseDirs;
use tracing::info;

use crate::{cas_fetcher::CasFetcher, virtual_machine::VirtualMachineDefinition};

pub async fn run() -> anyhow::Result<()> {
    let contents = fs::read_to_string("config.yaml").context("failed to read config.yaml")?;
    let virtual_machines = crate::config::from_str(&contents)?;
    fetch_images(virtual_machines).await
}

async fn fetch_images(virtual_machines: Vec<VirtualMachineDefinition>) -> anyhow::Result<()> {
    let downloads = virtual_machines
        .into_iter()
        .inspect(|virtual_machine| {
            info!(machine = %virtual_machine.name, "scheduling downloads");
        })
        .flat_map(|virtual_machine| [virtual_machine.images.amd64, virtual_machine.images.arm64])
        .fold(HashMap::new(), |mut downloads, manifest| {
            downloads.entry(manifest.sha256).or_insert(manifest.url);
            downloads
        });

    let mut fetcher = CasFetcher::new(downloads_dir()?).await?;
    for (sha256, url) in downloads {
        fetcher.schedule(url, sha256);
    }

    fetcher.finish().await?;
    Ok(())
}

fn downloads_dir() -> anyhow::Result<PathBuf> {
    let base_dirs = BaseDirs::new().context("could not determine the user cache directory")?;
    Ok(base_dirs.cache_dir().join("machine").join("downloads"))
}
