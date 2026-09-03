// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use reqwest::Client;
use sha2::{Digest, Sha256, digest::Output};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
    task::{JoinError, JoinSet},
};
use tracing::info;
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("HTTP request failed")]
    Http(#[from] reqwest::Error),

    #[error("download task failed")]
    Task(#[from] JoinError),

    #[error("SHA-256 mismatch for {url}: expected {expected}, got {actual}")]
    Sha256Mismatch {
        url: String,
        expected: String,
        actual: String,
    },
}

pub struct CasFetcher {
    client: Client,
    downloads_dir: PathBuf,
    tasks: JoinSet<Result<PathBuf, Error>>,
}

impl CasFetcher {
    pub async fn new(downloads_dir: PathBuf) -> Result<Self, Error> {
        fs::create_dir_all(&downloads_dir).await?;

        Ok(Self {
            client: Client::builder().build()?,
            downloads_dir,
            tasks: JoinSet::new(),
        })
    }

    pub fn schedule(&mut self, url: Url, expected_sha256: Output<Sha256>) {
        let client = self.client.clone();
        let target = self.downloads_dir.join(hex::encode(expected_sha256));

        self.tasks.spawn(async move {
            if fs::try_exists(&target).await? {
                info!(path = %target.display(), "download already exists");
                return Ok(target);
            }

            fetch(&client, target, url, expected_sha256).await
        });
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        let mut first_error = None;

        while let Some(result) = self.tasks.join_next().await {
            let result = result.map_err(Error::from).and_then(|result| result);
            if first_error.is_none() {
                first_error = result.err();
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

async fn fetch(
    client: &Client,
    target: PathBuf,
    url: Url,
    expected_sha256: Output<Sha256>,
) -> Result<PathBuf, Error> {
    let digest = hex::encode(expected_sha256);
    let partial = target.with_file_name(format!("{digest}.part"));

    info!(url = %url, "downloading");

    let mut response = client.get(url.clone()).send().await?.error_for_status()?;
    // TODO: Remove stale partial downloads when initializing the cache.
    // TODO: Coordinate concurrent processes before writing the same digest.
    let mut file = File::create(&partial).await?;
    let mut hasher = Sha256::new();

    while let Some(chunk) = response.chunk().await? {
        hasher.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;

    let actual_sha256 = hasher.finalize();
    if actual_sha256 != expected_sha256 {
        return Err(Error::Sha256Mismatch {
            url: url.into(),
            expected: digest,
            actual: hex::encode(actual_sha256),
        });
    }

    fs::rename(&partial, &target).await?;

    info!(path = %target.display(), "downloaded and verified");

    Ok(target)
}
