// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use tokio::process::Command;

pub(super) struct QemuImage {
    path: PathBuf,
}

impl QemuImage {
    pub(super) async fn create(base_image: &Path, path: PathBuf) -> Self {
        if path.exists() {
            return Self { path };
        }

        let base_image = std::fs::canonicalize(base_image).unwrap();
        let status = Command::new("qemu-img")
            .arg("create")
            .arg("-f")
            .arg("qcow2")
            .arg("-F")
            .arg("qcow2")
            .arg("-b")
            .arg(base_image)
            .arg(&path)
            .status()
            .await
            .unwrap();

        assert!(status.success());
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}
