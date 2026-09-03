// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, serde::Deserialize)]
pub(super) struct ImageManifest {
    pub(super) url: String,
    pub(super) sha256: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct Images {
    pub(super) arm64: ImageManifest,
    pub(super) amd64: ImageManifest,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct MachineConfiguration {
    pub(super) name: String,
    pub(super) images: Images,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct Configuration {
    pub(super) version: u32,
    pub(super) machines: Vec<MachineConfiguration>,
}
