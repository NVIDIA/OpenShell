// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use sha2::{Sha256, digest::Output};
use url::Url;

pub struct VirtualMachineDefinition {
    pub name: String,
    pub images: VirtualMachineImageManifests,
}

pub struct VirtualMachineImageManifests {
    pub amd64: VirtualMachineImageManifest,
    pub arm64: VirtualMachineImageManifest,
}

pub struct VirtualMachineImageManifest {
    pub url: Url,
    pub sha256: Output<Sha256>,
}
