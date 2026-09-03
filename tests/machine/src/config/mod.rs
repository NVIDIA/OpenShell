// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod schema;
mod validation;

use crate::virtual_machine::VirtualMachineDefinition;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to parse configuration")]
    Parse(#[from] serde_saphyr::Error),

    #[error("unsupported configuration version {0}")]
    UnsupportedConfigurationVersion(u32),

    #[error("machine name must not be empty")]
    EmptyMachineName,

    #[error("invalid image URL")]
    InvalidImageUrl(#[from] url::ParseError),

    #[error("image URL scheme must be HTTP or HTTPS, got {0}")]
    UnsupportedImageUrlScheme(String),

    #[error("invalid SHA-256 digest")]
    InvalidSha256(#[from] hex::FromHexError),
}

pub fn from_str(contents: &str) -> Result<Vec<VirtualMachineDefinition>, Error> {
    let configuration = serde_saphyr::from_str(contents)?;
    validation::validate(configuration)
}
