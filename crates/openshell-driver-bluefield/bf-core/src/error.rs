// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Error surface shared by BlueField driver crates.

pub type Result<T> = std::result::Result<T, BluefieldError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BluefieldError {
    InvalidConfig(String),
    Unsupported(String),
    ResourceExhausted(String),
    Runtime(String),
    Network(String),
    Storage(String),
    State(String),
}

impl std::fmt::Display for BluefieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message)
            | Self::Unsupported(message)
            | Self::ResourceExhausted(message)
            | Self::Runtime(message)
            | Self::Network(message)
            | Self::Storage(message)
            | Self::State(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for BluefieldError {}
