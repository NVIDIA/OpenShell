// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod build;
pub mod edge_token;
pub mod jwt;
pub mod oidc_token;

mod metadata;
pub mod mtls;
mod paths;
pub mod pki;

#[cfg(test)]
use std::sync::Mutex;

/// Shared lock for tests that mutate the process-global `XDG_CONFIG_HOME`
/// env var. All such tests in any module must hold this lock to avoid
/// concurrent clobbering.
#[cfg(test)]
pub(crate) static XDG_TEST_LOCK: Mutex<()> = Mutex::new(());

pub use crate::metadata::{
    GatewayMetadata, GatewayMetadataSource, ListedGateway, clear_active_gateway,
    clear_last_sandbox_if_matches, extract_host_from_ssh_destination, gateway_metadata_source,
    get_gateway_metadata, list_gateways, list_gateways_with_source, load_active_gateway,
    load_gateway_metadata, load_last_sandbox, load_user_active_gateway, remove_gateway_metadata,
    resolve_ssh_hostname, save_active_gateway, save_last_sandbox, store_gateway_metadata,
};
