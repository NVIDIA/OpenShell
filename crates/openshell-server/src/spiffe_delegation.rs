// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup selection of the gateway's sandbox identity provider.
//!
//! The provider broker depends only on
//! [`SandboxIdentityProvider`]; this module chooses the SPIRE adapter when
//! `[openshell.gateway.spiffe_delegation]` is configured.
use std::sync::Arc;

use openshell_core::config::{Config, SpiffeDelegationConfig};
use openshell_core::token_grant_failure::TokenGrantFailure;
use openshell_spiffe::SandboxIdentityProvider;

/// Check the delegation settings `config` enables without building them.
///
/// # Errors
///
/// Rejects delegation without gateway session JWTs and a positive session
/// TTL, and settings [`SpiffeDelegationConfig::validate`] rejects.
pub fn validate_config(config: &Config) -> Result<(), String> {
    enabled(config).map(drop)
}

/// The sandbox identity provider `config` enables, if any.
///
/// # Errors
///
/// Rejects what [`validate_config`] rejects.
pub fn sandbox_identity_provider(
    config: &Config,
) -> Result<Option<Arc<dyn SandboxIdentityProvider<Error = TokenGrantFailure>>>, String> {
    let Some(delegation) = enabled(config)? else {
        return Ok(None);
    };
    let provider = openshell_spire::SpireDelegatedIdentity::new(delegation)?;
    Ok(Some(Arc::new(provider)))
}

/// Validated delegation settings, when delegation is enabled.
fn enabled(config: &Config) -> Result<Option<&SpiffeDelegationConfig>, String> {
    let Some(delegation) = &config.spiffe_delegation else {
        return Ok(None);
    };
    let jwt = config
        .gateway_jwt
        .as_ref()
        .ok_or("spiffe_delegation requires gateway session JWTs")?;
    delegation.validate(&jwt.gateway_id)?;
    if jwt.ttl_secs.is_none() {
        return Err("spiffe_delegation requires a positive gateway_jwt.ttl_secs".into());
    }
    Ok(Some(delegation))
}
