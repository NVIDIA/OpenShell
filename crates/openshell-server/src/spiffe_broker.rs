// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup selection of the gateway's sandbox identity provider.
//!
//! The provider broker depends only on
//! [`SandboxIdentityProvider`]; this module chooses the SPIRE adapter when
//! `[openshell.gateway.spiffe_broker]` is configured.
use std::sync::Arc;

use openshell_core::config::{Config, SpiffeBrokerConfig};
use openshell_core::token_grant_failure::TokenGrantFailure;
use openshell_spiffe::SandboxIdentityProvider;

/// Check the broker settings `config` enables without building them.
///
/// # Errors
///
/// Rejects broker without gateway session JWTs and a positive session
/// TTL, and settings [`SpiffeBrokerConfig::validate`] rejects.
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
    let Some(broker) = enabled(config)? else {
        return Ok(None);
    };
    let provider = openshell_spire::SpireSandboxIdentity::new(broker)?;
    Ok(Some(Arc::new(provider)))
}

/// Validated broker settings, when broker is enabled.
fn enabled(config: &Config) -> Result<Option<&SpiffeBrokerConfig>, String> {
    let Some(broker) = &config.spiffe_broker else {
        return Ok(None);
    };
    let jwt = config
        .gateway_jwt
        .as_ref()
        .ok_or("spiffe_broker requires gateway session JWTs")?;
    broker.validate(&jwt.gateway_id)?;
    if jwt.ttl_secs.is_none() {
        return Err("spiffe_broker requires a positive gateway_jwt.ttl_secs".into());
    }
    Ok(Some(broker))
}
