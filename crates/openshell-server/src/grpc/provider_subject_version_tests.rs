// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::credentials::ResolvedCredentialVersion;

fn key(provider: &Provider, version: Option<&ResolvedCredentialVersion>) -> String {
    intermediate_token_cache_key(IntermediateTokenCacheKeyInput {
        provider,
        dynamic_credential: "access_token",
        subject_credential: "subject_token",
        subject_version: version,
        token_endpoint: "https://identity.example.test/token",
        client_assertion_type: "jwt-bearer",
        subject_token_type: "access_token",
        audience: "supervisor",
        requested_token_type: "access_token",
        supervisor_subject: "supervisor",
        gateway_subject: "gateway",
    })
}

#[test]
fn subject_rotation_with_unchanged_provider_row_misses_previous_cache_entry() {
    let provider = Provider::default();
    let old = ResolvedCredentialVersion {
        reference: "subject-reference".into(),
        version: 1,
        authorization_epoch: "authorization-a".into(),
    };
    let token = oauth::OAuthTokenResponse {
        access_token: "intermediate".into(),
        expires_in: 300,
        token_type: "Bearer".into(),
    };
    let cache = IntermediateTokenCache::new();
    cache.set(
        key(&provider, Some(&old)),
        &token,
        crate::persistence::current_time_ms() + 300_000,
    );
    assert!(cache.get(&key(&provider, Some(&old))).is_some());
    let new = ResolvedCredentialVersion {
        version: 2,
        ..old.clone()
    };
    assert!(cache.get(&key(&provider, Some(&new))).is_none());
    let new_epoch = ResolvedCredentialVersion {
        authorization_epoch: "authorization-b".into(),
        ..old
    };
    assert!(cache.get(&key(&provider, Some(&new_epoch))).is_none());
}

#[test]
fn captured_subject_expiration_caps_intermediate_token_cache() {
    let subject_expiry = crate::persistence::current_time_ms() + 45_000;
    let token = oauth::OAuthTokenResponse {
        access_token: "opaque-intermediate".into(),
        expires_in: 300,
        token_type: "Bearer".into(),
    };
    assert!(
        intermediate_token_cache_expires_at_ms(&token, None, subject_expiry, 0) <= subject_expiry
    );
}
