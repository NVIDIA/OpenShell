// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime provider credential snapshots.

use crate::secrets::SecretResolver;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

const MAX_RETAINED_CREDENTIAL_GENERATIONS: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct ProviderCredentialSnapshot {
    pub revision: u64,
    pub child_env: HashMap<String, String>,
    pub dynamic_credentials: HashMap<String, openshell_core::proto::ProviderProfileCredential>,
}

#[derive(Debug)]
struct ProviderCredentialStateInner {
    current: Arc<ProviderCredentialSnapshot>,
    generations: VecDeque<Arc<SecretResolver>>,
    current_resolver: Option<Arc<SecretResolver>>,
    combined_resolver: Option<Arc<SecretResolver>>,
}

#[derive(Debug, Clone)]
pub struct ProviderCredentialState {
    inner: Arc<RwLock<ProviderCredentialStateInner>>,
}

impl ProviderCredentialState {
    pub fn from_environment(
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, openshell_core::proto::ProviderProfileCredential>,
    ) -> Self {
        let (child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision(
                env,
                credential_expires_at_ms,
                revision,
            );
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
            dynamic_credentials,
        });
        let generations: VecDeque<_> = generation_resolver.map(Arc::new).into_iter().collect();
        let current_resolver = current_resolver.map(Arc::new);
        let combined_resolver = merge_resolvers(&generations, current_resolver.as_ref());

        Self {
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot,
                generations,
                current_resolver,
                combined_resolver,
            })),
        }
    }

    pub fn snapshot(&self) -> Arc<ProviderCredentialSnapshot> {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .current
            .clone()
    }

    pub fn resolver(&self) -> Option<Arc<SecretResolver>> {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .combined_resolver
            .clone()
    }

    pub fn install_environment(
        &self,
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, openshell_core::proto::ProviderProfileCredential>,
    ) -> usize {
        let (child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision(
                env,
                credential_expires_at_ms,
                revision,
            );
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        inner.current = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
            dynamic_credentials,
        });
        inner.current_resolver = current_resolver.map(Arc::new);

        if let Some(resolver) = generation_resolver {
            inner.generations.push_back(Arc::new(resolver));
            while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
                inner.generations.pop_front();
            }
        }
        inner.combined_resolver =
            merge_resolvers(&inner.generations, inner.current_resolver.as_ref());
        inner.current.child_env.len()
    }
}

fn merge_resolvers(
    generations: &VecDeque<Arc<SecretResolver>>,
    current_resolver: Option<&Arc<SecretResolver>>,
) -> Option<Arc<SecretResolver>> {
    SecretResolver::merge(
        generations
            .iter()
            .map(Arc::as_ref)
            .chain(current_resolver.into_iter().map(Arc::as_ref)),
    )
    .map(Arc::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_use_revision_scoped_placeholders() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let first = state.snapshot();
        assert_eq!(
            first.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v10_GITHUB_TOKEN")
        );

        state.install_environment(
            11,
            HashMap::from([("GITHUB_TOKEN".to_string(), "new".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let second = state.snapshot();
        assert_eq!(
            second.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v11_GITHUB_TOKEN")
        );

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v11_GITHUB_TOKEN"),
            Some("new")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:GITHUB_TOKEN"),
            Some("new")
        );
        assert_eq!(
            resolver.resolve_placeholder("provider-OPENSHELL-RESOLVE-ENV-GITHUB_TOKEN"),
            Some("new")
        );
    }

    #[test]
    fn empty_refresh_removes_current_aliases_but_retains_revisioned_resolver() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        state.install_environment(11, HashMap::new(), HashMap::new(), HashMap::new());

        assert!(state.snapshot().child_env.is_empty());
        let resolver = state.resolver().expect("old resolver retained");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:GITHUB_TOKEN"),
            None
        );
        assert_eq!(
            resolver.resolve_placeholder("provider-OPENSHELL-RESOLVE-ENV-GITHUB_TOKEN"),
            None
        );
    }

    #[test]
    fn expired_retained_generation_does_not_resolve() {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::from([("GITHUB_TOKEN".to_string(), now_ms - 1_000)]),
            HashMap::new(),
        );

        state.install_environment(
            11,
            HashMap::from([("GITHUB_TOKEN".to_string(), "new".to_string())]),
            HashMap::from([("GITHUB_TOKEN".to_string(), now_ms + 60_000)]),
            HashMap::new(),
        );

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            None
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v11_GITHUB_TOKEN"),
            Some("new")
        );
    }
}
