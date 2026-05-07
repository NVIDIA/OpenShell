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
}

#[derive(Debug)]
struct ProviderCredentialStateInner {
    current: Arc<ProviderCredentialSnapshot>,
    generations: VecDeque<Arc<SecretResolver>>,
    combined_resolver: Option<Arc<SecretResolver>>,
}

#[derive(Debug, Clone)]
pub struct ProviderCredentialState {
    inner: Arc<RwLock<ProviderCredentialStateInner>>,
}

impl ProviderCredentialState {
    pub fn from_environment(revision: u64, env: HashMap<String, String>) -> Self {
        let (child_env, resolver) = SecretResolver::from_provider_env_for_revision(env, revision);
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
        });
        let generations: VecDeque<_> = resolver.map(Arc::new).into_iter().collect();
        let combined_resolver =
            SecretResolver::merge(generations.iter().map(Arc::as_ref)).map(Arc::new);

        Self {
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot,
                generations,
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

    pub fn install_environment(&self, revision: u64, env: HashMap<String, String>) -> usize {
        let (child_env, resolver) = SecretResolver::from_provider_env_for_revision(env, revision);
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        inner.current = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
        });

        if let Some(resolver) = resolver {
            inner.generations.push_back(Arc::new(resolver));
            while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
                inner.generations.pop_front();
            }
        }
        inner.combined_resolver =
            SecretResolver::merge(inner.generations.iter().map(Arc::as_ref)).map(Arc::new);
        inner.current.child_env.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_use_revision_scoped_placeholders() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
        );
        let first = state.snapshot();
        assert_eq!(
            first.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v10_GITHUB_TOKEN")
        );

        state.install_environment(
            11,
            HashMap::from([("GITHUB_TOKEN".to_string(), "new".to_string())]),
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
    }

    #[test]
    fn empty_refresh_removes_env_from_new_snapshots_but_retains_old_resolver() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
        );

        state.install_environment(11, HashMap::new());

        assert!(state.snapshot().child_env.is_empty());
        let resolver = state.resolver().expect("old resolver retained");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("old")
        );
    }
}
