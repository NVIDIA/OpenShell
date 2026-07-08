// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime provider credential snapshots.

use crate::secrets::SecretResolver;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, RwLock};

const MAX_RETAINED_CREDENTIAL_GENERATIONS: usize = 8;

#[derive(Debug, Clone, Default)]
pub struct ProviderCredentialSnapshot {
    pub revision: u64,
    pub child_env: HashMap<String, String>,
    pub dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
}

#[derive(Debug)]
struct ProviderCredentialStateInner {
    current: Arc<ProviderCredentialSnapshot>,
    generations: VecDeque<Arc<SecretResolver>>,
    current_resolver: Option<Arc<SecretResolver>>,
    combined_resolver: Option<Arc<SecretResolver>>,
    suppressed_keys: HashSet<String>,
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
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
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
                suppressed_keys: HashSet::new(),
            })),
        }
    }

    /// Build a static provider state from an already-prepared child
    /// environment snapshot.
    ///
    /// Kubernetes sidecar topology uses this in the process-only supervisor:
    /// the network sidecar owns provider credential resolvers and sends the
    /// workload-facing env map over a local control channel. The process leaf
    /// must inject that map into child processes without re-placeholderizing it
    /// or holding the gateway-side resolver material.
    pub fn from_child_env_snapshot(revision: u64, child_env: HashMap<String, String>) -> Self {
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
            dynamic_credentials: HashMap::new(),
        });

        Self {
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot,
                generations: VecDeque::new(),
                current_resolver: None,
                combined_resolver: None,
                suppressed_keys: HashSet::new(),
            })),
        }
    }

    /// Install an already-prepared child environment snapshot.
    ///
    /// This is intentionally narrower than [`Self::install_environment`]: it
    /// updates only the workload-facing env map and clears resolver state so a
    /// process that does not own gateway/provider resolver material can still
    /// pick up refreshed provider env for future child processes.
    pub fn install_child_env_snapshot(
        &self,
        revision: u64,
        mut child_env: HashMap<String, String>,
    ) -> usize {
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }

        inner.current = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
            dynamic_credentials: HashMap::new(),
        });
        inner.generations.clear();
        inner.current_resolver = None;
        inner.combined_resolver = None;
        inner.current.child_env.len()
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

    /// Remove a key from the credential snapshot's child env.
    ///
    /// Used when a sandbox-side service (e.g., metadata server) fails to start
    /// and the corresponding env var should not be inherited by child processes
    /// or SSH sessions.
    pub fn remove_env_key(&self, key: &str) {
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        inner.suppressed_keys.insert(key.to_string());
        let mut env = (*inner.current).clone();
        env.child_env.remove(key);
        inner.current = Arc::new(env);
    }

    /// Return `child_env` with GCP static config vars resolved to real values.
    ///
    /// The credential pipeline placeholderizes ALL env values, but GCP SDKs
    /// and coding agents read certain vars (project ID, region, metadata host)
    /// at process startup before any HTTP request flows through the proxy.
    /// This method overrides those vars with resolved real values while
    /// keeping secret credentials (like `GCP_ACCESS_TOKEN`) as placeholders.
    ///
    /// Three layers of env var injection:
    /// 1. **Synthetic vars** (`GCE_METADATA_IP`, `METADATA_SERVER_DETECTION`)
    ///    — sandbox-internal config not from user
    ///    input, inserted directly here with real values.
    /// 2. **`google_cloud::STATIC_CONFIG_KEYS`** — user-provided non-secret config
    ///    (project ID, region, SA email) that was placeholderized by
    ///    `ProviderPlugin::inject_env` → `SecretResolver`; un-placeholderized
    ///    here so SDKs can read them at startup.
    /// 3. Everything else stays as placeholders for proxy-time resolution.
    pub fn child_env_with_gcp_resolved(&self) -> HashMap<String, String> {
        use crate::google_cloud;

        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        let mut env = inner.current.child_env.clone();

        let has_gcp_metadata = env.contains_key("GCE_METADATA_HOST");
        let has_gcp_config = google_cloud::STATIC_CONFIG_KEYS
            .iter()
            .any(|k| env.contains_key(*k));

        if !has_gcp_metadata && !has_gcp_config {
            return env;
        }

        if has_gcp_metadata {
            // Synthetic vars: sandbox-internal config that doesn't originate
            // from user input and was never placeholderized.
            env.insert(
                "GCE_METADATA_HOST".to_string(),
                google_cloud::METADATA_LOOPBACK_ADDR.to_string(),
            );
            // Python's google-auth builds its ping URL as http://{GCE_METADATA_IP}
            // so the value must include the port.
            env.insert(
                "GCE_METADATA_IP".to_string(),
                google_cloud::METADATA_LOOPBACK_ADDR.to_string(),
            );
            // Node.js gcp-metadata uses METADATA_SERVER_DETECTION to skip the
            // runtime ping that otherwise fails in sandboxed environments.
            env.insert(
                "METADATA_SERVER_DETECTION".to_string(),
                "assume-present".to_string(),
            );
        }

        // Un-placeholderize non-secret config vars so SDKs can read them
        // at process startup before any HTTP flows through the proxy.
        if let Some(ref resolver) = inner.combined_resolver {
            for key in google_cloud::STATIC_CONFIG_KEYS {
                let placeholder = crate::secrets::placeholder_for_env_key(key);
                if let Some(value) = resolver.resolve_placeholder(&placeholder) {
                    env.insert(key.to_string(), value.to_string());
                }
            }
        }

        env
    }

    /// Return the GCP token placeholder and its remaining lifetime in seconds.
    ///
    /// Searches `google_cloud::TOKEN_ENV_KEYS` in priority order (SA before
    /// ADC) atomically to avoid inconsistency during credential
    /// refresh. Returns `None` if no GCP token is configured or all are
    /// expired. The `expires_in` defaults to 3600 when expiry is unknown.
    pub fn gcp_token_response(&self) -> Option<(String, i64)> {
        const DEFAULT_EXPIRES_IN: i64 = 3600;
        let resolver = self.resolver()?;
        for key in crate::google_cloud::TOKEN_ENV_KEYS {
            let placeholder = crate::secrets::placeholder_for_env_key(key);
            if resolver.resolve_placeholder(&placeholder).is_none() {
                continue;
            }
            let expires_in = resolver.expires_at_ms_for_placeholder(&placeholder).map_or(
                DEFAULT_EXPIRES_IN,
                |expires_at_ms| {
                    if expires_at_ms <= 0 {
                        DEFAULT_EXPIRES_IN
                    } else {
                        let now = crate::time::now_ms();
                        (expires_at_ms - now) / 1000
                    }
                },
            );
            if expires_in <= 0 {
                continue;
            }
            return Some((placeholder, expires_in));
        }
        None
    }

    pub fn install_environment(
        &self,
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
    ) -> usize {
        let (mut child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision(
                env,
                credential_expires_at_ms,
                revision,
            );
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");

        for key in &inner.suppressed_keys {
            child_env.remove(key);
        }

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
    use crate::google_cloud;

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

    #[test]
    fn child_env_with_gcp_resolved_without_gcp_returns_unchanged() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_abc".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GITHUB_TOKEN").map(String::as_str),
            Some("openshell:resolve:env:v1_GITHUB_TOKEN"),
            "non-GCP env should remain as placeholder"
        );
        assert!(!env.contains_key("GCE_METADATA_HOST"));
        assert!(!env.contains_key("CLAUDE_CODE_USE_VERTEX"));
    }

    #[test]
    fn child_env_with_gcp_resolved_overrides_gcp_static_vars() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                (
                    "GCP_ADC_ACCESS_TOKEN".to_string(),
                    "ya29.secret".to_string(),
                ),
                ("GCP_PROJECT_ID".to_string(), "my-project".to_string()),
                ("CLOUD_ML_REGION".to_string(), "us-central1".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        let env = state.child_env_with_gcp_resolved();

        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_LOOPBACK_ADDR),
            "GCE_METADATA_HOST should be the loopback address"
        );
        assert!(
            !env.contains_key("CLAUDE_CODE_USE_VERTEX"),
            "inference-specific vars should not be injected"
        );
        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("my-project"),
            "static config should be resolved to real value"
        );
        assert_eq!(
            env.get("CLOUD_ML_REGION").map(String::as_str),
            Some("us-central1"),
        );

        let token = env.get("GCP_ADC_ACCESS_TOKEN").map(String::as_str).unwrap();
        assert!(
            token.starts_with("openshell:resolve:env:"),
            "GCP_ACCESS_TOKEN must stay as placeholder, got: {token}"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_handles_missing_config_keys() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "ya29.tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        let env = state.child_env_with_gcp_resolved();

        assert_eq!(
            env.get("GCE_METADATA_HOST").map(String::as_str),
            Some(google_cloud::METADATA_LOOPBACK_ADDR),
        );
        assert!(
            !env.contains_key("GCP_PROJECT_ID")
                || env
                    .get("GCP_PROJECT_ID")
                    .unwrap()
                    .starts_with("openshell:resolve:env:"),
            "missing config key should not be injected with a real value"
        );
    }

    #[test]
    fn gcp_token_response_returns_sa_over_adc() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCP_SA_ACCESS_TOKEN".to_string(), "sa-tok".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        let (placeholder, _) = state.gcp_token_response().expect("should find token");
        assert!(
            placeholder.contains("GCP_SA_ACCESS_TOKEN"),
            "SA token should win over ADC, got: {placeholder}"
        );
    }

    #[test]
    fn gcp_token_response_falls_back_to_adc() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let (placeholder, _) = state.gcp_token_response().expect("should find ADC token");
        assert!(placeholder.contains("GCP_ADC_ACCESS_TOKEN"));
    }

    #[test]
    fn gcp_token_response_returns_none_without_gcp() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GITHUB_TOKEN".to_string(), "ghp_abc".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(state.gcp_token_response().is_none());
    }

    #[test]
    fn gcp_token_response_defaults_expires_in_to_3600() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );
        let (_, expires_in) = state.gcp_token_response().unwrap();
        assert_eq!(
            expires_in, 3600,
            "should default to 3600 when no expiry set"
        );
    }

    #[test]
    fn gcp_token_response_calculates_remaining() {
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), "adc-tok".to_string())]),
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), now_ms + 120_000)]),
            HashMap::new(),
        );
        let (_, expires_in) = state.gcp_token_response().unwrap();
        assert!(
            (110..=120).contains(&expires_in),
            "expected ~120s remaining, got {expires_in}"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_resolves_vertex_vars_without_metadata_host() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GOOSE_PROVIDER".to_string(), "gcp_vertex_ai".to_string()),
                (
                    "ANTHROPIC_VERTEX_PROJECT_ID".to_string(),
                    "my-vertex-proj".to_string(),
                ),
                ("VERTEX_LOCATION".to_string(), "us-east4".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GOOSE_PROVIDER").map(String::as_str),
            Some("gcp_vertex_ai"),
            "GOOSE_PROVIDER should be resolved to real value"
        );
        assert_eq!(
            env.get("ANTHROPIC_VERTEX_PROJECT_ID").map(String::as_str),
            Some("my-vertex-proj"),
        );
        assert_eq!(
            env.get("VERTEX_LOCATION").map(String::as_str),
            Some("us-east4"),
        );
        assert!(
            !env.contains_key("GCE_METADATA_IP"),
            "metadata synthetic vars should not be injected without GCE_METADATA_HOST"
        );
    }

    #[test]
    fn suppressed_keys_survive_install_environment() {
        let state = ProviderCredentialState::from_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        state.remove_env_key("GCE_METADATA_HOST");
        assert!(!state.snapshot().child_env.contains_key("GCE_METADATA_HOST"));

        state.install_environment(
            2,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "tok2".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
        );
        assert!(
            !state.snapshot().child_env.contains_key("GCE_METADATA_HOST"),
            "suppressed key must not reappear after install_environment"
        );
    }

    #[test]
    fn child_env_snapshot_install_updates_env_without_resolver_material() {
        let state = ProviderCredentialState::from_child_env_snapshot(
            1,
            HashMap::from([
                ("GITHUB_TOKEN".to_string(), "old".to_string()),
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
            ]),
        );
        state.remove_env_key("GCE_METADATA_HOST");

        let env_count = state.install_child_env_snapshot(
            2,
            HashMap::from([
                ("GITHUB_TOKEN".to_string(), "new".to_string()),
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
            ]),
        );

        let snapshot = state.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(env_count, 1);
        assert_eq!(
            snapshot.child_env.get("GITHUB_TOKEN").map(String::as_str),
            Some("new")
        );
        assert!(!snapshot.child_env.contains_key("GCE_METADATA_HOST"));
        assert!(
            state.resolver().is_none(),
            "child-env snapshots must not install provider resolver material"
        );
    }

    #[test]
    fn stale_generation_falls_back_to_current_credential_after_retention_window() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        for revision in 11..20 {
            state.install_environment(
                revision,
                HashMap::from([("GITHUB_TOKEN".to_string(), format!("new-{revision}"))]),
                HashMap::new(),
                HashMap::new(),
            );
        }

        let resolver = state.resolver().expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            Some("new-19")
        );
    }

    #[test]
    fn stale_removed_generation_fails_closed_after_retention_window() {
        let state = ProviderCredentialState::from_environment(
            10,
            HashMap::from([("GITHUB_TOKEN".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
        );

        for revision in 11..20 {
            state.install_environment(
                revision,
                HashMap::from([("OTHER_TOKEN".to_string(), format!("other-{revision}"))]),
                HashMap::new(),
                HashMap::new(),
            );
        }

        let resolver = state.resolver().expect("retained resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v10_GITHUB_TOKEN"),
            None
        );
    }
}
