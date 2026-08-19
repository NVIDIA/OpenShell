// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runtime provider credential snapshots.

use crate::secrets::SecretResolver;
use crate::{
    endpoint_path::EndpointPathPattern,
    host_pattern::HostPattern,
    proto::{StaticCredentialBinding, StaticCredentialEndpointBinding},
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
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
    non_secret_environment_keys: HashSet<String>,
    static_credential_bindings: HashMap<String, CompiledStaticCredentialBinding>,
    known_static_credential_keys: HashSet<String>,
    static_credential_identity_epochs: HashMap<String, StaticCredentialIdentityEpoch>,
}

#[derive(Debug)]
struct StaticCredentialIdentityEpoch {
    identity: String,
    revisions: Arc<HashSet<u64>>,
}

#[derive(Debug, Clone)]
struct CompiledStaticCredentialBinding {
    endpoints: Vec<CompiledStaticCredentialEndpointBinding>,
    credential_identity: String,
    workload_credential_handle: String,
}

#[derive(Debug, Clone)]
struct CompiledStaticCredentialEndpointBinding {
    host: HostPattern,
    port: u16,
    path: EndpointPathPattern,
}

#[derive(Debug, Clone)]
pub struct ProviderCredentialState {
    inner: Arc<RwLock<ProviderCredentialStateInner>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCredentialBindingError {
    message: String,
}

impl fmt::Display for StaticCredentialBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StaticCredentialBindingError {}

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
                non_secret_environment_keys: HashSet::new(),
                static_credential_bindings: HashMap::new(),
                known_static_credential_keys: HashSet::new(),
                static_credential_identity_epochs: HashMap::new(),
            })),
        }
    }

    pub fn from_bound_environment(
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
        static_credential_bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
    ) -> Result<Self, StaticCredentialBindingError> {
        let static_credential_bindings = compile_static_credential_bindings(
            &env,
            static_credential_bindings,
            &non_secret_environment_keys,
        )?;
        let stable_handles = static_credential_stable_handles(&static_credential_bindings);
        let (child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision_with_stable_handles(
                env,
                credential_expires_at_ms,
                revision,
                &stable_handles,
            );
        let snapshot = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env,
            dynamic_credentials,
        });
        let generations = generation_resolver.map(Arc::new).into_iter().collect();
        let current_resolver = current_resolver.map(Arc::new);
        let combined_resolver = merge_resolvers(&generations, current_resolver.as_ref());
        let known_static_credential_keys = static_credential_bindings.keys().cloned().collect();
        let mut static_credential_identity_epochs = HashMap::new();
        update_static_credential_identity_epochs(
            &mut static_credential_identity_epochs,
            revision,
            &static_credential_bindings,
        );

        Ok(Self {
            inner: Arc::new(RwLock::new(ProviderCredentialStateInner {
                current: snapshot,
                generations,
                current_resolver,
                combined_resolver,
                suppressed_keys: HashSet::new(),
                non_secret_environment_keys: non_secret_environment_keys.into_iter().collect(),
                static_credential_bindings,
                known_static_credential_keys,
                static_credential_identity_epochs,
            })),
        })
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
                non_secret_environment_keys: HashSet::new(),
                static_credential_bindings: HashMap::new(),
                known_static_credential_keys: HashSet::new(),
                static_credential_identity_epochs: HashMap::new(),
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
        inner.non_secret_environment_keys.clear();
        inner.static_credential_bindings.clear();
        inner.known_static_credential_keys.clear();
        inner.static_credential_identity_epochs.clear();
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

    /// Resolve provider placeholders only for credentials bound to this
    /// concrete request endpoint. The view is created from one atomic state
    /// snapshot and shares underlying resolver material.
    #[must_use]
    pub fn resolver_for_endpoint(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> Option<Arc<SecretResolver>> {
        self.resolver_for_endpoint_with_revision(host, port, path).0
    }

    /// Resolve provider placeholders for one endpoint and return the provider
    /// revision observed from the same locked state snapshot.
    ///
    /// Callers that materialize credential-bearing requests asynchronously
    /// use the revision to reject stale material immediately before its first
    /// upstream write.
    #[must_use]
    pub fn resolver_for_endpoint_with_revision(
        &self,
        host: &str,
        port: u16,
        path: &str,
    ) -> (Option<Arc<SecretResolver>>, u64) {
        let request_path = path.split_once('?').map_or(path, |(path, _)| path);
        let request_path = crate::secrets::redact_target_for_policy(request_path);
        let normalized_host = host.to_ascii_lowercase();
        let host_labels = normalized_host.split('.').collect::<Vec<_>>();
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        let revision = inner.current.revision;
        let Ok(request_path) = request_path else {
            // Binding authorization must not depend on real credential
            // material. Malformed placeholder syntax cannot be normalized
            // safely, so expose no endpoint-scoped resolver.
            return (None, revision);
        };
        let allowed: HashSet<String> = inner
            .static_credential_bindings
            .iter()
            .filter(|(_, binding)| {
                binding.endpoints.iter().any(|endpoint| {
                    static_credential_endpoint_matches(endpoint, &host_labels, port, &request_path)
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        let resolver = inner.combined_resolver.as_ref().map(|resolver| {
            let revision_fallback_allowed_revisions = inner
                .static_credential_identity_epochs
                .iter()
                .filter(|(key, epoch)| {
                    allowed.contains(*key)
                        && inner
                            .static_credential_bindings
                            .get(*key)
                            .is_some_and(|binding| binding.credential_identity == epoch.identity)
                })
                .map(|(key, epoch)| (key.clone(), epoch.revisions.clone()))
                .collect();
            Arc::new(resolver.scoped_to_env_keys(
                &inner.known_static_credential_keys,
                &allowed,
                revision_fallback_allowed_revisions,
            ))
        });
        (resolver, revision)
    }

    #[must_use]
    pub fn revision(&self) -> u64 {
        self.inner
            .read()
            .expect("provider credential state poisoned")
            .current
            .revision
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

        let has_gcp_metadata = env.contains_key("GCE_METADATA_HOST")
            && inner
                .non_secret_environment_keys
                .contains("GCE_METADATA_HOST");
        let has_gcp_config = google_cloud::STATIC_CONFIG_KEYS
            .iter()
            .any(|key| env.contains_key(*key) && inner.non_secret_environment_keys.contains(*key));

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
            for key in google_cloud::STATIC_CONFIG_KEYS
                .iter()
                .filter(|key| inner.non_secret_environment_keys.contains(**key))
            {
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
        let inner = self
            .inner
            .read()
            .expect("provider credential state poisoned");
        let resolver = inner.current_resolver.as_ref()?;
        for key in crate::google_cloud::TOKEN_ENV_KEYS {
            let Some(placeholder) = inner.current.child_env.get(*key).cloned() else {
                continue;
            };
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
                        expires_at_ms.saturating_sub(now) / 1000
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
        inner.non_secret_environment_keys.clear();
        inner.current.child_env.len()
    }

    /// Install one gateway provider-environment snapshot.
    ///
    /// Callers must serialize this operation with other bound-environment
    /// installs and revocations. The sandbox settings refresh loop is the sole
    /// writer today. The internal lock makes each mutation memory-safe, but it
    /// does not establish revision ordering between concurrent snapshots.
    pub fn install_bound_environment(
        &self,
        revision: u64,
        env: HashMap<String, String>,
        credential_expires_at_ms: HashMap<String, i64>,
        dynamic_credentials: HashMap<String, crate::proto::ProviderProfileCredential>,
        static_credential_bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
    ) -> Result<usize, StaticCredentialBindingError> {
        let static_credential_bindings = match compile_static_credential_bindings(
            &env,
            static_credential_bindings,
            &non_secret_environment_keys,
        ) {
            Ok(bindings) => bindings,
            Err(error) => {
                self.revoke_static_provider_environment_inner(revision, Some(dynamic_credentials));
                return Err(error);
            }
        };

        let stable_handles = static_credential_stable_handles(&static_credential_bindings);
        let (mut child_env, generation_resolver, current_resolver) =
            SecretResolver::from_provider_env_for_current_revision_with_stable_handles(
                env,
                credential_expires_at_ms,
                revision,
                &stable_handles,
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
        if static_credential_identities(&inner.static_credential_bindings)
            != static_credential_identities(&static_credential_bindings)
        {
            inner.generations.clear();
        }
        if let Some(resolver) = generation_resolver {
            inner.generations.push_back(Arc::new(resolver));
            while inner.generations.len() > MAX_RETAINED_CREDENTIAL_GENERATIONS {
                inner.generations.pop_front();
            }
        }
        inner.combined_resolver =
            merge_resolvers(&inner.generations, inner.current_resolver.as_ref());
        inner
            .known_static_credential_keys
            .extend(static_credential_bindings.keys().cloned());
        update_static_credential_identity_epochs(
            &mut inner.static_credential_identity_epochs,
            revision,
            &static_credential_bindings,
        );
        inner.non_secret_environment_keys = non_secret_environment_keys.into_iter().collect();
        inner.static_credential_bindings = static_credential_bindings;
        Ok(inner.current.child_env.len())
    }

    /// Atomically remove static provider material after a failed refresh.
    ///
    /// Dynamic token grants retain their independently endpoint-bound state
    /// unless the caller supplies a newer dynamic snapshot. Identity-only
    /// revision membership remains as a tombstone so a later successful
    /// refresh can restore placeholders issued by the same provider identity.
    /// With no resolver or active bindings, the tombstone cannot resolve
    /// credentials while the refresh is failed. A successful empty provider
    /// environment removes it through the normal epoch update path.
    pub fn revoke_static_provider_environment(&self, revision: u64) {
        self.revoke_static_provider_environment_inner(revision, None);
    }

    fn revoke_static_provider_environment_inner(
        &self,
        revision: u64,
        dynamic_credentials: Option<HashMap<String, crate::proto::ProviderProfileCredential>>,
    ) {
        let mut inner = self
            .inner
            .write()
            .expect("provider credential state poisoned");
        let dynamic_credentials =
            dynamic_credentials.unwrap_or_else(|| inner.current.dynamic_credentials.clone());
        inner.current = Arc::new(ProviderCredentialSnapshot {
            revision,
            child_env: HashMap::new(),
            dynamic_credentials,
        });
        inner.generations.clear();
        inner.current_resolver = None;
        inner.combined_resolver = None;
        inner.non_secret_environment_keys.clear();
        inner.static_credential_bindings.clear();
    }
}

fn compile_static_credential_bindings(
    env: &HashMap<String, String>,
    bindings: HashMap<String, StaticCredentialBinding>,
    non_secret_environment_keys: &[String],
) -> Result<HashMap<String, CompiledStaticCredentialBinding>, StaticCredentialBindingError> {
    let non_secret_keys = non_secret_environment_keys
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if non_secret_keys.len() != non_secret_environment_keys.len() {
        return Err(binding_error(
            "provider environment repeats a non-secret environment key",
        ));
    }
    if bindings.keys().any(|key| non_secret_keys.contains(key)) {
        return Err(binding_error(
            "provider environment classifies a key as both credential and non-secret configuration",
        ));
    }
    if env
        .keys()
        .any(|key| !bindings.contains_key(key) && !non_secret_keys.contains(key))
    {
        return Err(binding_error(
            "provider environment contains an unclassified credential key",
        ));
    }
    if bindings.keys().any(|key| !env.contains_key(key))
        || non_secret_keys.iter().any(|key| !env.contains_key(key))
    {
        return Err(binding_error(
            "provider environment metadata references a missing environment key",
        ));
    }
    for binding in bindings.values() {
        if binding.credential_identity.is_empty() {
            return Err(binding_error(
                "static credential binding has no provider credential identity",
            ));
        }
        if binding.endpoints.is_empty() {
            return Err(binding_error(
                "static credential binding has no authorized endpoints",
            ));
        }
        if !binding.workload_credential_handle.is_empty()
            && !is_valid_workload_credential_handle(&binding.workload_credential_handle)
        {
            return Err(binding_error(
                "static credential binding has an invalid workload credential handle",
            ));
        }
        for endpoint in &binding.endpoints {
            if endpoint.port == 0 || endpoint.port > u32::from(u16::MAX) {
                return Err(binding_error(
                    "static credential binding contains an invalid endpoint",
                ));
            }
        }
    }

    bindings
        .into_iter()
        .map(|(key, binding)| {
            let endpoints = binding
                .endpoints
                .into_iter()
                .map(compile_static_credential_endpoint)
                .collect::<Result<_, _>>()?;
            Ok((
                key,
                CompiledStaticCredentialBinding {
                    endpoints,
                    credential_identity: binding.credential_identity,
                    workload_credential_handle: binding.workload_credential_handle,
                },
            ))
        })
        .collect()
}

fn compile_static_credential_endpoint(
    endpoint: StaticCredentialEndpointBinding,
) -> Result<CompiledStaticCredentialEndpointBinding, StaticCredentialBindingError> {
    let host = HostPattern::new(&endpoint.host)
        .map_err(|_| binding_error("static credential binding contains an invalid endpoint"))?;
    Ok(CompiledStaticCredentialEndpointBinding {
        host,
        port: u16::try_from(endpoint.port)
            .map_err(|_| binding_error("static credential binding contains an invalid endpoint"))?,
        path: EndpointPathPattern::new(&endpoint.path),
    })
}

fn static_credential_identities(
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) -> HashMap<&str, &str> {
    bindings
        .iter()
        .map(|(key, binding)| (key.as_str(), binding.credential_identity.as_str()))
        .collect()
}

fn static_credential_stable_handles(
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) -> HashMap<String, String> {
    bindings
        .iter()
        .filter(|(_, binding)| !binding.workload_credential_handle.is_empty())
        .map(|(key, binding)| (key.clone(), binding.workload_credential_handle.clone()))
        .collect()
}

fn is_valid_workload_credential_handle(handle: &str) -> bool {
    handle.len() == 64
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn update_static_credential_identity_epochs(
    epochs: &mut HashMap<String, StaticCredentialIdentityEpoch>,
    revision: u64,
    bindings: &HashMap<String, CompiledStaticCredentialBinding>,
) {
    epochs.retain(|key, _| {
        bindings
            .get(key)
            .is_some_and(|binding| binding.workload_credential_handle.is_empty())
    });
    for (key, binding) in bindings {
        if !binding.workload_credential_handle.is_empty() {
            continue;
        }
        match epochs.get_mut(key) {
            Some(epoch) if epoch.identity == binding.credential_identity => {
                Arc::make_mut(&mut epoch.revisions).insert(revision);
            }
            Some(epoch) => {
                epoch.identity.clone_from(&binding.credential_identity);
                epoch.revisions = Arc::new(HashSet::from([revision]));
            }
            None => {
                epochs.insert(
                    key.clone(),
                    StaticCredentialIdentityEpoch {
                        identity: binding.credential_identity.clone(),
                        revisions: Arc::new(HashSet::from([revision])),
                    },
                );
            }
        }
    }
}

fn binding_error(message: &str) -> StaticCredentialBindingError {
    StaticCredentialBindingError {
        message: message.to_string(),
    }
}

fn static_credential_endpoint_matches(
    endpoint: &CompiledStaticCredentialEndpointBinding,
    host_labels: &[&str],
    port: u16,
    path: &str,
) -> bool {
    endpoint.port == port
        && endpoint.host.matches_normalized_labels(host_labels)
        && endpoint.path.matches(path)
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

    fn binding(host: &str, port: u32, path: &str) -> StaticCredentialBinding {
        StaticCredentialBinding {
            endpoints: vec![StaticCredentialEndpointBinding {
                host: host.to_string(),
                port,
                path: path.to_string(),
            }],
            credential_identity: "provider-a:API_KEY".to_string(),
            workload_credential_handle: String::new(),
        }
    }

    fn stable_binding(host: &str, port: u32, path: &str, handle: &str) -> StaticCredentialBinding {
        let mut binding = binding(host, port, path);
        binding.credential_identity = format!("refresh:{handle}");
        binding.workload_credential_handle = handle.to_string();
        binding
    }

    fn assert_binding_validation_error(
        env: HashMap<String, String>,
        bindings: HashMap<String, StaticCredentialBinding>,
        non_secret_environment_keys: Vec<String>,
        expected: &str,
    ) {
        let error =
            compile_static_credential_bindings(&env, bindings, &non_secret_environment_keys)
                .expect_err("malformed provider metadata must fail validation");
        assert_eq!(error.to_string(), expected);
    }

    #[test]
    fn rejects_each_malformed_static_credential_binding_shape() {
        let credential_env = || HashMap::from([("API_KEY".to_string(), "secret".to_string())]);
        let credential_binding = || {
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )])
        };

        assert_binding_validation_error(
            HashMap::from([("PROJECT_ID".to_string(), "project".to_string())]),
            HashMap::new(),
            vec!["PROJECT_ID".to_string(), "PROJECT_ID".to_string()],
            "provider environment repeats a non-secret environment key",
        );
        assert_binding_validation_error(
            credential_env(),
            credential_binding(),
            vec!["API_KEY".to_string()],
            "provider environment classifies a key as both credential and non-secret configuration",
        );
        assert_binding_validation_error(
            credential_env(),
            HashMap::new(),
            Vec::new(),
            "provider environment contains an unclassified credential key",
        );
        assert_binding_validation_error(
            HashMap::new(),
            credential_binding(),
            Vec::new(),
            "provider environment metadata references a missing environment key",
        );

        let mut missing_identity = binding("api.example.com", 443, "/**");
        missing_identity.credential_identity.clear();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), missing_identity)]),
            Vec::new(),
            "static credential binding has no provider credential identity",
        );

        let mut missing_endpoints = binding("api.example.com", 443, "/**");
        missing_endpoints.endpoints.clear();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), missing_endpoints)]),
            Vec::new(),
            "static credential binding has no authorized endpoints",
        );

        let mut invalid_handle = binding("api.example.com", 443, "/**");
        invalid_handle.workload_credential_handle = "not-an-opaque-handle".to_string();
        assert_binding_validation_error(
            credential_env(),
            HashMap::from([("API_KEY".to_string(), invalid_handle)]),
            Vec::new(),
            "static credential binding has an invalid workload credential handle",
        );

        for (host, port) in [
            ("api.example.com", 0),
            ("api.example.com", u32::from(u16::MAX) + 1),
            ("invalid host", 443),
        ] {
            assert_binding_validation_error(
                credential_env(),
                HashMap::from([("API_KEY".to_string(), binding(host, port, "/**"))]),
                Vec::new(),
                "static credential binding contains an invalid endpoint",
            );
        }
    }

    #[test]
    fn bound_credentials_resolve_only_at_matching_endpoint() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("*.example.com", 443, "/v1/**"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");
        let placeholder = "openshell:resolve:env:v7_API_KEY";

        let allowed = state
            .resolver_for_endpoint("api.example.com", 443, "/v1/messages?stream=true")
            .expect("resolver");
        assert_eq!(allowed.resolve_placeholder(placeholder), Some("secret"));

        for (host, port, path) in [
            ("example.com", 443, "/v1/messages"),
            ("api.example.com", 80, "/v1/messages"),
            ("api.example.com", 443, "/v2/messages"),
        ] {
            let denied = state
                .resolver_for_endpoint(host, port, path)
                .expect("resolver");
            let error = denied
                .rewrite_header_value(placeholder)
                .expect_err("endpoint mismatch must fail closed");
            assert!(error.is_endpoint_mismatch(), "{host}:{port}{path}");
        }
    }

    #[test]
    fn multiple_credentials_resolve_only_at_their_own_endpoints() {
        let mut binding_a = binding("a.example.com", 443, "/a/**");
        binding_a.credential_identity = "provider-a:KEY_A".to_string();
        let mut binding_b = binding("b.example.com", 443, "/b/**");
        binding_b.credential_identity = "provider-b:KEY_B".to_string();
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([
                ("KEY_A".to_string(), "secret-a".to_string()),
                ("KEY_B".to_string(), "secret-b".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([
                ("KEY_A".to_string(), binding_a),
                ("KEY_B".to_string(), binding_b),
            ]),
            Vec::new(),
        )
        .expect("valid bindings");

        let resolver_a = state
            .resolver_for_endpoint("a.example.com", 443, "/a/check")
            .expect("endpoint A resolver");
        assert_eq!(
            resolver_a.resolve_placeholder("openshell:resolve:env:v7_KEY_A"),
            Some("secret-a")
        );
        assert_eq!(
            resolver_a.resolve_placeholder("openshell:resolve:env:v7_KEY_B"),
            None,
            "credential B must not resolve at endpoint A"
        );

        let resolver_b = state
            .resolver_for_endpoint("b.example.com", 443, "/b/check")
            .expect("endpoint B resolver");
        assert_eq!(
            resolver_b.resolve_placeholder("openshell:resolve:env:v7_KEY_B"),
            Some("secret-b")
        );
        assert_eq!(
            resolver_b.resolve_placeholder("openshell:resolve:env:v7_KEY_A"),
            None,
            "credential A must not resolve at endpoint B"
        );
    }

    #[test]
    fn refresh_replaces_compiled_endpoint_patterns() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("old.example.com", 443, "/v1/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("new.example.com", 443, "/v2/**"),
                )]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let replacement = state
            .resolver_for_endpoint("new.example.com", 443, "/v2/messages")
            .expect("replacement endpoint resolver");
        assert_eq!(
            replacement.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            Some("new")
        );

        let removed = state
            .resolver_for_endpoint("old.example.com", 443, "/v1/messages")
            .expect("restricted resolver");
        let error = removed
            .rewrite_header_value("openshell:resolve:env:v2_API_KEY")
            .expect_err("replaced endpoint binding must no longer authorize the credential");
        assert!(error.is_endpoint_mismatch());
    }

    #[test]
    fn revisioned_path_placeholder_matches_exact_redacted_binding() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/bot[CREDENTIAL]/sendMessage"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");
        let placeholder = "openshell:resolve:env:v7_API_KEY";

        let resolver = state
            .resolver_for_endpoint(
                "api.example.com",
                443,
                &format!("/bot{placeholder}/sendMessage?stream=true"),
            )
            .expect("syntax-redacted path should select the binding");
        assert_eq!(resolver.resolve_placeholder(placeholder), Some("secret"));
    }

    #[test]
    fn provider_alias_path_placeholder_matches_glob_redacted_binding() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/v1/*/messages"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");

        let resolver = state
            .resolver_for_endpoint(
                "api.example.com",
                443,
                "/v1/vendor-OPENSHELL-RESOLVE-ENV-API_KEY/messages",
            )
            .expect("syntax-redacted alias path should select the binding");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v7_API_KEY"),
            Some("secret")
        );
    }

    #[test]
    fn malformed_path_placeholder_exposes_no_endpoint_resolver() {
        let state = ProviderCredentialState::from_bound_environment(
            7,
            HashMap::from([("API_KEY".to_string(), "secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("valid bindings");

        assert!(
            state
                .resolver_for_endpoint(
                    "api.example.com",
                    443,
                    "/v1/openshell:resolve:env:/messages",
                )
                .is_none(),
            "malformed placeholder syntax must fail closed before path matching"
        );
    }

    #[test]
    fn non_secret_provider_config_is_not_endpoint_scoped() {
        let state = ProviderCredentialState::from_bound_environment(
            3,
            HashMap::from([("GCP_PROJECT_ID".to_string(), "project".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec!["GCP_PROJECT_ID".to_string()],
        )
        .expect("classified non-secret environment");
        let resolver = state
            .resolver_for_endpoint("unrelated.example", 1234, "/")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v3_GCP_PROJECT_ID"),
            Some("project")
        );
    }

    #[test]
    fn incomplete_refresh_revokes_previous_credentials_atomically() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        let dynamic_credentials = HashMap::from([(
            "dynamic".to_string(),
            crate::proto::ProviderProfileCredential::default(),
        )]);
        let result = state.install_bound_environment(
            2,
            HashMap::from([("API_KEY".to_string(), "new".to_string())]),
            HashMap::new(),
            dynamic_credentials,
            HashMap::new(),
            Vec::new(),
        );
        assert!(result.is_err());
        assert!(state.snapshot().child_env.is_empty());
        assert!(state.resolver().is_none());
        assert!(state.snapshot().dynamic_credentials.contains_key("dynamic"));

        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "recovered".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("same-identity recovery");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("recovered"),
            "a metadata failure must not permanently strand placeholders from the same provider identity"
        );
    }

    #[test]
    fn failed_fetch_revokes_secrets_then_same_identity_retry_recovers_running_placeholder() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state.revoke_static_provider_environment(2);

        assert!(
            state.resolver().is_none(),
            "no static secret resolver may remain active during the failed refresh"
        );
        assert!(
            state
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .is_none(),
            "an identity tombstone must not authorize requests without active bindings and secrets"
        );

        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("same-identity retry");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("new"),
            "the running process placeholder should recover against the current same-identity secret"
        );
    }

    #[test]
    fn retained_generation_survives_rotation_of_same_provider_credential() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    binding("api.example.com", 443, "/**"),
                )]),
                Vec::new(),
            )
            .expect("rotated bindings");

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            Some("old")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            Some("new")
        );
    }

    #[test]
    fn stable_handle_resolves_current_token_after_initial_token_expires() {
        let handle = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_millis(),
        )
        .expect("current time fits i64");
        let binding = stable_binding("api.example.com", 443, "/**", handle);
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "expired".to_string())]),
            HashMap::from([("API_KEY".to_string(), now_ms - 1)]),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding.clone())]),
            Vec::new(),
        )
        .expect("initial stable binding");
        let workload_placeholder = state.snapshot().child_env["API_KEY"].clone();
        assert!(workload_placeholder.contains(handle));
        assert_eq!(
            state
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .expect("resolver")
                .resolve_placeholder(&workload_placeholder),
            None,
            "the expired access token must fail closed"
        );

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "current".to_string())]),
                HashMap::from([("API_KEY".to_string(), now_ms + 60_000)]),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), binding)]),
                Vec::new(),
            )
            .expect("refreshed stable binding");

        assert_eq!(state.snapshot().child_env["API_KEY"], workload_placeholder);
        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder(&workload_placeholder),
            Some("current")
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v2_API_KEY"),
            None,
            "refresh-managed credentials must not expose revision aliases"
        );
    }

    #[test]
    fn stable_handle_survives_twelve_rotations_and_state_reconstruction() {
        let handle = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let binding = stable_binding("api.example.com", 443, "/**", handle);
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "token-1".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding.clone())]),
            Vec::new(),
        )
        .expect("initial stable binding");
        let workload_placeholder = state.snapshot().child_env["API_KEY"].clone();

        for revision in 2..=13 {
            let token = format!("token-{revision}");
            state
                .install_bound_environment(
                    revision,
                    HashMap::from([("API_KEY".to_string(), token.clone())]),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::from([("API_KEY".to_string(), binding.clone())]),
                    Vec::new(),
                )
                .expect("same-epoch rotation");
            assert_eq!(state.snapshot().child_env["API_KEY"], workload_placeholder);
            assert_eq!(
                state
                    .resolver_for_endpoint("api.example.com", 443, "/v1")
                    .expect("resolver")
                    .resolve_placeholder(&workload_placeholder),
                Some(token.as_str())
            );
        }

        let reconstructed = ProviderCredentialState::from_bound_environment(
            14,
            HashMap::from([("API_KEY".to_string(), "token-14".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding)]),
            Vec::new(),
        )
        .expect("reconstructed network supervisor state");
        assert_eq!(
            reconstructed.snapshot().child_env["API_KEY"],
            workload_placeholder
        );
        assert_eq!(
            reconstructed
                .resolver_for_endpoint("api.example.com", 443, "/v1")
                .expect("resolver")
                .resolve_placeholder(&workload_placeholder),
            Some("token-14")
        );
    }

    #[test]
    fn authorization_epoch_or_endpoint_change_revokes_stable_handle() {
        let old_handle = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let new_handle = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "old".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                stable_binding("old.example.com", 443, "/v1/**", old_handle),
            )]),
            Vec::new(),
        )
        .expect("old authorization");
        let old_placeholder = state.snapshot().child_env["API_KEY"].clone();

        state
            .install_bound_environment(
                2,
                HashMap::from([("API_KEY".to_string(), "new".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "API_KEY".to_string(),
                    stable_binding("new.example.com", 443, "/v2/**", new_handle),
                )]),
                Vec::new(),
            )
            .expect("replacement authorization");

        let current = state
            .resolver_for_endpoint("new.example.com", 443, "/v2/messages")
            .expect("current resolver");
        assert_eq!(current.resolve_placeholder(&old_placeholder), None);
        assert_eq!(
            current.resolve_placeholder(&state.snapshot().child_env["API_KEY"]),
            Some("new")
        );
        let wrong_endpoint = state
            .resolver_for_endpoint("old.example.com", 443, "/v1/messages")
            .expect("endpoint-scoped resolver");
        let error = wrong_endpoint
            .rewrite_header_value(&state.snapshot().child_env["API_KEY"])
            .expect_err("new handle must not resolve at the old endpoint");
        assert!(error.is_endpoint_mismatch());
    }

    #[test]
    fn aged_generation_falls_back_across_non_monotonic_same_identity_rotations() {
        let state = ProviderCredentialState::from_bound_environment(
            50,
            HashMap::from([("API_KEY".to_string(), "secret-50".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "API_KEY".to_string(),
                binding("api.example.com", 443, "/**"),
            )]),
            Vec::new(),
        )
        .expect("initial bindings");

        for revision in [10, 100, 9, 101, 8, 102, 7, 103, 6] {
            state
                .install_bound_environment(
                    revision,
                    HashMap::from([("API_KEY".to_string(), format!("secret-{revision}"))]),
                    HashMap::new(),
                    HashMap::new(),
                    HashMap::from([(
                        "API_KEY".to_string(),
                        binding("api.example.com", 443, "/**"),
                    )]),
                    Vec::new(),
                )
                .expect("rotated bindings");
        }

        let resolver = state
            .resolver_for_endpoint("api.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v50_API_KEY"),
            Some("secret-6"),
            "an aged-out placeholder may use the current secret across revisions in both numeric directions while its provider identity is unchanged"
        );
    }

    #[test]
    fn replacing_provider_with_reused_key_purges_retained_generation() {
        let state = ProviderCredentialState::from_bound_environment(
            u64::MAX,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");
        let mut replacement_binding = binding("b.example.com", 443, "/**");
        replacement_binding.credential_identity = "provider-b:API_KEY".to_string();

        state
            .install_bound_environment(
                1,
                HashMap::from([("API_KEY".to_string(), "provider-b-secret".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), replacement_binding)]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let resolver = state
            .resolver_for_endpoint("b.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder(&format!("openshell:resolve:env:v{}_API_KEY", u64::MAX)),
            None,
            "an opaque revision from another provider identity must fail closed even when it is numerically greater"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:API_KEY"),
            None,
            "an identityless canonical placeholder must not resolve a replacement provider"
        );
        assert_eq!(
            resolver.resolve_placeholder("vendor-OPENSHELL-RESOLVE-ENV-API_KEY"),
            None,
            "an identityless provider alias must not resolve a replacement provider"
        );
        assert_eq!(
            resolver
                .resolve_current_env_key_checked("API_KEY", "trusted-transform")
                .expect("binding authorizes the endpoint"),
            Some("provider-b-secret"),
            "trusted supervisor transforms may select the current bound credential by key"
        );
    }

    #[test]
    fn failed_refresh_then_replacement_with_reused_key_rejects_old_placeholder() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");
        state.revoke_static_provider_environment(2);

        let mut replacement_binding = binding("b.example.com", 443, "/**");
        replacement_binding.credential_identity = "provider-b:API_KEY".to_string();
        state
            .install_bound_environment(
                3,
                HashMap::from([("API_KEY".to_string(), "provider-b-secret".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), replacement_binding)]),
                Vec::new(),
            )
            .expect("replacement bindings");

        let resolver = state
            .resolver_for_endpoint("b.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            None,
            "a placeholder issued before detach must not resolve to a replacement provider"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:API_KEY"),
            None,
            "an identityless canonical placeholder must not cross a failed refresh into a replacement identity"
        );
        assert_eq!(
            resolver.resolve_placeholder("vendor-OPENSHELL-RESOLVE-ENV-API_KEY"),
            None,
            "an identityless provider alias must not cross a failed refresh into a replacement identity"
        );
    }

    #[test]
    fn successful_empty_environment_clears_failed_refresh_identity_tombstones() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([("API_KEY".to_string(), "provider-a-secret".to_string())]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
            Vec::new(),
        )
        .expect("initial bindings");

        state.revoke_static_provider_environment(2);
        state
            .install_bound_environment(
                3,
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                Vec::new(),
            )
            .expect("successful detached environment");
        state
            .install_bound_environment(
                4,
                HashMap::from([("API_KEY".to_string(), "reattached".to_string())]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([("API_KEY".to_string(), binding("a.example.com", 443, "/**"))]),
                Vec::new(),
            )
            .expect("reattached environment");

        let resolver = state
            .resolver_for_endpoint("a.example.com", 443, "/v1")
            .expect("resolver");
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v1_API_KEY"),
            None,
            "a successful empty environment represents detach and must invalidate old membership"
        );
        assert_eq!(
            resolver.resolve_placeholder("openshell:resolve:env:v4_API_KEY"),
            Some("reattached")
        );
    }

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
        let state = ProviderCredentialState::from_bound_environment(
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
            HashMap::from([(
                "GCP_ADC_ACCESS_TOKEN".to_string(),
                binding("oauth2.googleapis.com", 443, "/**"),
            )]),
            vec![
                "GCE_METADATA_HOST".to_string(),
                "GCP_PROJECT_ID".to_string(),
                "CLOUD_ML_REGION".to_string(),
            ],
        )
        .expect("classified GCP environment");
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
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                ("GCE_METADATA_HOST".to_string(), "marker".to_string()),
                ("GCP_ADC_ACCESS_TOKEN".to_string(), "ya29.tok".to_string()),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::from([(
                "GCP_ADC_ACCESS_TOKEN".to_string(),
                binding("oauth2.googleapis.com", 443, "/**"),
            )]),
            vec!["GCE_METADATA_HOST".to_string()],
        )
        .expect("classified GCP environment");
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
        assert_eq!(
            placeholder, "openshell:resolve:env:v1_GCP_SA_ACCESS_TOKEN",
            "metadata must return the current revision-scoped SA placeholder"
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
        assert_eq!(
            placeholder, "openshell:resolve:env:v1_GCP_ADC_ACCESS_TOKEN",
            "metadata must return the current revision-scoped ADC placeholder"
        );
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
    fn gcp_token_response_handles_already_expired_token_without_panic() {
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
            HashMap::from([("GCP_ADC_ACCESS_TOKEN".to_string(), now_ms - 1_000)]),
            HashMap::new(),
        );
        assert!(
            state.gcp_token_response().is_none(),
            "expired token should be skipped rather than panic"
        );
    }

    #[test]
    fn child_env_with_gcp_resolved_resolves_vertex_vars_without_metadata_host() {
        let state = ProviderCredentialState::from_bound_environment(
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
            HashMap::new(),
            vec![
                "GOOSE_PROVIDER".to_string(),
                "ANTHROPIC_VERTEX_PROJECT_ID".to_string(),
                "VERTEX_LOCATION".to_string(),
            ],
        )
        .expect("classified Vertex environment");
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
    fn child_env_with_gcp_resolved_only_unwraps_explicitly_non_secret_config() {
        let state = ProviderCredentialState::from_bound_environment(
            1,
            HashMap::from([
                (
                    "GOOGLE_CLOUD_PROJECT".to_string(),
                    "initial-project-config".to_string(),
                ),
                (
                    "GCP_PROJECT_ID".to_string(),
                    "visible-project-config".to_string(),
                ),
            ]),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            vec![
                "GOOGLE_CLOUD_PROJECT".to_string(),
                "GCP_PROJECT_ID".to_string(),
            ],
        )
        .expect("classified GCP environment");

        state
            .install_bound_environment(
                2,
                HashMap::from([
                    (
                        "GOOGLE_CLOUD_PROJECT".to_string(),
                        "bound-project-secret".to_string(),
                    ),
                    (
                        "GCP_PROJECT_ID".to_string(),
                        "visible-project-config".to_string(),
                    ),
                ]),
                HashMap::new(),
                HashMap::new(),
                HashMap::from([(
                    "GOOGLE_CLOUD_PROJECT".to_string(),
                    binding("example.googleapis.com", 443, "/**"),
                )]),
                vec!["GCP_PROJECT_ID".to_string()],
            )
            .expect("refreshed GCP environment");

        let env = state.child_env_with_gcp_resolved();
        assert_eq!(
            env.get("GCP_PROJECT_ID").map(String::as_str),
            Some("visible-project-config"),
            "explicitly non-secret GCP config should be visible to the workload"
        );
        assert_eq!(
            env.get("GOOGLE_CLOUD_PROJECT").map(String::as_str),
            Some("openshell:resolve:env:v2_GOOGLE_CLOUD_PROJECT"),
            "a reserved GCP name classified as a bound credential must stay placeholderized"
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
