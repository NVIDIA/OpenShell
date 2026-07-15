// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-local provider profile sources.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use openshell_core::GatewayProviderProfileSourceConfig;
use openshell_core::proto::{ProviderProfile, StoredProviderProfile};
use openshell_gateway_interceptors::{
    GatewayInterceptorProfileSource, GatewayInterceptorRuntime,
    ProviderProfileSourceSnapshot as InterceptorProfileSnapshot,
};
use openshell_providers::{
    ProfileValidationDiagnostic, ProviderTypeProfile, builtin_profiles, normalize_profile_id,
    validate_profile_set,
};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tonic::Status;
use tracing::debug;

use crate::persistence::{ObjectType, Store};

const BUILTIN_SOURCE_ID: &str = "builtin";
const USER_SOURCE_ID: &str = "user";

impl ObjectType for StoredProviderProfile {
    fn object_type() -> &'static str {
        "provider_profile"
    }
}

#[derive(Debug, Clone)]
pub struct ProviderProfileSnapshot {
    revision: String,
    profiles: Vec<ProviderProfile>,
}

#[async_trait]
pub trait ProviderProfileSource: Send + Sync + std::fmt::Debug {
    fn source_id(&self) -> &str;
    fn user_managed(&self) -> bool;
    fn allow_empty(&self) -> bool;
    async fn snapshot(&self, store: &Store) -> Result<ProviderProfileSnapshot, Status>;
}

#[derive(Debug, Clone, Default)]
struct BuiltinProviderProfileSource;

#[async_trait]
impl ProviderProfileSource for BuiltinProviderProfileSource {
    fn source_id(&self) -> &str {
        BUILTIN_SOURCE_ID
    }

    fn user_managed(&self) -> bool {
        false
    }

    fn allow_empty(&self) -> bool {
        false
    }

    async fn snapshot(&self, _store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        let profiles = builtin_profiles()
            .iter()
            .map(ProviderTypeProfile::to_proto)
            .collect::<Vec<_>>();
        Ok(ProviderProfileSnapshot {
            revision: profile_snapshot_revision(&profiles),
            profiles,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct UserProviderProfileSource;

#[async_trait]
impl ProviderProfileSource for UserProviderProfileSource {
    fn source_id(&self) -> &str {
        USER_SOURCE_ID
    }

    fn user_managed(&self) -> bool {
        true
    }

    fn allow_empty(&self) -> bool {
        true
    }

    async fn snapshot(&self, store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        let stored = user_provider_profiles(store).await?;
        let mut profiles = Vec::new();
        let mut hasher = Sha256::new();
        hasher.update(b"openshell-user-provider-profile-source-v1");
        for stored in stored {
            let resource_version = stored_profile_resource_version(&stored);
            hasher.update(resource_version.to_le_bytes());
            if let Some(profile) = stored.profile {
                let profile = profile_response_payload(profile, resource_version);
                hasher.update(profile.encode_to_vec());
                profiles.push(profile);
            }
        }
        Ok(ProviderProfileSnapshot {
            revision: format!("sha256:{:x}", hasher.finalize()),
            profiles,
        })
    }
}

#[async_trait]
impl ProviderProfileSource for GatewayInterceptorProfileSource {
    fn source_id(&self) -> &str {
        Self::source_id(self)
    }

    fn user_managed(&self) -> bool {
        false
    }

    fn allow_empty(&self) -> bool {
        false
    }

    async fn snapshot(&self, _store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        let InterceptorProfileSnapshot { revision, profiles } =
            Self::snapshot(self).await.map_err(|err| {
                Status::unavailable(format!(
                    "provider profile source '{}' snapshot failed: {err}",
                    self.source_id()
                ))
            })?;
        Ok(ProviderProfileSnapshot { revision, profiles })
    }
}

#[derive(Debug, Clone)]
pub struct ProviderProfileSources {
    sources: Vec<Arc<dyn ProviderProfileSource>>,
}

#[derive(Debug, Clone)]
struct CollectedProviderProfileSnapshot {
    source_id: String,
    revision: String,
    profiles: Vec<ProviderProfile>,
    user_managed: bool,
    allow_empty: bool,
}

#[derive(Debug, Clone)]
struct EffectiveProfileEntry {
    source_id: String,
    source_revision: String,
    user_managed: bool,
    profile: ProviderTypeProfile,
    response: ProviderProfile,
}

#[derive(Debug, Clone)]
pub struct EffectiveProviderProfileCatalog {
    profiles: BTreeMap<String, EffectiveProfileEntry>,
    revision: String,
    source_count: usize,
}

impl ProviderProfileSources {
    pub fn with_default_sources() -> Self {
        Self {
            sources: vec![
                Arc::new(BuiltinProviderProfileSource),
                Arc::new(UserProviderProfileSource),
            ],
        }
    }

    pub fn from_config(
        configured: &[GatewayProviderProfileSourceConfig],
        runtime: Option<&GatewayInterceptorRuntime>,
    ) -> Result<Self, String> {
        if configured.is_empty() {
            return Err("provider_profile_sources must contain at least one source".to_string());
        }

        let mut source_ids = BTreeSet::new();
        let mut sources: Vec<Arc<dyn ProviderProfileSource>> = Vec::with_capacity(configured.len());
        for source in configured {
            let source: Arc<dyn ProviderProfileSource> = match source {
                GatewayProviderProfileSourceConfig::Builtin => {
                    Arc::new(BuiltinProviderProfileSource)
                }
                GatewayProviderProfileSourceConfig::User => Arc::new(UserProviderProfileSource),
                GatewayProviderProfileSourceConfig::Interceptor { name } => {
                    if name.trim().is_empty() {
                        return Err("provider profile interceptor source name must not be empty"
                            .to_string());
                    }
                    let source = runtime
                        .and_then(|runtime| runtime.provider_profile_source(name))
                        .ok_or_else(|| {
                            format!(
                                "provider profile source interceptor '{name}' is not configured or does not advertise provider_profiles"
                            )
                        })?;
                    Arc::new(source)
                }
            };
            let source_id = source.source_id().to_string();
            if !source_ids.insert(source_id.clone()) {
                return Err(format!(
                    "duplicate provider profile source '{source_id}' in provider_profile_sources"
                ));
            }
            sources.push(source);
        }
        Ok(Self { sources })
    }

    pub fn source_ids(&self) -> Vec<&str> {
        self.sources
            .iter()
            .map(|source| source.source_id())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn from_test_profiles(profiles: Vec<ProviderProfile>) -> Self {
        Self {
            sources: vec![Arc::new(StaticProviderProfileSource {
                snapshot: ProviderProfileSnapshot {
                    revision: profile_snapshot_revision(&profiles),
                    profiles,
                },
            })],
        }
    }

    #[cfg(test)]
    pub(crate) fn from_test_snapshot_sequence(
        snapshots: Vec<(String, Vec<ProviderProfile>)>,
        fetch_count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        assert!(
            !snapshots.is_empty(),
            "test snapshot sequence must not be empty"
        );
        Self {
            sources: vec![Arc::new(SequencedProviderProfileSource {
                snapshots: snapshots
                    .into_iter()
                    .map(|(revision, profiles)| ProviderProfileSnapshot { revision, profiles })
                    .collect(),
                fetch_count,
            })],
        }
    }

    pub(crate) async fn snapshot_catalog(
        &self,
        store: &Store,
    ) -> Result<EffectiveProviderProfileCatalog, Status> {
        let snapshots = self.snapshots(store).await?;
        let catalog = build_effective_profiles(snapshots)?;
        debug!(
            catalog_revision = %catalog.revision(),
            source_fetch_count = catalog.source_count(),
            profile_count = catalog.profiles.len(),
            "captured provider profile catalog snapshot"
        );
        Ok(catalog)
    }

    async fn snapshots(
        &self,
        store: &Store,
    ) -> Result<Vec<CollectedProviderProfileSnapshot>, Status> {
        let mut snapshots = Vec::with_capacity(self.sources.len());
        for source in &self.sources {
            let snapshot = source.snapshot(store).await?;
            snapshots.push(CollectedProviderProfileSnapshot {
                source_id: source.source_id().to_string(),
                revision: snapshot.revision,
                profiles: snapshot.profiles,
                user_managed: source.user_managed(),
                allow_empty: source.allow_empty(),
            });
        }
        Ok(snapshots)
    }
}

impl EffectiveProviderProfileCatalog {
    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }

    pub(crate) fn source_count(&self) -> usize {
        self.source_count
    }

    pub(crate) fn list_profiles(&self) -> Vec<ProviderProfile> {
        self.profiles
            .values()
            .map(|entry| entry.response.clone())
            .collect()
    }

    pub(crate) fn get_profile(&self, id: &str) -> Option<ProviderProfile> {
        let id = normalize_profile_id(id)?;
        self.profiles.get(&id).map(|entry| entry.response.clone())
    }

    pub(crate) fn get_type_profile(&self, id: &str) -> Option<ProviderTypeProfile> {
        let id = normalize_profile_id(id)?;
        self.profiles.get(&id).map(|entry| entry.profile.clone())
    }

    pub(crate) fn static_source_for_profile(&self, id: &str) -> Option<String> {
        let id = normalize_profile_id(id)?;
        self.profiles
            .get(&id)
            .filter(|entry| !entry.user_managed)
            .map(|entry| entry.source_id.clone())
    }

    pub(crate) fn hash_profile_revision(&self, profile_id: &str, hasher: &mut Sha256) {
        let Some(profile_id) = normalize_profile_id(profile_id) else {
            hasher.update(b"invalid-profile-id");
            return;
        };

        let Some(entry) = self.profiles.get(&profile_id) else {
            hasher.update(b"missing");
            return;
        };

        hasher.update(b"provider-profile-source-entry");
        hasher.update(entry.source_id.as_bytes());
        hasher.update(entry.source_revision.as_bytes());
        let ownership_tag: &[u8] = if entry.user_managed {
            b"user-managed"
        } else {
            b"source-managed"
        };
        hasher.update(ownership_tag);
        hasher.update(entry.response.encode_to_vec());
    }
}

fn build_effective_profiles(
    snapshots: Vec<CollectedProviderProfileSnapshot>,
) -> Result<EffectiveProviderProfileCatalog, Status> {
    let mut source_ids = BTreeSet::new();
    let mut profiles: BTreeMap<String, EffectiveProfileEntry> = BTreeMap::new();
    let source_count = snapshots.len();
    let mut catalog_hasher = Sha256::new();
    catalog_hasher.update(b"openshell-effective-provider-profile-catalog-v1");

    for snapshot in snapshots {
        let source_id = snapshot.source_id.trim();
        if source_id.is_empty() {
            return Err(Status::failed_precondition(
                "provider profile source id must not be empty",
            ));
        }
        if !source_ids.insert(source_id.to_string()) {
            return Err(Status::failed_precondition(format!(
                "duplicate provider profile source id '{source_id}'"
            )));
        }
        let source_revision = snapshot.revision.trim();
        if source_revision.is_empty() {
            return Err(Status::failed_precondition(format!(
                "provider profile source '{source_id}' returned an empty revision"
            )));
        }
        if snapshot.profiles.is_empty() && !snapshot.allow_empty {
            return Err(Status::failed_precondition(format!(
                "provider profile source '{source_id}' returned no profiles"
            )));
        }

        catalog_hasher.update((source_id.len() as u64).to_le_bytes());
        catalog_hasher.update(source_id.as_bytes());
        catalog_hasher.update((source_revision.len() as u64).to_le_bytes());
        catalog_hasher.update(source_revision.as_bytes());

        let source_profiles = snapshot
            .profiles
            .iter()
            .map(|profile| {
                (
                    source_id.to_string(),
                    ProviderTypeProfile::from_proto(profile),
                )
            })
            .collect::<Vec<_>>();
        validate_source_profiles(source_id, &source_profiles)?;

        for profile in snapshot.profiles {
            let id = normalize_profile_id(&profile.id).ok_or_else(|| {
                Status::failed_precondition(format!(
                    "provider profile '{}' in source '{}' has invalid id",
                    profile.id, source_id
                ))
            })?;
            if let Some(existing) = profiles.get(&id) {
                let location = if existing.source_id == source_id {
                    format!("within source '{source_id}'")
                } else {
                    format!(
                        "across configured sources '{}' and '{source_id}'",
                        existing.source_id
                    )
                };
                return Err(Status::failed_precondition(format!(
                    "duplicate provider profile id '{id}' {location}"
                )));
            }
            profiles.insert(
                id,
                EffectiveProfileEntry {
                    source_id: source_id.to_string(),
                    source_revision: source_revision.to_string(),
                    user_managed: snapshot.user_managed,
                    profile: ProviderTypeProfile::from_proto(&profile),
                    response: profile,
                },
            );
        }
    }

    Ok(EffectiveProviderProfileCatalog {
        profiles,
        revision: format!("sha256:{:x}", catalog_hasher.finalize()),
        source_count,
    })
}

fn validate_source_profiles(
    source_id: &str,
    profiles: &[(String, ProviderTypeProfile)],
) -> Result<(), Status> {
    let diagnostics = validate_profile_set(profiles);
    if let Some(diagnostic) = diagnostics
        .into_iter()
        .find(|diagnostic| diagnostic.severity == "error")
    {
        return Err(Status::failed_precondition(format!(
            "provider profile source '{source_id}' is invalid: {}",
            format_diagnostic(diagnostic)
        )));
    }
    Ok(())
}

fn format_diagnostic(diagnostic: ProfileValidationDiagnostic) -> String {
    if diagnostic.profile_id.is_empty() {
        format!("{}: {}", diagnostic.field, diagnostic.message)
    } else {
        format!(
            "provider profile '{}' {}: {}",
            diagnostic.profile_id, diagnostic.field, diagnostic.message
        )
    }
}

fn profile_snapshot_revision(profiles: &[ProviderProfile]) -> String {
    let mut profiles = profiles.to_vec();
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let mut hasher = Sha256::new();
    hasher.update(b"openshell-provider-profile-snapshot-v1");
    for profile in profiles {
        hasher.update(profile.encode_to_vec());
    }
    format!("sha256:{:x}", hasher.finalize())
}

pub async fn user_provider_profiles(store: &Store) -> Result<Vec<StoredProviderProfile>, Status> {
    let profiles: Vec<StoredProviderProfile> = store
        .list_messages(10_000, 0)
        .await
        .map_err(|e| Status::internal(format!("list provider profiles failed: {e}")))?;
    Ok(profiles)
}

pub fn stored_provider_profile(profile: ProviderProfile) -> StoredProviderProfile {
    use crate::persistence::current_time_ms;
    let now_ms = current_time_ms();
    let profile = profile_storage_payload(profile);
    StoredProviderProfile {
        metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
            id: uuid::Uuid::new_v4().to_string(),
            name: profile.id.clone(),
            created_at_ms: now_ms,
            labels: std::collections::HashMap::new(),
            resource_version: 0,
            annotations: std::collections::HashMap::new(),
        }),
        profile: Some(profile),
    }
}

pub fn profile_storage_payload(mut profile: ProviderProfile) -> ProviderProfile {
    profile.resource_version = 0;
    profile
}

pub fn profile_response_payload(
    mut profile: ProviderProfile,
    resource_version: u64,
) -> ProviderProfile {
    profile.resource_version = resource_version;
    profile
}

pub fn stored_profile_resource_version(stored: &StoredProviderProfile) -> u64 {
    stored
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version)
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct StaticProviderProfileSource {
    snapshot: ProviderProfileSnapshot,
}

#[cfg(test)]
#[async_trait]
impl ProviderProfileSource for StaticProviderProfileSource {
    fn source_id(&self) -> &'static str {
        "test"
    }

    fn user_managed(&self) -> bool {
        false
    }

    fn allow_empty(&self) -> bool {
        false
    }

    async fn snapshot(&self, _store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        Ok(self.snapshot.clone())
    }
}

#[cfg(test)]
#[derive(Debug)]
struct SequencedProviderProfileSource {
    snapshots: Vec<ProviderProfileSnapshot>,
    fetch_count: Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(test)]
#[async_trait]
impl ProviderProfileSource for SequencedProviderProfileSource {
    fn source_id(&self) -> &'static str {
        "sequenced"
    }

    fn user_managed(&self) -> bool {
        false
    }

    fn allow_empty(&self) -> bool {
        false
    }

    async fn snapshot(&self, _store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        let index = self
            .fetch_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(self.snapshots[index.min(self.snapshots.len() - 1)].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_core::GatewayInterceptorConfig;
    use openshell_core::proto::gateway_interceptor::v1::{
        DescribeRequest, InterceptorEvaluation, InterceptorManifest, InterceptorResult,
        ProviderProfileSnapshot as ProtoProviderProfileSnapshot, ProviderProfileSnapshotRequest,
        gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response};

    #[derive(Clone)]
    struct MockProfileInterceptor {
        advertises_profiles: bool,
        snapshot: ProtoProviderProfileSnapshot,
    }

    #[tonic::async_trait]
    impl GatewayInterceptor for MockProfileInterceptor {
        async fn describe(
            &self,
            _request: Request<DescribeRequest>,
        ) -> Result<Response<InterceptorManifest>, Status> {
            Ok(Response::new(InterceptorManifest {
                name: "mock-profile-source".to_string(),
                provider_profiles: self.advertises_profiles,
                ..InterceptorManifest::default()
            }))
        }

        async fn evaluate(
            &self,
            _request: Request<InterceptorEvaluation>,
        ) -> Result<Response<InterceptorResult>, Status> {
            Ok(Response::new(InterceptorResult {
                allowed: true,
                ..InterceptorResult::default()
            }))
        }

        async fn snapshot_provider_profiles(
            &self,
            _request: Request<ProviderProfileSnapshotRequest>,
        ) -> Result<Response<ProtoProviderProfileSnapshot>, Status> {
            if self.snapshot.revision == "test:unavailable" {
                return Err(Status::unavailable("mock profile source unavailable"));
            }
            Ok(Response::new(self.snapshot.clone()))
        }
    }

    async fn interceptor_runtime(
        snapshot: ProtoProviderProfileSnapshot,
        advertises_profiles: bool,
    ) -> (GatewayInterceptorRuntime, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(GatewayInterceptorServer::new(MockProfileInterceptor {
                    advertises_profiles,
                    snapshot,
                }))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        let runtime = openshell_gateway_interceptors::initialize(vec![GatewayInterceptorConfig {
            name: "governance".to_string(),
            grpc_endpoint: format!("http://{address}"),
            ..GatewayInterceptorConfig::default()
        }])
        .await
        .unwrap()
        .unwrap();
        (runtime, task)
    }

    fn profile(id: &str) -> ProviderProfile {
        let mut profile = builtin_profiles()
            .iter()
            .find(|profile| profile.id == "github")
            .expect("github built-in profile")
            .clone();
        profile.id = id.to_string();
        profile.display_name = id.to_string();
        profile.to_proto()
    }

    #[tokio::test]
    async fn captured_catalog_is_immutable_and_each_source_is_fetched_once() {
        let mut revision_a = profile("moving-profile");
        revision_a.display_name = "revision-a".to_string();
        let mut revision_b = revision_a.clone();
        revision_b.display_name = "revision-b".to_string();
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let sources = ProviderProfileSources::from_test_snapshot_sequence(
            vec![
                ("revision-a".to_string(), vec![revision_a]),
                ("revision-b".to_string(), vec![revision_b]),
            ],
            Arc::clone(&fetch_count),
        );
        let store = crate::persistence::test_store().await;

        let first = sources.snapshot_catalog(&store).await.unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
        assert_eq!(first.source_count(), 1);
        assert_eq!(
            first.get_profile("moving-profile").unwrap().display_name,
            "revision-a"
        );
        assert!(first.get_type_profile("moving-profile").is_some());
        let mut first_profile_hash = Sha256::new();
        first.hash_profile_revision("moving-profile", &mut first_profile_hash);
        let first_profile_hash = first_profile_hash.finalize();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);

        let second = sources.snapshot_catalog(&store).await.unwrap();
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2);
        assert_eq!(
            second.get_profile("moving-profile").unwrap().display_name,
            "revision-b"
        );
        let mut second_profile_hash = Sha256::new();
        second.hash_profile_revision("moving-profile", &mut second_profile_hash);
        assert_ne!(first_profile_hash, second_profile_hash.finalize());
        assert_ne!(first.revision(), second.revision());
    }

    #[test]
    fn empty_source_revision_is_invalid() {
        let err = build_effective_profiles(vec![CollectedProviderProfileSnapshot {
            source_id: "source-a".to_string(),
            revision: "  ".to_string(),
            profiles: vec![profile("github")],
            user_managed: false,
            allow_empty: false,
        }])
        .unwrap_err();

        assert!(err.message().contains("returned an empty revision"));
    }

    #[test]
    fn duplicate_profile_ids_across_sources_are_invalid() {
        let err = build_effective_profiles(vec![
            CollectedProviderProfileSnapshot {
                source_id: "source-a".to_string(),
                revision: "a".to_string(),
                profiles: vec![profile("github")],
                user_managed: false,
                allow_empty: false,
            },
            CollectedProviderProfileSnapshot {
                source_id: "source-b".to_string(),
                revision: "b".to_string(),
                profiles: vec![profile("github")],
                user_managed: false,
                allow_empty: false,
            },
        ])
        .unwrap_err();

        assert!(err.message().contains("duplicate provider profile id"));
    }

    #[test]
    fn configured_local_sources_preserve_order() {
        let sources = ProviderProfileSources::from_config(
            &[
                GatewayProviderProfileSourceConfig::User,
                GatewayProviderProfileSourceConfig::Builtin,
            ],
            None,
        )
        .unwrap();

        assert_eq!(sources.source_ids(), vec!["user", "builtin"]);
    }

    #[test]
    fn configured_sources_must_not_be_empty() {
        let err = ProviderProfileSources::from_config(&[], None).unwrap_err();
        assert!(err.contains("at least one source"));
    }

    #[test]
    fn configured_sources_must_be_unique() {
        let err = ProviderProfileSources::from_config(
            &[
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::Builtin,
            ],
            None,
        )
        .unwrap_err();
        assert!(err.contains("duplicate provider profile source 'builtin'"));
    }

    #[test]
    fn configured_interceptor_must_advertise_profile_capability() {
        let err = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            None,
        )
        .unwrap_err();
        assert!(err.contains("not configured or does not advertise provider_profiles"));
    }

    #[test]
    fn source_that_disallows_empty_snapshots_fails_closed() {
        let err = build_effective_profiles(vec![CollectedProviderProfileSnapshot {
            source_id: "interceptor/test".to_string(),
            revision: "empty".to_string(),
            profiles: Vec::new(),
            user_managed: false,
            allow_empty: false,
        }])
        .unwrap_err();

        assert!(err.message().contains("returned no profiles"));
    }

    #[test]
    fn user_source_may_return_an_empty_snapshot() {
        let catalog = build_effective_profiles(vec![CollectedProviderProfileSnapshot {
            source_id: "user".to_string(),
            revision: "empty".to_string(),
            profiles: Vec::new(),
            user_managed: true,
            allow_empty: true,
        }])
        .unwrap();

        assert!(catalog.profiles.is_empty());
    }

    #[test]
    fn invalid_profile_semantics_fail_closed() {
        let err = build_effective_profiles(vec![CollectedProviderProfileSnapshot {
            source_id: "interceptor/test".to_string(),
            revision: "invalid".to_string(),
            profiles: vec![profile("GitHub")],
            user_managed: false,
            allow_empty: false,
        }])
        .unwrap_err();

        assert!(
            err.message()
                .contains("provider profile source 'interceptor/test' is invalid")
        );
    }

    #[tokio::test]
    async fn interceptor_snapshot_passes_through_adapter_and_validation_boundary() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: String::new(),
                profiles: vec![profile("github")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let profiles = sources
            .snapshot_catalog(&store)
            .await
            .unwrap()
            .list_profiles();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "github");
        let snapshot = runtime
            .provider_profile_source("governance")
            .unwrap()
            .snapshot()
            .await
            .unwrap();
        assert!(snapshot.revision.starts_with("sha256:"));
        task.abort();
    }

    #[tokio::test]
    async fn empty_interceptor_snapshot_received_over_adapter_fails_closed() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "empty".to_string(),
                profiles: Vec::new(),
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let err = sources.snapshot_catalog(&store).await.unwrap_err();
        assert!(err.message().contains("returned no profiles"));
        task.abort();
    }

    #[tokio::test]
    async fn invalid_interceptor_snapshot_received_over_adapter_fails_closed() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "invalid".to_string(),
                profiles: vec![profile("GitHub")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let err = sources.snapshot_catalog(&store).await.unwrap_err();
        assert!(err.message().contains("is invalid"));
        task.abort();
    }

    #[tokio::test]
    async fn distinct_local_and_interceptor_profiles_compose() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "external".to_string(),
                profiles: vec![profile("governed-github")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::Interceptor {
                    name: "governance".to_string(),
                },
            ],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let profiles = sources
            .snapshot_catalog(&store)
            .await
            .unwrap()
            .list_profiles();
        assert!(profiles.iter().any(|profile| profile.id == "github"));
        assert!(
            profiles
                .iter()
                .any(|profile| profile.id == "governed-github")
        );
        task.abort();
    }

    #[tokio::test]
    async fn duplicate_profile_ids_across_local_and_interceptor_sources_fail_closed() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "external".to_string(),
                profiles: vec![profile("github")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::Interceptor {
                    name: "governance".to_string(),
                },
            ],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let err = sources.snapshot_catalog(&store).await.unwrap_err();
        assert!(
            err.message()
                .contains("duplicate provider profile id 'github'")
        );
        task.abort();
    }

    #[tokio::test]
    async fn duplicate_profiles_within_interceptor_snapshot_fail_closed() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "duplicates".to_string(),
                profiles: vec![profile("github"), profile("github")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let err = sources.snapshot_catalog(&store).await.unwrap_err();
        assert!(err.message().contains("duplicate provider profile id"));
        task.abort();
    }

    #[tokio::test]
    async fn unavailable_selected_interceptor_does_not_fall_back() {
        let (runtime, task) = interceptor_runtime(
            ProtoProviderProfileSnapshot {
                revision: "test:unavailable".to_string(),
                profiles: vec![profile("governed-github")],
            },
            true,
        )
        .await;
        let sources = ProviderProfileSources::from_config(
            &[
                GatewayProviderProfileSourceConfig::Builtin,
                GatewayProviderProfileSourceConfig::Interceptor {
                    name: "governance".to_string(),
                },
            ],
            Some(&runtime),
        )
        .unwrap();
        let store = crate::persistence::test_store().await;

        let err = sources.snapshot_catalog(&store).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        task.abort();
    }

    #[tokio::test]
    async fn interceptor_without_profile_capability_cannot_be_selected() {
        let (runtime, task) =
            interceptor_runtime(ProtoProviderProfileSnapshot::default(), false).await;
        let err = ProviderProfileSources::from_config(
            &[GatewayProviderProfileSourceConfig::Interceptor {
                name: "governance".to_string(),
            }],
            Some(&runtime),
        )
        .unwrap_err();

        assert!(err.contains("does not advertise provider_profiles"));
        task.abort();
    }

    #[test]
    fn source_managed_profiles_report_static_source() {
        let catalog = build_effective_profiles(vec![CollectedProviderProfileSnapshot {
            source_id: "interceptor/test".to_string(),
            revision: "test".to_string(),
            profiles: vec![profile("slack")],
            user_managed: false,
            allow_empty: false,
        }])
        .unwrap();

        let entry = catalog.profiles.get("slack").unwrap();
        assert_eq!(entry.source_id, "interceptor/test");
        assert!(!entry.user_managed);
    }
}
