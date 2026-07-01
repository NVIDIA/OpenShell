// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-local provider profile sources.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use openshell_core::proto::{ProviderProfile, StoredProviderProfile};
use openshell_gateway_interceptors::ProviderProfileSourceSnapshot as InterceptorProfileSnapshot;
use openshell_providers::{
    ProfileValidationDiagnostic, ProviderTypeProfile, builtin_profiles, normalize_profile_id,
    validate_profile_set,
};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tonic::Status;

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
    source_id: String,
    revision: String,
    profiles: Vec<ProviderProfile>,
    user_managed: bool,
    allow_empty: bool,
}

#[async_trait]
pub trait ProviderProfileSource: Send + Sync {
    async fn snapshot(&self, store: &Store) -> Result<ProviderProfileSnapshot, Status>;
}

#[derive(Debug, Clone, Default)]
struct BuiltinProviderProfileSource;

#[async_trait]
impl ProviderProfileSource for BuiltinProviderProfileSource {
    async fn snapshot(&self, _store: &Store) -> Result<ProviderProfileSnapshot, Status> {
        let profiles = builtin_profiles()
            .iter()
            .map(ProviderTypeProfile::to_proto)
            .collect::<Vec<_>>();
        Ok(ProviderProfileSnapshot {
            source_id: BUILTIN_SOURCE_ID.to_string(),
            revision: profile_snapshot_revision(&profiles),
            profiles,
            user_managed: false,
            allow_empty: false,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct UserProviderProfileSource;

#[async_trait]
impl ProviderProfileSource for UserProviderProfileSource {
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
            source_id: USER_SOURCE_ID.to_string(),
            revision: format!("sha256:{:x}", hasher.finalize()),
            profiles,
            user_managed: true,
            allow_empty: true,
        })
    }
}

#[derive(Debug, Clone)]
enum ConfiguredProviderProfileSource {
    Builtin(BuiltinProviderProfileSource),
    User(UserProviderProfileSource),
    Interceptors(openshell_gateway_interceptors::GatewayInterceptorRuntime),
}

#[derive(Debug, Clone)]
pub struct ProviderProfileSources {
    sources: Vec<ConfiguredProviderProfileSource>,
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
struct EffectiveProviderProfiles {
    profiles: BTreeMap<String, EffectiveProfileEntry>,
}

impl ProviderProfileSources {
    pub fn with_default_sources() -> Self {
        Self {
            sources: vec![
                ConfiguredProviderProfileSource::Builtin(BuiltinProviderProfileSource),
                ConfiguredProviderProfileSource::User(UserProviderProfileSource),
            ],
        }
    }

    pub fn from_gateway_interceptors(
        runtime: Option<openshell_gateway_interceptors::GatewayInterceptorRuntime>,
    ) -> Self {
        if let Some(runtime) = runtime
            && runtime.has_profile_sources()
        {
            return Self {
                sources: vec![ConfiguredProviderProfileSource::Interceptors(runtime)],
            };
        }
        Self::with_default_sources()
    }

    pub async fn list_profiles(&self, store: &Store) -> Result<Vec<ProviderProfile>, Status> {
        let catalog = self.effective_profiles(store).await?;
        Ok(catalog
            .profiles
            .values()
            .map(|entry| entry.response.clone())
            .collect())
    }

    pub async fn get_profile(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Option<ProviderProfile>, Status> {
        let Some(id) = normalize_profile_id(id) else {
            return Ok(None);
        };
        Ok(self
            .effective_profiles(store)
            .await?
            .profiles
            .get(&id)
            .map(|entry| entry.response.clone()))
    }

    pub async fn get_type_profile(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Option<ProviderTypeProfile>, Status> {
        let Some(id) = normalize_profile_id(id) else {
            return Ok(None);
        };
        Ok(self
            .effective_profiles(store)
            .await?
            .profiles
            .get(&id)
            .map(|entry| entry.profile.clone()))
    }

    pub async fn static_source_for_profile(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Option<String>, Status> {
        let Some(id) = normalize_profile_id(id) else {
            return Ok(None);
        };
        Ok(self
            .effective_profiles(store)
            .await?
            .profiles
            .get(&id)
            .filter(|entry| !entry.user_managed)
            .map(|entry| entry.source_id.clone()))
    }

    pub async fn hash_profile_revision(
        &self,
        store: &Store,
        profile_id: &str,
        hasher: &mut Sha256,
    ) -> Result<(), Status> {
        let Some(profile_id) = normalize_profile_id(profile_id) else {
            hasher.update(b"invalid-profile-id");
            return Ok(());
        };

        let catalog = self.effective_profiles(store).await?;
        let Some(entry) = catalog.profiles.get(&profile_id) else {
            hasher.update(b"missing");
            return Ok(());
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
        Ok(())
    }

    async fn effective_profiles(&self, store: &Store) -> Result<EffectiveProviderProfiles, Status> {
        let snapshots = self.snapshots(store).await?;
        build_effective_profiles(snapshots)
    }

    async fn snapshots(&self, store: &Store) -> Result<Vec<ProviderProfileSnapshot>, Status> {
        let mut snapshots = Vec::new();
        for source in &self.sources {
            match source {
                ConfiguredProviderProfileSource::Builtin(source) => {
                    snapshots.push(source.snapshot(store).await?);
                }
                ConfiguredProviderProfileSource::User(source) => {
                    snapshots.push(source.snapshot(store).await?);
                }
                ConfiguredProviderProfileSource::Interceptors(runtime) => {
                    let external = runtime.provider_profile_snapshots().await.map_err(|err| {
                        Status::unavailable(format!(
                            "provider profile source snapshot failed: {err}"
                        ))
                    })?;
                    snapshots.extend(external.into_iter().map(interceptor_snapshot));
                }
            }
        }
        Ok(snapshots)
    }
}

fn interceptor_snapshot(snapshot: InterceptorProfileSnapshot) -> ProviderProfileSnapshot {
    ProviderProfileSnapshot {
        source_id: snapshot.source_id,
        revision: snapshot.revision,
        profiles: snapshot.profiles,
        user_managed: false,
        allow_empty: false,
    }
}

fn build_effective_profiles(
    snapshots: Vec<ProviderProfileSnapshot>,
) -> Result<EffectiveProviderProfiles, Status> {
    let mut source_ids = BTreeSet::new();
    let mut profiles = BTreeMap::new();

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
        if snapshot.profiles.is_empty() && !snapshot.allow_empty {
            return Err(Status::failed_precondition(format!(
                "provider profile source '{source_id}' returned no profiles"
            )));
        }

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
            if profiles.contains_key(&id) {
                return Err(Status::failed_precondition(format!(
                    "duplicate provider profile id '{id}' across configured sources"
                )));
            }
            profiles.insert(
                id,
                EffectiveProfileEntry {
                    source_id: source_id.to_string(),
                    source_revision: snapshot.revision.clone(),
                    user_managed: snapshot.user_managed,
                    profile: ProviderTypeProfile::from_proto(&profile),
                    response: profile,
                },
            );
        }
    }

    Ok(EffectiveProviderProfiles { profiles })
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
mod tests {
    use super::*;

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

    #[test]
    fn duplicate_profile_ids_across_sources_are_invalid() {
        let err = build_effective_profiles(vec![
            ProviderProfileSnapshot {
                source_id: "source-a".to_string(),
                revision: "a".to_string(),
                profiles: vec![profile("github")],
                user_managed: false,
                allow_empty: false,
            },
            ProviderProfileSnapshot {
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
    fn source_managed_profiles_report_static_source() {
        let catalog = build_effective_profiles(vec![ProviderProfileSnapshot {
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
