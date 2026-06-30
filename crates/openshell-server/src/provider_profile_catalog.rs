// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Gateway-local provider profile catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use openshell_core::proto::{ProviderProfile, StoredProviderProfile};
use openshell_providers::{
    ProfileValidationDiagnostic, ProviderTypeProfile, builtin_profiles, normalize_profile_id,
    validate_profile_set,
};
use prost::Message as _;
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::persistence::{ObjectType, Store};

const BUILTIN_SOURCE_ID: &str = "builtin";

impl ObjectType for StoredProviderProfile {
    fn object_type() -> &'static str {
        "provider_profile"
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileCatalogSourceMode {
    Append,
    Authoritative,
}

impl ProfileCatalogSourceMode {
    const fn as_revision_tag(self) -> &'static [u8] {
        match self {
            Self::Append => b"append",
            Self::Authoritative => b"authoritative",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProfileCatalogSource {
    pub source_id: String,
    pub mode: ProfileCatalogSourceMode,
    pub profiles: Vec<ProviderTypeProfile>,
}

#[derive(Debug, Clone)]
struct StaticProfileEntry {
    source_id: String,
    mode: ProfileCatalogSourceMode,
    profile: ProviderTypeProfile,
}

#[derive(Debug, Clone)]
pub struct ProviderProfileCatalog {
    visible_static: Arc<BTreeMap<String, StaticProfileEntry>>,
    authoritative: bool,
}

impl ProviderProfileCatalog {
    pub fn from_interceptor_sources(
        sources: &[openshell_gateway_interceptors::ProfileCatalogSource],
    ) -> Result<Self, String> {
        let mut catalog_sources = vec![builtin_profile_source()];
        for source in sources {
            catalog_sources.push(ProfileCatalogSource {
                source_id: source.source_id.clone(),
                mode: match source.mode {
                    openshell_gateway_interceptors::ProfileCatalogMode::Append => {
                        ProfileCatalogSourceMode::Append
                    }
                    openshell_gateway_interceptors::ProfileCatalogMode::Authoritative => {
                        ProfileCatalogSourceMode::Authoritative
                    }
                },
                profiles: source
                    .profiles
                    .iter()
                    .map(ProviderTypeProfile::from_proto)
                    .collect(),
            });
        }
        Self::from_sources(catalog_sources)
    }

    pub fn with_builtin_profiles() -> Self {
        Self::from_sources(vec![builtin_profile_source()])
            .expect("built-in provider profiles must form a valid catalog")
    }

    pub fn from_sources(sources: Vec<ProfileCatalogSource>) -> Result<Self, String> {
        let mut source_ids = BTreeSet::new();
        let authoritative_count = sources
            .iter()
            .filter(|source| source.mode == ProfileCatalogSourceMode::Authoritative)
            .count();
        if authoritative_count > 1 {
            return Err(
                "multiple authoritative provider profile catalog sources configured".into(),
            );
        }

        for source in &sources {
            let source_id = source.source_id.trim();
            if source_id.is_empty() {
                return Err("provider profile catalog source_id must not be empty".into());
            }
            if !source_ids.insert(source_id.to_string()) {
                return Err(format!(
                    "duplicate provider profile catalog source id '{source_id}'"
                ));
            }
            if source.mode == ProfileCatalogSourceMode::Authoritative && source.profiles.is_empty()
            {
                return Err(format!(
                    "authoritative provider profile catalog source '{source_id}' must not be empty"
                ));
            }
            validate_source_profiles(source)?;
        }

        let authoritative = authoritative_count == 1;
        let mut visible_static = BTreeMap::new();
        for source in sources.iter().filter(|source| {
            if authoritative {
                source.mode == ProfileCatalogSourceMode::Authoritative
            } else {
                source.mode == ProfileCatalogSourceMode::Append
            }
        }) {
            for profile in &source.profiles {
                let id = normalize_profile_id(&profile.id).ok_or_else(|| {
                    format!(
                        "provider profile '{}' in source '{}' has invalid id",
                        profile.id, source.source_id
                    )
                })?;
                if visible_static
                    .insert(
                        id.clone(),
                        StaticProfileEntry {
                            source_id: source.source_id.clone(),
                            mode: source.mode,
                            profile: profile.clone(),
                        },
                    )
                    .is_some()
                {
                    return Err(format!(
                        "duplicate visible provider profile id '{id}' across catalog sources"
                    ));
                }
            }
        }

        Ok(Self {
            visible_static: Arc::new(visible_static),
            authoritative,
        })
    }

    #[must_use]
    pub fn static_source_for_profile(&self, id: &str) -> Option<&str> {
        let id = normalize_profile_id(id)?;
        self.visible_static
            .get(&id)
            .map(|entry| entry.source_id.as_str())
    }

    pub async fn list_profiles(&self, store: &Store) -> Result<Vec<ProviderProfile>, Status> {
        let mut profiles = self
            .visible_static
            .values()
            .map(|entry| entry.profile.to_proto())
            .collect::<Vec<_>>();
        if !self.authoritative {
            for stored in user_provider_profiles(store).await? {
                let resource_version = stored_profile_resource_version(&stored);
                if let Some(profile) = stored.profile {
                    if normalize_profile_id(&profile.id)
                        .is_some_and(|id| self.visible_static.contains_key(&id))
                    {
                        continue;
                    }
                    profiles.push(profile_response_payload(profile, resource_version));
                }
            }
        }
        profiles.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(profiles)
    }

    pub async fn get_profile(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Option<ProviderProfile>, Status> {
        let Some(id) = normalize_profile_id(id) else {
            return Ok(None);
        };
        if let Some(entry) = self.visible_static.get(&id) {
            return Ok(Some(entry.profile.to_proto()));
        }
        if self.authoritative {
            return Ok(None);
        }
        let profile = store
            .get_message_by_name::<StoredProviderProfile>(&id)
            .await
            .map_err(|e| Status::internal(format!("fetch provider profile failed: {e}")))?
            .and_then(|stored| {
                let resource_version = stored_profile_resource_version(&stored);
                stored
                    .profile
                    .map(|profile| profile_response_payload(profile, resource_version))
            });
        Ok(profile)
    }

    pub async fn get_type_profile(
        &self,
        store: &Store,
        id: &str,
    ) -> Result<Option<ProviderTypeProfile>, Status> {
        Ok(self
            .get_profile(store, id)
            .await?
            .as_ref()
            .map(ProviderTypeProfile::from_proto))
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

        if let Some(entry) = self.visible_static.get(&profile_id) {
            hasher.update(b"catalog-profile");
            hasher.update(entry.source_id.as_bytes());
            hasher.update(entry.mode.as_revision_tag());
            hasher.update(entry.profile.to_proto().encode_to_vec());
            return Ok(());
        }

        if self.authoritative {
            hasher.update(b"missing");
            return Ok(());
        }

        hasher.update(b"user-profile");
        match store
            .get_by_name(StoredProviderProfile::object_type(), &profile_id)
            .await
            .map_err(|e| {
                Status::internal(format!("fetch provider profile '{profile_id}' failed: {e}"))
            })? {
            Some(record) => {
                hasher.update(record.id.as_bytes());
                hasher.update(record.updated_at_ms.to_le_bytes());
                hasher.update(record.payload.as_slice());
            }
            None => {
                hasher.update(b"missing");
            }
        }
        Ok(())
    }
}

fn builtin_profile_source() -> ProfileCatalogSource {
    ProfileCatalogSource {
        source_id: BUILTIN_SOURCE_ID.to_string(),
        mode: ProfileCatalogSourceMode::Append,
        profiles: builtin_profiles().to_vec(),
    }
}

fn validate_source_profiles(source: &ProfileCatalogSource) -> Result<(), String> {
    let profiles = source
        .profiles
        .iter()
        .map(|profile| (source.source_id.clone(), profile.clone()))
        .collect::<Vec<_>>();
    let diagnostics = validate_profile_set(&profiles);
    if let Some(diagnostic) = diagnostics
        .into_iter()
        .find(|diagnostic| diagnostic.severity == "error")
    {
        return Err(format_diagnostic(diagnostic));
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

pub(crate) async fn user_provider_profiles(
    store: &Store,
) -> Result<Vec<StoredProviderProfile>, Status> {
    let profiles: Vec<StoredProviderProfile> = store
        .list_messages(10_000, 0)
        .await
        .map_err(|e| Status::internal(format!("list provider profiles failed: {e}")))?;
    Ok(profiles)
}

pub(crate) fn stored_provider_profile(profile: ProviderProfile) -> StoredProviderProfile {
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

pub(crate) fn profile_storage_payload(mut profile: ProviderProfile) -> ProviderProfile {
    profile.resource_version = 0;
    profile
}

pub(crate) fn profile_response_payload(
    mut profile: ProviderProfile,
    resource_version: u64,
) -> ProviderProfile {
    profile.resource_version = resource_version;
    profile
}

pub(crate) fn stored_profile_resource_version(stored: &StoredProviderProfile) -> u64 {
    stored
        .metadata
        .as_ref()
        .map_or(0, |metadata| metadata.resource_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str) -> ProviderTypeProfile {
        let mut profile = builtin_profiles()
            .iter()
            .find(|profile| profile.id == "github")
            .expect("github built-in profile")
            .clone();
        profile.id = id.to_string();
        profile.display_name = id.to_string();
        profile
    }

    #[test]
    fn authoritative_catalog_hides_builtin_sources_from_management_checks() {
        let catalog = ProviderProfileCatalog::from_sources(vec![
            builtin_profile_source(),
            ProfileCatalogSource {
                source_id: "interceptor/test".to_string(),
                mode: ProfileCatalogSourceMode::Authoritative,
                profiles: vec![profile("slack")],
            },
        ])
        .unwrap();

        assert_eq!(
            catalog.static_source_for_profile("slack"),
            Some("interceptor/test")
        );
        assert_eq!(catalog.static_source_for_profile("github"), None);
    }
}
