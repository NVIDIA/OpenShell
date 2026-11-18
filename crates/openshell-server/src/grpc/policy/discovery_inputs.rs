// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Collection-local inputs. No validated configuration survives a collection.

use std::collections::HashMap;

use openshell_core::proto::{Sandbox, SandboxConfigSnapshot, ServiceEndpoint};
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace, SetResourceVersion};
use prost::Message as _;
use tonic::Status;

use super::super::StoredSettings;
use super::super::provider::load_provider_environment_records;
use super::{build_sandbox_config_snapshot_with_sources, load_global_settings};
use crate::ServerState;
use crate::persistence::{ObjectListQuery, ObjectType};
use crate::policy_store::PolicyStoreExt as _;
use crate::provider_profile_sources::EffectiveProviderProfileCatalog;

const MAX_DECLARATIONS: usize = 4096;
const MAX_DECLARATION_BYTES: usize = 4 * 1024 * 1024;

#[derive(PartialEq)]
struct Declarations {
    versions: Vec<(String, u64)>,
    by_sandbox: HashMap<String, Vec<ServiceEndpoint>>,
}

impl Declarations {
    /// Bulk reads are an optimization, not an additional workspace limit.
    /// Legacy/unsuitable rows and large workspaces retain the original lookup.
    async fn load(state: &ServerState, workspace: &str) -> Result<Option<Self>, Status> {
        let mut result = Self {
            versions: Vec::new(),
            by_sandbox: HashMap::new(),
        };
        let mut cursor = None;
        let mut bytes = 0usize;
        loop {
            let page = state
                .store
                .list_object_page(
                    ServiceEndpoint::object_type(),
                    ObjectListQuery::Workspace(workspace),
                    cursor.as_ref(),
                    128,
                )
                .await
                .map_err(|_| Status::unavailable("service declarations unavailable"))?;
            for record in page.records {
                bytes = bytes
                    .saturating_add(record.payload.len())
                    .saturating_add(record.labels.as_ref().map_or(0, String::len));
                if bytes > MAX_DECLARATION_BYTES || result.versions.len() >= MAX_DECLARATIONS {
                    return Ok(None);
                }
                let Ok(mut endpoint) = ServiceEndpoint::decode(record.payload.as_slice()) else {
                    return Ok(None);
                };
                endpoint.set_resource_version(record.resource_version);
                let Ok(labels) = serde_json::from_str::<HashMap<String, String>>(
                    record.labels.as_deref().unwrap_or("{}"),
                ) else {
                    return Ok(None);
                };
                let Some(meta) = &endpoint.metadata else {
                    return Ok(None);
                };
                if endpoint.object_id() != record.id
                    || endpoint.object_workspace() != workspace
                    || meta.labels != labels
                {
                    return Ok(None);
                }
                result.versions.push((record.id, record.resource_version));
                if let Some(name) = labels.get("sandbox") {
                    result
                        .by_sandbox
                        .entry(name.clone())
                        .or_default()
                        .push(endpoint);
                }
            }
            let Some(next) = page.next_cursor else {
                break;
            };
            cursor = Some(next);
        }
        result.versions.sort();
        // Stable equality even if an update changes the store's listing order.
        for endpoints in result.by_sandbox.values_mut() {
            endpoints.sort_by(|a, b| a.object_id().cmp(b.object_id()));
        }
        Ok(Some(result))
    }
}

pub struct DiscoveryConfigInputs {
    workspace: String,
    catalog: EffectiveProviderProfileCatalog,
    global_settings: StoredSettings,
    declarations: Option<Declarations>,
}

impl DiscoveryConfigInputs {
    pub(crate) async fn load(state: &ServerState, workspace: &str) -> Result<Self, Status> {
        let (catalog, global_settings, declarations) = tokio::try_join!(
            state
                .provider_profile_sources
                .snapshot_catalog(&state.store, workspace),
            load_global_settings(&state.store),
            Declarations::load(state, workspace),
        )?;
        Ok(Self {
            workspace: workspace.into(),
            catalog,
            global_settings,
            declarations,
        })
    }

    pub(crate) async fn ensure_current(&self, state: &ServerState) -> Result<(), Status> {
        let next = Self::load(state, &self.workspace).await?;
        if self.catalog.revision() != next.catalog.revision()
            // A source-owned revision cannot replace a content comparison,
            // including the platform fallback beneath workspace overrides.
            || self.catalog.list_all_scoped_profiles() != next.catalog.list_all_scoped_profiles()
            || self.global_settings.record_id != next.global_settings.record_id
            || self.global_settings.resource_version != next.global_settings.resource_version
            || self.global_settings.revision != next.global_settings.revision
            || self.declarations != next.declarations
        {
            return Err(Status::unavailable(
                "discovery configuration changed during collection",
            ));
        }
        Ok(())
    }

    pub(crate) async fn build(
        &self,
        state: &ServerState,
        sandbox: &Sandbox,
    ) -> Result<SandboxConfigSnapshot, Status> {
        if sandbox.object_workspace() != self.workspace {
            return Err(Status::internal("installation workspace mismatch"));
        }
        let providers = sandbox
            .spec
            .as_ref()
            .map_or(&[][..], |spec| spec.providers.as_slice());
        let (records, latest) = tokio::try_join!(
            load_provider_environment_records(
                &state.store,
                &state.refresh,
                &self.workspace,
                providers
            ),
            async {
                state
                    .store
                    .get_latest_policy(sandbox.object_id())
                    .await
                    .map_err(|_| Status::unavailable("sandbox policy unavailable"))
            },
        )?;
        let routes = if let Some(declarations) = &self.declarations {
            let endpoints = declarations
                .by_sandbox
                .get(sandbox.object_name())
                .cloned()
                .unwrap_or_default();
            if endpoints.len()
                > usize::try_from(super::super::service::MAX_APP_SERVICE_ROUTES)
                    .expect("bounded route limit")
            {
                return Err(Status::resource_exhausted(
                    "too many application service declarations",
                ));
            }
            Some(super::super::service::configured_app_routes_from_endpoints(
                state, sandbox, endpoints,
            ))
        } else {
            None
        };
        build_sandbox_config_snapshot_with_sources(
            state,
            sandbox,
            &self.catalog,
            &records,
            &self.global_settings,
            latest.as_ref(),
            routes,
        )
        .await
    }
}
