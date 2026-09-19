// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Durable source clocks for the provisioning repair window. Status observations
//! never contribute. Source identities distinguish real A -> B -> A edits.

use super::{POLICY_SETTING_KEY, load_global_settings, load_sandbox_settings};
use crate::compute::provisioning_deadline::ConfigurationChange;
use crate::persistence::{ObjectId, ObjectName, ObjectType, ObjectWorkspace, Store};
use crate::policy_store::PolicyStoreExt;
use crate::storage_proto::StoredProviderProfile;
use openshell_core::proto::{Provider, Sandbox};
use openshell_core::time::timestamp_to_millis;
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Read only committed configuration sources, never sandbox `updated_at`.
/// The caller serializes this read with configuration mutations and expiry.
pub async fn configuration_change(
    store: &Store,
    sandbox: &Sandbox,
) -> Result<ConfigurationChange, String> {
    let global = load_global_settings(store)
        .await
        .map_err(|e| e.to_string())?;
    let local = load_sandbox_settings(store, sandbox.object_workspace(), sandbox.object_name())
        .await
        .map_err(|e| e.to_string())?;
    let created = sandbox
        .metadata
        .as_ref()
        .and_then(|meta| meta.created_time.as_ref())
        .and_then(|time| timestamp_to_millis(time).ok())
        .unwrap_or(0);
    let mut committed_at_ms = created;
    let mut sources = Vec::<(String, String)>::new();
    let keys: BTreeSet<_> = global
        .change_clocks
        .keys()
        .chain(local.change_clocks.keys())
        .collect();
    for key in keys {
        if key != POLICY_SETTING_KEY && openshell_core::settings::setting_for_key(key).is_none() {
            continue;
        }
        // Global settings override sandbox values. Keep global deletion clocks
        // because deleting an override reveals the sandbox value again.
        if let Some(clock) = global.change_clocks.get(key) {
            sources.push((format!("global:{key}"), clock.id.clone()));
            committed_at_ms = committed_at_ms.max(clock.committed_at_ms);
        }
        if key != POLICY_SETTING_KEY
            && !global.settings.contains_key(key)
            && let Some(clock) = local.change_clocks.get(key)
        {
            sources.push((format!("sandbox:{key}"), clock.id.clone()));
            committed_at_ms = committed_at_ms.max(clock.committed_at_ms);
        }
    }
    if !global.settings.contains_key(POLICY_SETTING_KEY) {
        if let Some(policy) = store
            .get_latest_policy(sandbox.object_id())
            .await
            .map_err(|e| e.to_string())?
        {
            sources.push((
                "policy".into(),
                format!("{}:{}", policy.version, policy.policy_hash),
            ));
            // Lazy version-one backfill has the same source identity as the
            // original spec, so its newer timestamp alone cannot reset the TTL.
            committed_at_ms = committed_at_ms.max(policy.created_at_ms);
        } else {
            let hash = sandbox
                .spec
                .as_ref()
                .and_then(|spec| spec.policy.as_ref())
                .map(|policy| {
                    openshell_policy::lower_authored_policy(policy.clone())
                        .map(|policy| {
                            openshell_core::policy_identity::deterministic_policy_hash(&policy)
                        })
                        .map_err(|error| error.to_string())
                })
                .transpose()?
                .unwrap_or_default();
            sources.push(("policy".into(), format!("1:{hash}")));
        }
    }
    if let Some(record) = sandbox
        .status
        .as_ref()
        .and_then(|status| status.provisioning.as_ref())
    {
        sources.push(("attachments".into(), record.attachment_change_id.clone()));
        if let Some(time) = &record.attachment_change_time {
            committed_at_ms =
                committed_at_ms.max(timestamp_to_millis(time).map_err(|e| e.to_string())?);
        }
    }
    if let Some(spec) = &sandbox.spec {
        for name in &spec.providers {
            let Some(record) = store
                .get_by_name(Provider::object_type(), sandbox.object_workspace(), name)
                .await
                .map_err(|e| e.to_string())?
            else {
                sources.push((format!("provider:{name}"), "missing".into()));
                continue;
            };
            sources.push((
                format!("provider:{name}"),
                format!("{}:{}", record.id, record.resource_version),
            ));
            committed_at_ms = committed_at_ms.max(record.updated_at_ms);
            let provider =
                Provider::decode(record.payload.as_slice()).map_err(|e| e.to_string())?;
            let mut profile = store
                .get_by_name(
                    StoredProviderProfile::object_type(),
                    &provider.profile_workspace,
                    &provider.r#type,
                )
                .await
                .map_err(|e| e.to_string())?;
            if profile.is_none() && !provider.profile_workspace.is_empty() {
                profile = store
                    .get_by_name(StoredProviderProfile::object_type(), "", &provider.r#type)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            if let Some(profile) = profile {
                sources.push((
                    format!("profile:{}:{}", provider.profile_workspace, provider.r#type),
                    format!("{}:{}", profile.id, profile.resource_version),
                ));
                committed_at_ms = committed_at_ms.max(profile.updated_at_ms);
            }
        }
    }
    sources.sort();
    let encoded = serde_json::to_vec(&sources).map_err(|e| e.to_string())?;
    Ok(ConfigurationChange {
        id: format!("{:x}", Sha256::digest(encoded)),
        committed_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::StoredSettingValue;
    use crate::grpc::policy::{save_global_settings, save_sandbox_settings};
    use openshell_core::proto::ObjectMeta;

    fn sandbox() -> Sandbox {
        Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-clock".into(),
                name: "clock".into(),
                workspace: "default".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn provisioning_settings_clock_survives_noop_and_a_b_a() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sandbox = sandbox();
        let mut settings = load_global_settings(&store).await.unwrap();
        settings
            .settings
            .insert("ocsf_json_enabled".into(), StoredSettingValue::Bool(false));
        save_global_settings(&store, &settings).await.unwrap();
        let first = configuration_change(&store, &sandbox).await.unwrap();
        let settings = load_global_settings(&store).await.unwrap();
        save_global_settings(&store, &settings).await.unwrap();
        assert_eq!(configuration_change(&store, &sandbox).await.unwrap(), first);
        let mut settings = load_global_settings(&store).await.unwrap();
        settings
            .settings
            .insert("ocsf_json_enabled".into(), StoredSettingValue::Bool(true));
        save_global_settings(&store, &settings).await.unwrap();
        let mut settings = load_global_settings(&store).await.unwrap();
        settings
            .settings
            .insert("ocsf_json_enabled".into(), StoredSettingValue::Bool(false));
        save_global_settings(&store, &settings).await.unwrap();
        let last = configuration_change(&store, &sandbox).await.unwrap();
        assert_ne!(
            last.id, first.id,
            "a missed intermediate generation is still a real edit"
        );
        assert!(last.committed_at_ms >= first.committed_at_ms);
        assert_eq!(
            configuration_change(&store, &sandbox).await.unwrap(),
            last,
            "reads cannot refresh commit time"
        );
    }

    #[tokio::test]
    async fn provisioning_global_override_ignores_shadowed_changes_and_tracks_deletion() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let sandbox = sandbox();
        let mut global = load_global_settings(&store).await.unwrap();
        global
            .settings
            .insert("ocsf_json_enabled".into(), StoredSettingValue::Bool(false));
        save_global_settings(&store, &global).await.unwrap();
        let first = configuration_change(&store, &sandbox).await.unwrap();
        let mut local = load_sandbox_settings(&store, "default", "clock")
            .await
            .unwrap();
        local
            .settings
            .insert("ocsf_json_enabled".into(), StoredSettingValue::Bool(true));
        save_sandbox_settings(&store, "default", "clock", &local)
            .await
            .unwrap();
        assert_eq!(configuration_change(&store, &sandbox).await.unwrap(), first);
        let mut global = load_global_settings(&store).await.unwrap();
        global.settings.remove("ocsf_json_enabled");
        save_global_settings(&store, &global).await.unwrap();
        let deleted = configuration_change(&store, &sandbox).await.unwrap();
        assert_ne!(deleted.id, first.id);
        let loaded = load_global_settings(&store).await.unwrap();
        assert!(loaded.change_clocks.contains_key("ocsf_json_enabled"));
        assert_eq!(
            deleted.committed_at_ms,
            loaded.change_clocks["ocsf_json_enabled"].committed_at_ms
        );
    }

    #[tokio::test]
    async fn provisioning_lazy_policy_backfill_does_not_change_generation() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let mut sandbox = sandbox();
        let policy = openshell_policy::restrictive_default_policy();
        let hash = openshell_core::policy_identity::deterministic_policy_hash(&policy);
        sandbox.spec = Some(openshell_core::proto::SandboxSpec {
            policy: Some(openshell_policy::project_base_policy(&policy).unwrap()),
            ..Default::default()
        });
        let first = configuration_change(&store, &sandbox).await.unwrap();
        store
            .put_policy_revision(
                "policy-1",
                "sb-clock",
                "default",
                1,
                &policy.encode_to_vec(),
                &hash,
            )
            .await
            .unwrap();
        let projected = configuration_change(&store, &sandbox).await.unwrap();
        assert_eq!(projected.id, first.id);
        store
            .put_policy_revision(
                "policy-2",
                "sb-clock",
                "default",
                2,
                &policy.encode_to_vec(),
                &hash,
            )
            .await
            .unwrap();
        assert_ne!(
            configuration_change(&store, &sandbox).await.unwrap().id,
            first.id
        );
    }
}
