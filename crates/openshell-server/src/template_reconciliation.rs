// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Desired-state reconciliation of sandbox templates with the compute driver.

use crate::ServerState;
use crate::persistence::{ObjectCursor, ObjectType, Store};
use openshell_core::SetResourceVersion;
use openshell_core::proto::SandboxWorkloadTemplate;
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, watch};
use tracing::{debug, info, warn};

const PAGE_SIZE: u32 = 100;
const SWEEP_INTERVAL: Duration = Duration::from_mins(1);

async fn list_desired_templates(store: &Store) -> Result<Vec<SandboxWorkloadTemplate>, String> {
    let mut templates = Vec::new();
    let mut cursor = None;
    loop {
        let records = store
            .list_by_type_after(
                SandboxWorkloadTemplate::object_type(),
                cursor.as_ref(),
                PAGE_SIZE,
            )
            .await
            .map_err(|error| format!("list sandbox templates failed: {error}"))?;
        if records.is_empty() {
            break;
        }
        for record in &records {
            let mut template =
                SandboxWorkloadTemplate::decode(record.payload.as_slice()).map_err(|error| {
                    format!("decode sandbox template {} failed: {error}", record.id)
                })?;
            template.set_resource_version(record.resource_version);
            templates.push(template);
        }
        cursor = records.last().map(ObjectCursor::from);
    }
    Ok(templates)
}

async fn reconcile_templates(state: &ServerState) -> Result<usize, String> {
    if !state.compute.supports_sandbox_template_reconciliation() {
        debug!(
            driver = %state.compute.configured_driver_name(),
            "Compute driver does not support sandbox template reconciliation"
        );
        return Ok(0);
    }

    // Build the complete snapshot before crossing the driver boundary. A store
    // read or decode failure must not turn a partial snapshot into destructive
    // backend pruning.
    let templates = list_desired_templates(state.store.as_ref()).await?;
    let requested = templates.len();
    let result = state
        .compute
        .reconcile_sandbox_templates(&templates)
        .await
        .map_err(|status| status.to_string())?;
    info!(
        driver = %state.compute.configured_driver_name(),
        requested,
        reconciled = result.reconciled,
        pruned = result.pruned,
        "Reconciled sandbox template desired state"
    );
    Ok(result.reconciled as usize)
}

pub fn spawn_worker(state: Arc<ServerState>, mut shutdown_rx: watch::Receiver<bool>) {
    tokio::spawn(async move {
        loop {
            if *shutdown_rx.borrow() {
                return;
            }
            if let Err(error) = reconcile_templates(&state).await {
                warn!(error = %error, "Sandbox template reconciliation sweep failed");
            }
            tokio::select! {
                () = state.template_reconciliation_notify.notified() => {}
                () = tokio::time::sleep(SWEEP_INTERVAL) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                }
            }
        }
    });
}

pub fn notify_after_create(state: &ServerState) {
    state.template_reconciliation_notify.notify_one();
}

pub fn notify_after_delete(state: &ServerState) {
    state.template_reconciliation_notify.notify_one();
}

pub fn new_notify() -> Arc<Notify> {
    Arc::new(Notify::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::WriteCondition;
    use openshell_core::proto::datamodel::v1::ObjectMeta;
    use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};

    fn template(id: &str) -> SandboxWorkloadTemplate {
        SandboxWorkloadTemplate {
            metadata: Some(ObjectMeta {
                id: id.to_string(),
                name: format!("template-{id}"),
                workspace: "default".to_string(),
                ..ObjectMeta::default()
            }),
            spec: Some(openshell_core::proto::SandboxWorkloadTemplateSpec {
                workload: Some(openshell_core::proto::SandboxWorkloadConfig {
                    image: "registry.example.com/agent:latest".to_string(),
                    ..openshell_core::proto::SandboxWorkloadConfig::default()
                }),
                ..openshell_core::proto::SandboxWorkloadTemplateSpec::default()
            }),
        }
    }

    #[tokio::test]
    async fn desired_snapshot_pages_through_all_templates() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        for index in 0..105 {
            let template = template(&index.to_string());
            store
                .put_if(
                    SandboxWorkloadTemplate::object_type(),
                    template.object_id(),
                    template.object_name(),
                    template.object_workspace(),
                    &template.encode_to_vec(),
                    None,
                    WriteCondition::MustCreate,
                )
                .await
                .unwrap();
        }

        let templates = list_desired_templates(&store).await.unwrap();
        assert_eq!(templates.len(), 105);
        assert!(templates.iter().all(|template| {
            template
                .metadata
                .as_ref()
                .is_some_and(|metadata| metadata.resource_version == 1)
        }));
    }

    #[tokio::test]
    async fn invalid_template_aborts_snapshot() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        store
            .put_if(
                SandboxWorkloadTemplate::object_type(),
                "broken",
                "broken",
                "default",
                b"not protobuf",
                None,
                WriteCondition::MustCreate,
            )
            .await
            .unwrap();

        assert!(list_desired_templates(&store).await.is_err());
    }
}
