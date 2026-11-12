// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{BTreeSet, PersistenceError, SupervisorPool, WriteCondition};
use openshell_supervisor_control::warm_pool::{WarmPoolSnapshot, WarmPoolState, WarmPoolUpdate};

use crate::persistence::ObjectListQuery;
use openshell_core::proto::{Sandbox, SandboxWorkloadTemplate};
use openshell_supervisor_control::warm_pool::WarmPoolTarget;

const OBJECT_TYPE: &str = "warm_pool_journal";
const MAX_JOURNAL_BYTES: usize = 128 * 1024;

fn identity(workspace: &str, pool: &str) -> Result<String, String> {
    if workspace.is_empty() || workspace.len() > 63 || pool.is_empty() || pool.len() > 63 {
        return Err("warm-pool journal requires bounded workspace and pool names".into());
    }
    serde_json::to_string(&(workspace, pool)).map_err(|e| e.to_string())
}

fn validate(state: &WarmPoolState) -> Result<(), String> {
    if state.revision == 0
        || state.fingerprint.len() != 64
        || state.entries.len() > 256
        || !state
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || state.entries.iter().any(|entry| {
            entry.created_at_ms < 0
                || entry
                    .resource_uid
                    .as_ref()
                    .is_some_and(|uid| uid.is_empty() || uid.len() > 256)
        })
        || state
            .entries
            .iter()
            .map(|entry| entry.session_id)
            .collect::<BTreeSet<_>>()
            .len()
            != state.entries.len()
    {
        return Err("invalid warm-pool journal".into());
    }
    Ok(())
}

impl SupervisorPool {
    pub(super) async fn warm_pool_targets(
        &self,
        sandbox_id: Option<&str>,
    ) -> Result<Vec<WarmPoolTarget>, String> {
        if let Some(sandbox_id) = sandbox_id {
            let sandbox = self
                .store
                .get_message::<Sandbox>(sandbox_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("sandbox disappeared during pool lookup")?;
            let Some(id) = sandbox.metadata.as_ref().and_then(|m| {
                m.annotations
                    .get(crate::compute::WORKLOAD_TEMPLATE_ID_ANNOTATION)
            }) else {
                return Ok(Vec::new());
            };
            let template = self
                .store
                .get_message::<SandboxWorkloadTemplate>(id)
                .await
                .map_err(|e| e.to_string())?;
            return template
                .as_ref()
                .filter(|template| {
                    template.metadata.as_ref().is_some_and(|m| {
                        sandbox
                            .metadata
                            .as_ref()
                            .is_some_and(|s| s.workspace == m.workspace)
                    })
                })
                .map(template_target)
                .transpose()
                .map(|target| target.flatten().into_iter().collect());
        }
        let templates = self
            .store
            .collect_messages::<SandboxWorkloadTemplate>(ObjectListQuery::AllWorkspaces)
            .await
            .map_err(|e| e.to_string())?;
        let mut targets = templates
            .iter()
            .map(template_target)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        // Journals outlive templates so deletion and gateway restarts still drain
        // old capacity. Confirm apparent absences with a direct lookup: listings
        // can race a new template and must not retire its pool accidentally.
        for journal in self
            .list_all(OBJECT_TYPE)
            .await
            .map_err(|e| e.to_string())?
        {
            let Some(id) = journal.name.strip_prefix("tpl-") else {
                continue;
            };
            if targets
                .iter()
                .any(|t| (&t.pool_id, &t.workspace) == (&journal.name, &journal.workspace))
            {
                continue;
            }
            let template = self
                .store
                .get_message::<SandboxWorkloadTemplate>(id)
                .await
                .map_err(|e| e.to_string())?;
            if let Some(target) = template
                .as_ref()
                .map(template_target)
                .transpose()?
                .flatten()
            {
                targets.push(target);
            } else {
                targets.push(WarmPoolTarget {
                    pool_id: journal.name,
                    workspace: journal.workspace,
                    target: 0,
                    spec: None,
                });
            }
        }
        Ok(targets)
    }

    pub(super) async fn warm_pool_state(
        &self,
        workspace: &str,
        pool_id: &str,
    ) -> Result<Option<WarmPoolSnapshot>, String> {
        let id = identity(workspace, pool_id)?;
        let row = self
            .store
            .get(OBJECT_TYPE, &id)
            .await
            .map_err(|e| e.to_string())?;
        row.map(|row| {
            if row.payload.len() > MAX_JOURNAL_BYTES {
                return Err("warm-pool journal exceeds its size limit".into());
            }
            let state: WarmPoolState = serde_json::from_slice(&row.payload)
                .map_err(|_| "invalid warm-pool journal".to_string())?;
            validate(&state)?;
            if row.workspace != workspace || row.name != pool_id {
                return Err("warm-pool journal scope changed".into());
            }
            Ok(WarmPoolSnapshot {
                resource_version: row.resource_version,
                state,
            })
        })
        .transpose()
    }

    pub(super) async fn update_warm_pool(&self, update: WarmPoolUpdate) -> Result<bool, String> {
        let id = identity(&update.workspace, &update.pool_id)?;
        validate(&update.state)?;
        if let Some(id) = update.pool_id.strip_prefix("tpl-") {
            let template = self
                .store
                .get_message::<SandboxWorkloadTemplate>(id)
                .await
                .map_err(|e| e.to_string())?;
            let target = template
                .as_ref()
                .map(template_target)
                .transpose()?
                .flatten();
            let active = target
                .as_ref()
                .is_some_and(|t| t.workspace == update.workspace);
            if active == (update.state.revision == u64::MAX) {
                return Err("template changed during pool reconciliation".into());
            }
        }
        let current = self
            .warm_pool_state(&update.workspace, &update.pool_id)
            .await?;
        if current.as_ref().map(|snapshot| snapshot.resource_version) != update.expected_version {
            return Ok(false);
        }
        if let Some(current) = current
            && (current.state.revision > update.state.revision
                || (current.state.revision == update.state.revision
                    && current.state.fingerprint != update.state.fingerprint)
                || current.state.entries.iter().any(|old| {
                    old.retiring
                        && update
                            .state
                            .entries
                            .iter()
                            .any(|new| new.session_id == old.session_id && !new.retiring)
                }))
        {
            return Err(
                "warm-pool update would revive an old configuration or retired identity".into(),
            );
        }
        let condition = update.expected_version.map_or(
            WriteCondition::MustCreate,
            WriteCondition::MatchResourceVersion,
        );
        let payload = serde_json::to_vec(&update.state).map_err(|e| e.to_string())?;
        if payload.len() > MAX_JOURNAL_BYTES {
            return Err("warm-pool journal exceeds its size limit".into());
        }
        match self
            .store
            .put_if(
                OBJECT_TYPE,
                &id,
                &update.pool_id,
                &update.workspace,
                &payload,
                None,
                condition,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(PersistenceError::Conflict { .. } | PersistenceError::UniqueViolation { .. }) => {
                Ok(false)
            }
            Err(error) => Err(error.to_string()),
        }
    }
}

fn template_target(template: &SandboxWorkloadTemplate) -> Result<Option<WarmPoolTarget>, String> {
    let metadata = template
        .metadata
        .as_ref()
        .ok_or("template metadata missing")?;
    let startup = template
        .spec
        .as_ref()
        .and_then(|s| s.desired_service_level.as_ref())
        .and_then(|s| s.startup.as_ref());
    let Some(startup) = startup.filter(|s| s.ready_within.is_some() && s.max_burst > 0) else {
        return Ok(None);
    };
    if metadata.deletion_time.is_some() {
        return Ok(None);
    }
    let spec = crate::grpc::sandbox_spec_from_stored_workload_template(template)
        .map_err(|e| e.to_string())?;
    let spec = crate::compute::driver_sandbox_spec_from_public(&spec, "kubernetes")
        .map_err(|e| e.to_string())?;
    Ok(Some(WarmPoolTarget {
        pool_id: format!("tpl-{}", metadata.id),
        workspace: metadata.workspace.clone(),
        target: startup.max_burst,
        spec: Some(spec),
    }))
}

#[cfg(test)]
mod tests {
    use super::super::tests::Fixture;
    use super::*;
    use openshell_supervisor_control::warm_pool::WarmPoolEntry;

    fn update() -> WarmPoolUpdate {
        WarmPoolUpdate {
            workspace: "team".into(),
            pool_id: "agents".into(),
            expected_version: None,
            state: WarmPoolState {
                revision: 1,
                fingerprint: "a".repeat(64),
                entries: vec![WarmPoolEntry {
                    session_id: openshell_core::SandboxSessionId::new(),
                    created_at_ms: 1,
                    retiring: false,
                    last_attempt_at_ms: None,
                    last_ready_at_ms: None,
                    resource_uid: None,
                }],
            },
        }
    }

    fn template() -> SandboxWorkloadTemplate {
        SandboxWorkloadTemplate {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "original-template".into(),
                name: "agents".into(),
                workspace: "team".into(),
                ..Default::default()
            }),
            spec: Some(openshell_core::proto::SandboxWorkloadTemplateSpec {
                workload: Some(openshell_core::proto::SandboxWorkloadConfig {
                    image: "test:1".into(),
                    environment: [("LANG".into(), "C".into())].into(),
                    resources: Some(openshell_core::proto::SandboxResources {
                        cpu: "2".into(),
                        memory: "1Gi".into(),
                        ..Default::default()
                    }),
                }),
                desired_service_level: Some(openshell_core::proto::SandboxServiceLevel {
                    startup: Some(openshell_core::proto::SandboxStartup {
                        ready_within: Some(prost_types::Duration {
                            seconds: 5,
                            nanos: 0,
                        }),
                        max_burst: 2,
                    }),
                }),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn only_tuned_templates_request_capacity_and_preserve_workload() {
        let mut template = template();
        let target = template_target(&template).unwrap().unwrap();
        assert_eq!(target.pool_id, "tpl-original-template");
        assert_eq!(target.target, 2);
        let spec = target.spec.unwrap();
        assert_eq!(spec.environment["LANG"], "C");
        assert_eq!(spec.template.unwrap().resources.unwrap().cpu_limit, "2");
        template
            .spec
            .as_mut()
            .unwrap()
            .desired_service_level
            .as_mut()
            .unwrap()
            .startup
            .as_mut()
            .unwrap()
            .max_burst = 0;
        assert!(template_target(&template).unwrap().is_none());
        template
            .spec
            .as_mut()
            .unwrap()
            .desired_service_level
            .as_mut()
            .unwrap()
            .startup
            .as_mut()
            .unwrap()
            .max_burst = 2;
        template
            .spec
            .as_mut()
            .unwrap()
            .desired_service_level
            .as_mut()
            .unwrap()
            .startup
            .as_mut()
            .unwrap()
            .ready_within = None;
        assert!(template_target(&template).unwrap().is_none());
    }

    #[tokio::test]
    async fn template_deletion_drains_after_restart_and_recreation_cannot_steal_claims() {
        use crate::persistence::ObjectType;
        let fixture = Fixture::new().await;
        let pool = fixture.replica("a");
        let mut template = template();
        pool.store.put_message(&template).await.unwrap();
        let targets = pool.warm_pool_targets(None).await.unwrap();
        assert_eq!(targets.len(), 1);
        let mut journal = update();
        journal.pool_id = targets[0].pool_id.clone();
        assert!(pool.update_warm_pool(journal.clone()).await.unwrap());
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: "sandbox".into(),
                name: "sandbox".into(),
                workspace: "team".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        pool.store.put_message(&sandbox).await.unwrap();
        assert!(
            pool.warm_pool_targets(Some("sandbox"))
                .await
                .unwrap()
                .is_empty()
        );
        sandbox.metadata.as_mut().unwrap().annotations.insert(
            crate::compute::WORKLOAD_TEMPLATE_ID_ANNOTATION.into(),
            "original-template".into(),
        );
        pool.store.put_message(&sandbox).await.unwrap();
        assert_eq!(
            pool.warm_pool_targets(Some("sandbox")).await.unwrap().len(),
            1
        );
        let mut other = sandbox.clone();
        other.metadata.as_mut().unwrap().workspace = "other".into();
        other.metadata.as_mut().unwrap().id = "other-sandbox".into();
        pool.store.put_message(&other).await.unwrap();
        assert!(
            pool.warm_pool_targets(Some("other-sandbox"))
                .await
                .unwrap()
                .is_empty()
        );
        pool.store
            .delete(SandboxWorkloadTemplate::object_type(), "original-template")
            .await
            .unwrap();
        assert!(pool.update_warm_pool(journal).await.is_err());
        template.metadata.as_mut().unwrap().id = "replacement-template".into();
        pool.store.put_message(&template).await.unwrap();
        let restarted = fixture.replica("restarted");
        let targets = restarted.warm_pool_targets(None).await.unwrap();
        assert_eq!(targets.len(), 2);
        assert!(
            targets
                .iter()
                .any(|t| t.pool_id == "tpl-original-template" && t.spec.is_none() && t.target == 0)
        );
        assert!(
            targets
                .iter()
                .any(|t| t.pool_id == "tpl-replacement-template" && t.target == 2)
        );
        assert!(
            restarted
                .warm_pool_targets(Some("sandbox"))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn replicas_share_creation_intents_and_fence_stale_configuration() {
        let fixture = Fixture::new().await;
        let a = fixture.replica("a");
        let b = fixture.replica("b");
        let first = update();
        let (left, right) = tokio::join!(
            a.update_warm_pool(first.clone()),
            b.update_warm_pool(update())
        );
        assert_ne!(left.unwrap(), right.unwrap());
        let stored = b.warm_pool_state("team", "agents").await.unwrap().unwrap();
        let mut next = first.clone();
        next.expected_version = Some(stored.resource_version);
        next.state = stored.state;
        next.state.revision = 2;
        next.state.fingerprint = "b".repeat(64);
        next.state.entries[0].retiring = true;
        assert!(a.update_warm_pool(next.clone()).await.unwrap());
        assert!(!b.update_warm_pool(next.clone()).await.unwrap());
        let restarted = fixture.replica("restarted");
        let stored = restarted
            .warm_pool_state("team", "agents")
            .await
            .unwrap()
            .unwrap();
        next.expected_version = Some(stored.resource_version);
        next.state.entries[0].retiring = false;
        assert!(restarted.update_warm_pool(next.clone()).await.is_err());
        next.state.entries[0].retiring = true;
        next.state.revision = 1;
        assert!(restarted.update_warm_pool(next).await.is_err());
        assert!(
            restarted
                .warm_pool_state("another", "agents")
                .await
                .unwrap()
                .is_none()
        );
    }
}
