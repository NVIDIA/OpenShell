// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! BlueField VM extension runtime state persisted under the sandbox state dir.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bf_inventory::FunctionSlot;
use serde::{Deserialize, Serialize};

use crate::lifecycle::{LifecycleError, LifecycleResult, extension_state_dir};

/// Name of this extension. Must match the module name (`bluefield`).
pub const EXTENSION_NAME: &str = "bluefield";
const PCI_BIND_STATE_FILE: &str = "pci-bind-state.json";

/// Per-sandbox bookkeeping for reverse-order teardown.
#[derive(Debug, Clone)]
pub(crate) struct AttachmentRecord {
    pub(crate) slot: FunctionSlot,
}

/// Persisted record of the VF bound to a sandbox, for crash recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BluefieldPciBindState {
    pub(crate) host_bdf: String,
    pub(crate) sandbox_id: String,
    #[serde(default)]
    pub(crate) mac: Option<String>,
    pub(crate) bound_at_ms: u128,
}

pub(crate) fn persist_bind_state(
    sandbox_id: &str,
    sandbox_state_dir: &Path,
    slot: &FunctionSlot,
) -> LifecycleResult<()> {
    let path = bind_state_path(sandbox_state_dir)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            LifecycleError::new(format!(
                "create bluefield bind state dir {}: {err}",
                parent.display()
            ))
        })?;
    }
    let state = BluefieldPciBindState {
        host_bdf: slot.host_bdf.clone(),
        sandbox_id: sandbox_id.to_string(),
        mac: slot.mac.clone(),
        bound_at_ms: now_millis(),
    };
    let data = serde_json::to_string_pretty(&state)
        .map_err(|err| LifecycleError::new(format!("serialize bluefield bind state: {err}")))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|err| {
        LifecycleError::new(format!(
            "write bluefield bind state {}: {err}",
            tmp.display()
        ))
    })?;
    std::fs::rename(&tmp, &path).map_err(|err| {
        LifecycleError::new(format!(
            "commit bluefield bind state {}: {err}",
            path.display()
        ))
    })
}

pub(crate) fn load_bind_state(
    sandbox_id: &str,
    sandbox_state_dir: &Path,
) -> LifecycleResult<BluefieldPciBindState> {
    let path = bind_state_path(sandbox_state_dir)?;
    let data = std::fs::read_to_string(&path).map_err(|err| {
        LifecycleError::new(format!(
            "read bluefield bind state {}: {err}",
            path.display()
        ))
    })?;
    let state: BluefieldPciBindState = serde_json::from_str(&data).map_err(|err| {
        LifecycleError::new(format!(
            "parse bluefield bind state {}: {err}",
            path.display()
        ))
    })?;
    if state.sandbox_id != sandbox_id {
        return Err(LifecycleError::new(format!(
            "bluefield bind state sandbox mismatch: expected {sandbox_id}, got {}",
            state.sandbox_id
        )));
    }
    Ok(state)
}

pub(crate) fn remove_bind_state(sandbox_state_dir: &Path) -> LifecycleResult<()> {
    let path = bind_state_path(sandbox_state_dir)?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(LifecycleError::new(format!(
            "remove bluefield bind state {}: {err}",
            path.display()
        ))),
    }
}

fn bind_state_path(sandbox_state_dir: &Path) -> LifecycleResult<PathBuf> {
    Ok(extension_state_dir(sandbox_state_dir, EXTENSION_NAME)?.join(PCI_BIND_STATE_FILE))
}

pub(crate) fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}
