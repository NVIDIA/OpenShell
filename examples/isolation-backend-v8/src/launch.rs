// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protected provisioning files shared by the example driver and backend.
use anyhow::Result;
use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
use openshell_sandbox_backend::delegated::DelegatedLaunch;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
pub struct Launch {
    pub boundary: DelegatedLaunch,
    pub script: PathBuf,
    pub descriptor: Vec<u8>,
    pub gateway_id: String,
    pub keys: Vec<SessionVerificationKey>,
    pub epoch: CredentialEpoch,
    pub rotation: SessionRotation,
    pub certificate: String,
    pub private_key: String,
    /// Private driver-to-backend provisioning, never supervisor bootstrap.
    pub restore: Option<Restore>,
}

#[derive(Serialize, Deserialize)]
pub struct Restore {
    pub reference: Vec<u8>,
    pub restart_if_restore_fails: bool,
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Evidence for capabilities the V8 runner actually grants.
pub fn capability_evidence(digest: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"script_sha256":digest,"network":"disabled","filesystem":"no-host-access"})).expect("string-valued capability manifest")
}

/// Admit the actual identity of the host process containing the V8 guest.
pub fn host_identity(
    digest: String,
) -> Result<openshell_isolation_interface::contract::ResolvedWorkloadIdentity> {
    Ok(
        openshell_isolation_interface::contract::ResolvedWorkloadIdentity::new(
            rustix::process::geteuid().as_raw(),
            rustix::process::getegid().as_raw(),
            rustix::process::getgroups()?
                .into_iter()
                .map(|gid| gid.as_raw())
                .collect(),
            "v8-script".into(),
            digest,
        )?,
    )
}
