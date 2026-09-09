// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman-owned provisioning for the common authenticated isolation channel.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use openshell_core::ComputeDriverError;
use openshell_core::proto::compute::v1::DriverSandbox;
use openshell_isolation_interface::boundary_protocol::{
    BoundaryClientTls, BoundaryConfig, BoundaryListener, BoundaryServerTls, BoundaryTopology,
    BoundaryTransport, generate_boundary_mutual_tls_material,
};
use openshell_isolation_interface::contract::{DriverFenceEvidence, ResolvedWorkloadIdentity};

pub const LABEL_ROLE: &str = "openshell.io/isolation-role";
pub const WORKLOAD_FILTER: &str = "openshell.io/isolation-role=sandbox";
pub const CHANNEL_ROOT: &str = "/.openshell/channel";
pub const BOOTSTRAP_PATH: &str = "/.openshell/channel/sandbox/bootstrap.json";
pub const TOPOLOGY_PATH: &str = "/.openshell/supervisor/topology.payload";
pub const RESTART_BUNDLE_PATH: &str = "/.openshell/supervisor/sandbox-bundle.tar";
const SOCKET_PATH: &str = "/.openshell/channel/sandbox/control.sock";

pub fn supervisor_name(id: &str) -> String {
    format!("openshell-supervisor-{id}")
}
pub fn channel_volume_name(id: &str) -> String {
    format!("openshell-channel-{id}")
}

fn invalid(error: impl std::fmt::Display) -> ComputeDriverError {
    ComputeDriverError::Precondition(error.to_string())
}

/// Resolve policy names against the pinned workload image, never the gateway.
pub fn resolve_identity(
    sandbox: &DriverSandbox,
    image_id: &str,
    image_user: &str,
    passwd: &[u8],
    group: &[u8],
) -> Result<ResolvedWorkloadIdentity, ComputeDriverError> {
    let passwd = std::str::from_utf8(passwd).map_err(invalid)?;
    let group = std::str::from_utf8(group).map_err(invalid)?;
    let accounts: Vec<_> = passwd
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            fields.next()?;
            Some((
                name,
                fields.next()?.parse::<u32>().ok()?,
                fields.next()?.parse::<u32>().ok()?,
            ))
        })
        .collect();
    let groups: Vec<_> = group
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            fields.next()?;
            Some((name, fields.next()?.parse::<u32>().ok()?, fields.next()?))
        })
        .collect();
    let request = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.workload_identity.as_ref());
    let requested_user = request.map_or("", |identity| identity.user.trim());
    let requested_group = request.map_or("", |identity| identity.group.trim());
    let (image_user, image_group) = image_user.split_once(':').unwrap_or((image_user, ""));
    let user = if requested_user.is_empty() {
        image_user
    } else {
        requested_user
    };
    let group = if requested_group.is_empty() {
        image_group
    } else {
        requested_group
    };
    let account = accounts
        .iter()
        .find(|(name, uid, _)| *name == user || user.parse::<u32>().ok() == Some(*uid));
    let uid = user
        .parse()
        .ok()
        .or_else(|| account.map(|(_, uid, _)| *uid))
        .ok_or_else(|| invalid("configure a non-root workload user present in the pinned image"))?;
    let gid = if group.is_empty() {
        account.map(|(_, _, gid)| *gid)
    } else {
        group.parse().ok().or_else(|| {
            groups
                .iter()
                .find(|(name, _, _)| *name == group)
                .map(|(_, gid, _)| *gid)
        })
    }
    .ok_or_else(|| {
        invalid("configure an explicit workload group for a UID without an image passwd entry")
    })?;
    let supplemental = account.map_or_else(Vec::new, |(username, _, _)| {
        groups
            .iter()
            .filter(|(_, id, members)| {
                *id != gid && members.split(',').any(|member| member == *username)
            })
            .map(|(_, gid, _)| *gid)
            .collect()
    });
    let source = if requested_user.is_empty() && requested_group.is_empty() {
        "image"
    } else {
        "policy"
    };
    ResolvedWorkloadIdentity::new(uid, gid, supplemental, source.into(), image_id.into())
        .map_err(invalid)
}

pub struct BootstrapArchives {
    pub workload: Vec<u8>,
    pub supervisor: Vec<u8>,
}

/// The shared volume contains only sandbox credentials. Supervisor credentials,
/// gateway authorization, and the restart copy never enter that volume.
pub fn bootstrap_archives(
    sandbox_id: &str,
    container_id: &str,
    identity: &ResolvedWorkloadIdentity,
    child_env: HashMap<String, String>,
) -> Result<BootstrapArchives, ComputeDriverError> {
    let tls = generate_boundary_mutual_tls_material().map_err(invalid)?;
    let resource_claims = BTreeMap::from([
        ("podman.container_id".into(), container_id.into()),
        (
            "podman.image_identity".into(),
            identity.resource_digest.clone(),
        ),
    ]);
    let driver_fence = DriverFenceEvidence::Podman {
        container_id: container_id.into(),
        network_mode: "none".into(),
        unexpected_networks: Vec::new(),
    };
    let generation = uuid::Uuid::new_v4().to_string();
    let session_epoch = uuid::Uuid::new_v4().to_string();
    let bootstrap_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let config = BoundaryConfig {
        boundary_id: sandbox_id.into(),
        generation: generation.clone(),
        session_epoch: session_epoch.clone(),
        bootstrap_token: bootstrap_token.clone(),
        listener: BoundaryListener::Unix {
            socket_path: PathBuf::from(SOCKET_PATH),
            tls: BoundaryServerTls {
                certificate_chain_path: PathBuf::from("/.openshell/channel/sandbox/server.crt"),
                private_key_path: PathBuf::from("/.openshell/channel/sandbox/server.key"),
                client_ca_certificate_path: PathBuf::from(
                    "/.openshell/channel/sandbox/client-ca.crt",
                ),
            },
        },
        resource_claims: resource_claims.clone(),
        resource_claim_files: BTreeMap::new(),
        workload_identity: identity.clone(),
        driver_fence: driver_fence.clone(),
        child_env,
    };
    let topology = BoundaryTopology {
        boundary_id: sandbox_id.into(),
        generation,
        session_epoch,
        bootstrap_token,
        transport: BoundaryTransport::Unix {
            socket_path: PathBuf::from(SOCKET_PATH),
            tls: BoundaryClientTls {
                server_name: tls.server_name,
                ca_certificate_pem: tls.ca_certificate_pem.clone(),
                certificate_chain_pem: tls.supervisor_certificate_pem,
                private_key_pem: tls.supervisor_private_key_pem,
            },
        },
        host_gateway_ip: None,
        resource_claims,
        workload_identity: identity.clone(),
        driver_fence,
    };
    let mut workload = Archive::new(identity);
    workload.directory(".openshell", 0o755, false)?;
    workload.directory(".openshell/channel", 0o755, false)?;
    workload.directory(".openshell/channel/sandbox", 0o711, true)?;
    workload.directory("sandbox", 0o700, true)?;
    workload.file(
        BOOTSTRAP_PATH,
        &serde_json::to_vec(&config).map_err(invalid)?,
    )?;
    workload.file(
        "/.openshell/channel/sandbox/server.crt",
        tls.sandbox_certificate_pem.as_bytes(),
    )?;
    workload.file(
        "/.openshell/channel/sandbox/server.key",
        tls.sandbox_private_key_pem.as_bytes(),
    )?;
    workload.file(
        "/.openshell/channel/sandbox/client-ca.crt",
        tls.ca_certificate_pem.as_bytes(),
    )?;
    let workload = workload.finish()?;
    let mut supervisor = Archive::new(identity);
    supervisor.directory(".openshell", 0o755, false)?;
    supervisor.directory(".openshell/supervisor", 0o700, true)?;
    supervisor.file(
        TOPOLOGY_PATH,
        &serde_json::to_vec(&topology).map_err(invalid)?,
    )?;
    supervisor.file(RESTART_BUNDLE_PATH, &workload)?;
    Ok(BootstrapArchives {
        workload,
        supervisor: supervisor.finish()?,
    })
}

struct Archive<'a> {
    builder: tar::Builder<Vec<u8>>,
    identity: &'a ResolvedWorkloadIdentity,
}
impl<'a> Archive<'a> {
    fn new(identity: &'a ResolvedWorkloadIdentity) -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
            identity,
        }
    }
    fn directory(&mut self, path: &str, mode: u32, owned: bool) -> Result<(), ComputeDriverError> {
        self.append(path, mode, owned, tar::EntryType::Directory, &[])
    }
    fn file(&mut self, path: &str, content: &[u8]) -> Result<(), ComputeDriverError> {
        self.append(
            path.trim_start_matches('/'),
            0o600,
            true,
            tar::EntryType::Regular,
            content,
        )
    }
    fn append(
        &mut self,
        path: &str,
        mode: u32,
        owned: bool,
        kind: tar::EntryType,
        content: &[u8],
    ) -> Result<(), ComputeDriverError> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_uid(if owned {
            u64::from(self.identity.uid)
        } else {
            0
        });
        header.set_gid(if owned {
            u64::from(self.identity.gid)
        } else {
            0
        });
        header.set_size(content.len() as u64);
        header.set_mtime(0);
        header.set_cksum();
        self.builder
            .append_data(&mut header, path, content)
            .map_err(invalid)
    }
    fn finish(self) -> Result<Vec<u8>, ComputeDriverError> {
        self.builder.into_inner().map_err(invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    #[test]
    fn identity_uses_pinned_image_accounts_and_rejects_root() {
        let sandbox = DriverSandbox::default();
        let passwd = b"root:x:0:0:root:/root:/bin/sh\nagent:x:1000:1001::/home/agent:/bin/sh\n";
        let groups = b"agent:x:1001:\ndata:x:2000:agent\n";
        let identity =
            resolve_identity(&sandbox, "sha256:pinned", "agent", passwd, groups).unwrap();
        assert_eq!((identity.uid, identity.gid), (1000, 1001));
        assert_eq!(identity.supplementary_gids, vec![2000]);
        assert_eq!(identity.resource_digest, "sha256:pinned");
        assert!(resolve_identity(&sandbox, "sha256:pinned", "root", passwd, groups).is_err());
        assert!(resolve_identity(&sandbox, "sha256:pinned", "", passwd, groups).is_err());
        assert!(resolve_identity(&sandbox, "sha256:pinned", "2000", passwd, groups).is_err());
    }

    fn files(bytes: &[u8]) -> BTreeMap<PathBuf, Vec<u8>> {
        tar::Archive::new(bytes)
            .entries()
            .unwrap()
            .filter_map(|entry| {
                let mut entry = entry.unwrap();
                if !entry.header().entry_type().is_file() {
                    return None;
                }
                let path = entry.path().unwrap().into_owned();
                assert_eq!(entry.header().mode().unwrap(), 0o600);
                assert_eq!(entry.header().uid().unwrap(), 1000);
                let mut content = Vec::new();
                entry.read_to_end(&mut content).unwrap();
                Some((path, content))
            })
            .collect()
    }

    #[test]
    fn archives_separate_supervisor_credentials_and_bind_one_channel() {
        let identity = ResolvedWorkloadIdentity::new(
            1000,
            1001,
            vec![],
            "image".into(),
            "sha256:image".into(),
        )
        .unwrap();
        let archives =
            bootstrap_archives("sandbox", "container", &identity, HashMap::new()).unwrap();
        let workload = files(&archives.workload);
        let supervisor = files(&archives.supervisor);
        assert_eq!(workload.len(), 4);
        assert_eq!(supervisor.len(), 2);
        assert!(
            workload
                .keys()
                .all(|path| path.starts_with(".openshell/channel/sandbox"))
        );
        assert!(
            supervisor
                .keys()
                .all(|path| path.starts_with(".openshell/supervisor"))
        );
        let config: BoundaryConfig = serde_json::from_slice(
            workload
                .get(&PathBuf::from(BOOTSTRAP_PATH.trim_start_matches('/')))
                .unwrap(),
        )
        .unwrap();
        let topology: BoundaryTopology = serde_json::from_slice(
            supervisor
                .get(&PathBuf::from(TOPOLOGY_PATH.trim_start_matches('/')))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(config.boundary_id, topology.boundary_id);
        assert_eq!(config.bootstrap_token, topology.bootstrap_token);
        assert_eq!(config.driver_fence, topology.driver_fence);
        assert_eq!(config.workload_identity, identity);
        topology
            .driver_fence
            .validate_for_backend("podman")
            .unwrap();
        assert_eq!(
            supervisor
                .get(&PathBuf::from(RESTART_BUNDLE_PATH.trim_start_matches('/')))
                .unwrap(),
            &archives.workload
        );
    }
}
