// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman-owned provisioning for the common authenticated isolation channel.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::PathBuf;

use openshell_core::ComputeDriverError;
use openshell_core::proto::compute::v1::DriverSandbox;
use openshell_isolation_interface::boundary_protocol::{
    BoundaryConfig, BoundaryListener, BoundaryTopology, GatewayVerificationKey,
    SandboxTlsClientConfig, SandboxTlsServerConfig, SandboxTransport,
    generate_sandbox_tls_material,
};
use openshell_isolation_interface::contract::{DriverFenceEvidence, ResolvedWorkloadIdentity};

pub const LABEL_ROLE: &str = "openshell.io/isolation-role";
pub const WORKLOAD_FILTER: &str = "openshell.io/isolation-role=sandbox";
pub const CHANNEL_ROOT: &str = "/.openshell/channel";
pub const BOOTSTRAP_PATH: &str = "/.openshell/channel/sandbox/bootstrap.json";
pub const TOPOLOGY_PATH: &str = "/.openshell/supervisor/topology.payload";
pub const AUTH_BUNDLE_PATH: &str = "/.openshell/supervisor/auth.json";
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
    pub channel: Vec<u8>,
    pub workspace: Vec<u8>,
    pub supervisor: Vec<u8>,
}

/// The shared volume contains only sandbox credentials. Supervisor credentials,
/// gateway authorization, and the restart copy never enter that volume.
pub fn bootstrap_archives(
    sandbox_id: &str,
    container_id: &str,
    identity: &ResolvedWorkloadIdentity,
    child_env: HashMap<String, String>,
    launch_authentication: &openshell_core::jwt::SandboxLaunchAuthentication,
) -> Result<BootstrapArchives, ComputeDriverError> {
    launch_authentication.validate().map_err(invalid)?;
    let session_id = launch_authentication.supervisor.session_id;
    let tls = generate_sandbox_tls_material(session_id).map_err(invalid)?;
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
    let verification_keys = launch_authentication
        .verification_keys
        .iter()
        .map(|key| {
            String::from_utf8(key.public_key_pem.clone())
                .map(|public_key_pem| GatewayVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem,
                })
                .map_err(invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let config = BoundaryConfig {
        boundary_id: sandbox_id.into(),
        generation: generation.clone(),
        session_id,
        gateway_id: launch_authentication.gateway_id.clone(),
        verification_keys,
        listener: BoundaryListener::Unix {
            socket_path: PathBuf::from(SOCKET_PATH),
            tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from("/.openshell/channel/sandbox/server.crt"),
                private_key_path: PathBuf::from("/.openshell/channel/sandbox/server.key"),
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
        session_id,
        transport: SandboxTransport::Unix {
            socket_path: PathBuf::from(SOCKET_PATH),
        },
        tls: SandboxTlsClientConfig {
            server_name: tls.server_name,
            trust_anchor_pem: tls.trust_anchor_pem,
        },
        host_gateway_ip: None,
        resource_claims,
        workload_identity: identity.clone(),
        driver_fence,
    };
    // Libpod resolves the requested upload destination once for a stopped
    // container. Archive entries must be relative to the selected named volume,
    // not rootfs paths that the volume would shadow on container start.
    let mut channel = Archive::new(identity);
    channel.directory(".", 0o755, false)?;
    channel.directory("sandbox", 0o711, true)?;
    channel.file(
        "sandbox/bootstrap.json",
        &serde_json::to_vec(&config).map_err(invalid)?,
    )?;
    channel.file("sandbox/server.crt", tls.certificate_chain_pem.as_bytes())?;
    channel.file("sandbox/server.key", tls.private_key_pem.as_bytes())?;
    let channel = channel.finish()?;
    let mut workspace = Archive::new(identity);
    workspace.directory(".", 0o700, true)?;
    let mut supervisor = Archive::new(identity);
    supervisor.directory(".openshell", 0o755, false)?;
    supervisor.directory(".openshell/supervisor", 0o700, true)?;
    supervisor.file(
        TOPOLOGY_PATH,
        &serde_json::to_vec(&topology).map_err(invalid)?,
    )?;
    supervisor.file(
        AUTH_BUNDLE_PATH,
        &serde_json::to_vec(&launch_authentication.supervisor).map_err(invalid)?,
    )?;
    supervisor.file(RESTART_BUNDLE_PATH, &channel)?;
    Ok(BootstrapArchives {
        channel,
        workspace: workspace.finish()?,
        supervisor: supervisor.finish()?,
    })
}

pub fn boundary_config_from_channel_archive(
    archive: &[u8],
) -> Result<BoundaryConfig, ComputeDriverError> {
    for entry in tar::Archive::new(archive).entries().map_err(invalid)? {
        let mut entry = entry.map_err(invalid)?;
        if entry.path().map_err(invalid)?.as_ref() != std::path::Path::new("sandbox/bootstrap.json")
        {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(invalid)?;
        return serde_json::from_slice(&bytes).map_err(invalid);
    }
    Err(ComputeDriverError::Precondition(
        "Podman restart bundle has no sandbox bootstrap".to_string(),
    ))
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
    use openshell_core::jwt::{
        CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionVerificationKey,
        SupervisorAuthBundle,
    };

    fn authentication() -> SandboxLaunchAuthentication {
        SandboxLaunchAuthentication {
            supervisor: SupervisorAuthBundle {
                session_id: openshell_core::SandboxSessionId::new(),
                gateway_token: SecretJwt::parse("gateway.token.value").unwrap(),
                gateway_expires_at: i64::MAX,
                sandbox_token: SecretJwt::parse("sandbox.token.value").unwrap(),
                sandbox_expires_at: i64::MAX,
                credential_epoch: CredentialEpoch::new(1).unwrap(),
            },
            gateway_id: "gateway-test".to_string(),
            verification_keys: vec![SessionVerificationKey {
                key_id: "test-key".to_string(),
                public_key_pem: b"public-key".to_vec(),
            }],
        }
    }

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
        let authentication = authentication();
        let archives = bootstrap_archives(
            "sandbox",
            "container",
            &identity,
            HashMap::new(),
            &authentication,
        )
        .unwrap();
        let workload = files(&archives.channel);
        let supervisor = files(&archives.supervisor);
        let mut workspace = tar::Archive::new(archives.workspace.as_slice());
        let mut entries = workspace.entries().unwrap();
        let root = entries.next().unwrap().unwrap();
        assert_eq!(root.path().unwrap().as_ref(), std::path::Path::new("."));
        assert!(root.header().entry_type().is_dir());
        assert_eq!(root.header().uid().unwrap(), u64::from(identity.uid));
        assert_eq!(root.header().gid().unwrap(), u64::from(identity.gid));
        assert_eq!(root.header().mode().unwrap(), 0o700);
        assert!(entries.next().is_none());
        assert_eq!(workload.len(), 3);
        assert_eq!(supervisor.len(), 3);
        assert!(workload.keys().all(|path| path.starts_with("sandbox")));
        assert!(
            supervisor
                .keys()
                .all(|path| path.starts_with(".openshell/supervisor"))
        );
        let config: BoundaryConfig = serde_json::from_slice(
            workload
                .get(&PathBuf::from("sandbox/bootstrap.json"))
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
        assert_eq!(config.session_id, topology.session_id);
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
            &archives.channel
        );
    }
}
