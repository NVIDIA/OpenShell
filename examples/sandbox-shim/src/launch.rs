// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Launch material handed from the host driver to the in-guest shim, and the
//! workload plan both sides derive from the explicit privilege setting.
use anyhow::Result;
use openshell_core::jwt::{CredentialEpoch, SessionRotation, SessionVerificationKey};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use openshell_sandbox_backend::delegated::DelegatedLaunch;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Guest UID/GID of a nonprivileged workload.
pub const NONPRIVILEGED_ID: u32 = 10_001;
/// Guest UID/GID that a privileged workload's user-namespace root maps to.
pub const PRIVILEGED_BASE_ID: u32 = 100_000;
/// IDs mapped into a privileged workload's user namespace (0..RANGE).
pub const PRIVILEGED_ID_RANGE: u32 = 65_536;
/// Guest-local CONNECT proxy for mediated egress.
pub const PROXY_ADDR: &str = "127.0.0.1:3128";
/// AF_VSOCK port the shim serves on inside Firecracker.
pub const VSOCK_PORT: u32 = 5000;
pub const WORKDIR: &str = "/sandbox";
/// Mount point, in the shim's root, of the separate workload rootfs.
pub const WORKLOAD_ROOT: &str = "/run/openshell/workload";
/// Shim-owned CA material, bind-mounted read-only into the workload root.
pub const SHIM_TLS_DIR: &str = "/run/openshell/tls";
/// Where the workload sees the CA material.
pub const WORKLOAD_TLS_DIR: &str = "/etc/openshell-tls";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Substrate {
    Firecracker,
    Gvisor,
}

impl Substrate {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Gvisor => "gvisor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    /// Root of a dedicated user namespace with a full capability set.
    Privileged,
    /// One fixed non-root guest UID with `no_new_privs`.
    Nonprivileged,
}

impl Privilege {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Privileged => "privileged",
            Self::Nonprivileged => "nonprivileged",
        }
    }

    /// Guest kernel UID/GID the workload runs as. For `Privileged` this is
    /// what user-namespace root maps to; the identity contract admits no UID 0.
    pub fn guest_id(self) -> u32 {
        match self {
            Self::Privileged => PRIVILEGED_BASE_ID,
            Self::Nonprivileged => NONPRIVILEGED_ID,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Launch {
    pub boundary: DelegatedLaunch,
    pub descriptor: Vec<u8>,
    pub substrate: Substrate,
    pub privilege: Privilege,
    pub image: Image,
    pub gateway_id: String,
    pub keys: Vec<SessionVerificationKey>,
    pub epoch: CredentialEpoch,
    pub rotation: SessionRotation,
    pub certificate: String,
    pub private_key: String,
}

/// Content identity of what the guest boots. `rootfs_source_sha256` covers the
/// rootfs tree before the driver's ownership transform; the transform and the
/// shim binary are named separately rather than folded into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub rootfs_source_sha256: String,
    pub shim_sha256: String,
}

impl Image {
    pub fn validate(&self) -> Result<()> {
        for digest in [&self.rootfs_source_sha256, &self.shim_sha256] {
            anyhow::ensure!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "digests must be SHA-256 hex strings"
            );
        }
        Ok(())
    }
}

/// Owner the driver gives every file of the workload rootfs.
pub fn workload_root_owner(privilege: Privilege) -> u32 {
    match privilege {
        Privilege::Privileged => PRIVILEGED_BASE_ID,
        Privilege::Nonprivileged => 0,
    }
}

/// Immutable launch binding the supervisor echoes in `OpenBoundary`.
pub fn descriptor(substrate: Substrate, privilege: Privilege, image: &Image) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "substrate": substrate.as_str(),
        "privilege": privilege.as_str(),
        "rootfs_source_sha256": image.rootfs_source_sha256,
        "rootfs_owner_transform": format!("all files chowned to {}:{}", workload_root_owner(privilege), workload_root_owner(privilege)),
        "shim_sha256": image.shim_sha256,
    }))
    .expect("string-valued descriptor")
}

/// The identity's resource digest is the SHA-256 of the descriptor, so it
/// covers the rootfs source, the ownership transform, and the shim.
pub fn identity(
    substrate: Substrate,
    privilege: Privilege,
    image: &Image,
) -> Result<ResolvedWorkloadIdentity> {
    let id = privilege.guest_id();
    let digest = openshell_crypto::sha256(&descriptor(substrate, privilege, image))?;
    Ok(ResolvedWorkloadIdentity::new(
        id,
        id,
        vec![],
        format!("sandbox-shim-{}", privilege.as_str()),
        digest.iter().map(|b| format!("{b:02x}")).collect(),
    )?)
}

/// What this backend applies, and what it does not. The driver commits to it in
/// the provisioning fence and the shim reports it as `backend_audit`. It states
/// properties the shim sets up; it is not independent proof.
pub fn audit(substrate: Substrate, privilege: Privilege, image: &Image) -> serde_json::Value {
    let network_fence = match substrate {
        Substrate::Firecracker => {
            "microvm has no network device; vsock carries only the backend channel"
        }
        Substrate::Gvisor => {
            "runsc --network=none (loopback only); host UDS limited to the backend channel"
        }
    };
    let process = match privilege {
        Privilege::Privileged => format!(
            "user-namespace root mapped to guest ids {PRIVILEGED_BASE_ID}..{}; capabilities only inside that namespace; not guest init-namespace root",
            PRIVILEGED_BASE_ID + PRIVILEGED_ID_RANGE - 1
        ),
        Privilege::Nonprivileged => {
            format!("guest uid/gid {NONPRIVILEGED_ID}, no supplementary groups, no_new_privs")
        }
    };
    let (egress, binary_identity, seccomp) = match substrate {
        Substrate::Firecracker => (
            "native: every workload process inherits the openshell-sandbox networking seccomp user-notification listener; the production NetworkBroker injects loopback-bound sockets created in the shim's network namespace, relays external TCP only after the supervisor decides, and answers UDP and TCP DNS on 127.0.0.53:53 through supervisor policy DNS; other external UDP is denied; no proxy settings; a listener, broker or launcher failure ends the boundary",
            "seccomp-notifying thread resolved through guest procfs by the shim, with per-generation trust-on-first-use digest pins; each path is reported only if it names the running executable inside the process's own root; processes with another root (nested containers) are reported under /.openshell/nested-root",
            "networking user-notification listener plus child hardening (io_uring, ptrace, process_vm, pidfd_getfd, kcmp, bpf, perf_event_open, userfaultfd, kernel modules, and nested seccomp listeners refused); no other syscall filtering",
        ),
        Substrate::Gvisor => (
            "HTTP CONNECT proxy on guest loopback only; other TCP and all UDP have no route and are denied, not mediated",
            "best effort: guest procfs socket-owner lookup by the in-guest shim; racy under fd passing or exec and not kernel-authoritative",
            "not applied",
        ),
    };
    serde_json::json!({
        "backend": crate::protocol::BACKEND,
        "substrate": substrate.as_str(),
        "privilege": privilege.as_str(),
        "image": image,
        "process": process,
        "workload_root": "private mount namespace pivoted into a separate workload rootfs; shim binary, launch credentials, backend channel and CA source live outside it; CA is bind-mounted read-only",
        "network_fence": network_fence,
        "egress": egress,
        "binary_identity": binary_identity,
        "filesystem_enforcement": "none; landlock best_effort filesystem_policy paths are accepted unenforced, hard_requirement is rejected",
        "landlock": "not applied",
        "seccomp": seccomp,
        "tamper_resistance": "none against guest init-namespace root",
    })
}

pub fn evidence(substrate: Substrate, privilege: Privilege, image: &Image) -> Vec<u8> {
    serde_json::to_vec(&audit(substrate, privilege, image)).expect("JSON value")
}

/// Streaming SHA-256 of a file, as lowercase hex.
pub fn file_sha256(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut digest = openshell_crypto::sha256_digest()?;
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read])?;
    }
    Ok(digest
        .finish()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image() -> Image {
        Image {
            rootfs_source_sha256: "a".repeat(64),
            shim_sha256: "b".repeat(64),
        }
    }

    #[test]
    fn identities_are_never_root() {
        for privilege in [Privilege::Privileged, Privilege::Nonprivileged] {
            let identity = identity(Substrate::Gvisor, privilege, &image()).unwrap();
            assert_ne!(identity.uid, 0);
            assert_ne!(identity.gid, 0);
        }
    }

    #[test]
    fn audit_does_not_claim_enforcement_it_lacks() {
        let audit = audit(Substrate::Gvisor, Privilege::Privileged, &image());
        assert_eq!(audit["landlock"], "not applied");
        assert_eq!(audit["seccomp"], "not applied");
        assert!(
            audit["filesystem_enforcement"]
                .as_str()
                .unwrap()
                .starts_with("none")
        );
        assert!(
            audit["tamper_resistance"]
                .as_str()
                .unwrap()
                .starts_with("none")
        );
        let firecracker = super::audit(Substrate::Firecracker, Privilege::Privileged, &image());
        assert_eq!(firecracker["landlock"], "not applied");
        assert!(
            firecracker["egress"]
                .as_str()
                .unwrap()
                .starts_with("native")
        );
    }
}
