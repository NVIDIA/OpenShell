// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod binary-identity resolver (RFC 0012 runtime contract).
//!
//! RFC 0012 delivers executable identity on every
//! [`MediatedConnection`](openshell_isolation::contract::MediatedConnection):
//! the backend resolves identity for the exact accepted connection, and an
//! unresolved identity denies that connection. This is the in-pod resolution
//! mechanism — procfs, keyed by the workload-side TCP peer port — kept in this
//! crate on purpose: the proxy that consumes identity is here, and so are
//! procfs and the binary identity cache. The result type lives in the lower
//! `openshell-isolation` crate (network -> isolation -> core, acyclic).
//!
//! Adoption note: the proxy hot path still resolves identity inline through
//! [`BinaryIdentityCache`](crate::identity::BinaryIdentityCache). Routing the
//! live accept path through `MediationIngress` (so every connection carries
//! this resolver's result) is the remaining live-adoption refactor.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use openshell_isolation::contract::{BinaryIdentity, ResolveError};

/// In-pod binary-identity resolver: reads and hashes the connecting binary from
/// procfs. Resolution fails closed; it never fabricates identity fields.
pub struct ProcfsIdentityResolver {
    /// The workload entrypoint PID, whose network namespace owns the peer
    /// sockets the proxy resolves. Published once the agent starts.
    pub entrypoint_pid: Arc<AtomicU32>,
}

impl ProcfsIdentityResolver {
    /// Resolve the executable identity behind a workload connection, keyed by
    /// its workload-side TCP peer port.
    pub fn resolve_peer_port(&self, peer_port: u16) -> Result<BinaryIdentity, ResolveError> {
        // procfs resolution is Linux-only; on other targets the supervisor has
        // no procfs to read, so resolution fails closed.
        #[cfg(target_os = "linux")]
        {
            self.resolve_via_procfs(peer_port)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = peer_port;
            Err(ResolveError::Failed(
                "no procfs on this platform; identity resolution unavailable".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcfsIdentityResolver {
    fn resolve_via_procfs(&self, peer_port: u16) -> Result<BinaryIdentity, ResolveError> {
        use std::sync::atomic::Ordering;

        let entrypoint_pid = self.entrypoint_pid.load(Ordering::Acquire);
        if entrypoint_pid == 0 {
            // No workload yet: nothing to attribute the connection to. Fail
            // closed so a binary-scoped rule cannot match an unattributed peer.
            return Err(ResolveError::NotFound);
        }

        let (binary_path, owner_pid) =
            crate::procfs::resolve_tcp_peer_identity(entrypoint_pid, peer_port)
                .map_err(|_| ResolveError::NotFound)?;

        // Hash the live `/proc/<pid>/exe` object, not the reopened resolved
        // path: opening the magic symlink pins the inode the process is actually
        // executing, so a post-resolution swap of the path cannot launder the
        // hash. A missing digest is `None`, never an empty string, and an
        // unhashable binary fails closed rather than asserting an identity the
        // resolver could not verify.
        let exe = std::path::PathBuf::from(format!("/proc/{owner_pid}/exe"));
        let binary_sha256 = match crate::procfs::file_sha256(&exe) {
            Ok(digest) => Some(digest),
            Err(_) => {
                return Err(ResolveError::Failed(
                    "could not hash connecting binary; refusing to assert identity".to_string(),
                ));
            }
        };

        let ancestors = crate::procfs::collect_ancestor_binaries(owner_pid, entrypoint_pid);
        let cmdline_paths = crate::procfs::cmdline_absolute_paths(owner_pid);

        Ok(BinaryIdentity {
            binary_path,
            binary_sha256,
            ancestors,
            cmdline_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the mediation service: a binary-scoped rule can only be
    /// authorized by a resolved identity carrying the fields it requires.
    fn admits_binary_rule(result: Result<BinaryIdentity, ResolveError>) -> bool {
        matches!(result, Ok(identity) if identity.binary_sha256.is_some())
    }

    #[test]
    fn fails_closed_before_the_workload_starts() {
        // entrypoint_pid == 0 means no agent yet; identity must fail closed so a
        // binary-scoped rule cannot be satisfied by an unattributed connection.
        let resolver = ProcfsIdentityResolver {
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
        };
        assert!(!admits_binary_rule(resolver.resolve_peer_port(12345)));
    }

    #[test]
    fn unknown_peer_fails_closed() {
        // A peer port no live workload connection owns must resolve to an error,
        // never a fabricated identity.
        let resolver = ProcfsIdentityResolver {
            entrypoint_pid: Arc::new(AtomicU32::new(u32::MAX - 1)),
        };
        assert!(!admits_binary_rule(resolver.resolve_peer_port(1)));
    }
}
