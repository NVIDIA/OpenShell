// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The in-pod binary-identity resolver (RFC 0012 runtime contract).
//!
//! RFC 0012 delivers executable identity on every
//! [`MediatedConnection`](openshell_isolation_interface::contract::MediatedConnection):
//! the backend resolves identity for the accepted connection before mediation.
//! An unresolved identity denies that connection. This is the in-pod
//! resolution mechanism — procfs, keyed by the workload-side TCP peer port —
//! kept in this crate on purpose: the proxy that consumes identity is here, and
//! so are procfs and the binary identity cache. Stronger backends may use a
//! different resolution mechanism without changing the contract. The result
//! type lives in the lower `openshell-isolation-interface` crate (network ->
//! interface -> core, acyclic).
//!
//! The legacy listener still resolves identity in the proxy hot path. The RFC
//! 0012 co-located source invokes this resolver before returning each accepted
//! connection, so mediation consumes the bound identity result.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use openshell_binary_identity::ProcfsIdentityResolver as SharedProcfsIdentityResolver;
use openshell_isolation_interface::contract::{BinaryIdentity, ResolveError};

/// In-pod binary-identity resolver: reads and hashes the executable resolved
/// for an accepted connection from procfs. Resolution fails closed; it never
/// fabricates identity fields.
#[derive(Clone)]
pub struct ProcfsIdentityResolver {
    /// The workload entrypoint PID, whose network namespace owns the peer
    /// sockets the proxy resolves. Published once the agent starts.
    pub entrypoint_pid: Arc<AtomicU32>,
}

impl ProcfsIdentityResolver {
    /// Resolve the executable identity behind an accepted workload connection.
    pub fn resolve_connection(
        &self,
        workload_addr: std::net::SocketAddr,
        proxy_addr: std::net::SocketAddr,
    ) -> Result<BinaryIdentity, ResolveError> {
        // procfs resolution is Linux-only; on other targets the supervisor has
        // no procfs to read, so resolution fails closed.
        #[cfg(target_os = "linux")]
        {
            self.resolve_via_procfs(workload_addr, proxy_addr)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (workload_addr, proxy_addr);
            Err(ResolveError::Failed(
                "no procfs on this platform; identity resolution unavailable".to_string(),
            ))
        }
    }
}

#[cfg(target_os = "linux")]
impl ProcfsIdentityResolver {
    fn resolve_via_procfs(
        &self,
        workload_addr: std::net::SocketAddr,
        proxy_addr: std::net::SocketAddr,
    ) -> Result<BinaryIdentity, ResolveError> {
        use std::sync::atomic::Ordering;

        let entrypoint_pid = self.entrypoint_pid.load(Ordering::Acquire);
        if entrypoint_pid == 0 {
            // No workload yet: nothing to attribute the connection to. Fail
            // closed so a binary-scoped rule cannot match an unattributed peer.
            return Err(ResolveError::NotFound);
        }

        let connection = crate::procfs::WorkloadProxyTcpConnection::new(workload_addr, proxy_addr);
        let owners = crate::procfs::resolve_tcp_peer_socket_owners(entrypoint_pid, connection)
            .map_err(|_| ResolveError::NotFound)?;
        let resolver = SharedProcfsIdentityResolver::for_process_tree(entrypoint_pid);
        let mut identities = Vec::with_capacity(owners.owners.len());
        for owner in owners.owners {
            identities.push(resolver.resolve(owner.pid)?);
        }
        let Some(identity) = identities.first().cloned() else {
            return Err(ResolveError::NotFound);
        };
        if identities.iter().skip(1).any(|candidate| {
            candidate.binary_path != identity.binary_path
                || candidate.binary_digest != identity.binary_digest
                || candidate.ancestors != identity.ancestors
                || candidate.cmdline_paths != identity.cmdline_paths
        }) {
            return Err(ResolveError::Failed(
                "shared socket owners have different policy identities".to_string(),
            ));
        }
        Ok(identity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stands in for the mediation service: a binary-scoped rule can only be
    /// authorized by a resolved identity carrying the fields it requires.
    fn admits_binary_rule(result: Result<BinaryIdentity, ResolveError>) -> bool {
        matches!(result, Ok(identity) if identity.binary_digest.is_some())
    }

    #[test]
    fn fails_closed_before_the_workload_starts() {
        // entrypoint_pid == 0 means no agent yet; identity must fail closed so a
        // binary-scoped rule cannot be satisfied by an unattributed connection.
        let resolver = ProcfsIdentityResolver {
            entrypoint_pid: Arc::new(AtomicU32::new(0)),
        };
        assert!(!admits_binary_rule(resolver.resolve_connection(
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:3128".parse().unwrap(),
        )));
    }

    #[test]
    fn unknown_peer_fails_closed() {
        // A peer port no live workload connection owns must resolve to an error,
        // never a fabricated identity.
        let resolver = ProcfsIdentityResolver {
            entrypoint_pid: Arc::new(AtomicU32::new(u32::MAX - 1)),
        };
        assert!(!admits_binary_rule(resolver.resolve_connection(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:3128".parse().unwrap(),
        )));
    }
}
