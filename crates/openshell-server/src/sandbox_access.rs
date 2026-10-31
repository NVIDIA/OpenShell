// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The one gate in front of every way into a sandbox.
//!
//! Exec, SSH sessions (and the file transfer that rides on them), port
//! forwarding, and exposed services all reach a sandbox through a relay its
//! supervisor opens. They must agree on when a sandbox can be used, so each of
//! them calls [`acquire`] and opens its relays through the returned
//! [`SandboxAccess`]. Anything that has to happen before a sandbox can be used
//! belongs in [`acquire`], so every entry point picks it up together.
//!
//! The rules:
//!
//! - A `Ready` sandbox is usable. Opening a relay waits for its supervisor and
//!   routes to whichever replica holds it.
//! - A `Completed` or `Error` sandbox is usable while its supervisor is still
//!   connected to any replica. A retained sandbox keeps its access plane after
//!   its main process exits.
//! - Every other phase is refused.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use openshell_core::ObjectId;
use openshell_core::proto::{Sandbox, SandboxPhase, relay_open};
use tokio::io::DuplexStream;
use tokio::sync::oneshot;
use tonic::Status;

use crate::ServerState;

/// How long opening a relay waits for the supervisor session: enough to cover
/// a transient supervisor reconnect while still failing quickly.
const RELAY_SESSION_WAIT: Duration = Duration::from_secs(15);

/// Why a sandbox could not be used.
#[derive(Debug)]
pub enum AccessError {
    /// The sandbox is in a state that does not allow access.
    NotReachable,
    /// The gateway could not determine whether the sandbox is reachable.
    Lookup(Status),
    /// The supervisor did not open the relay.
    Relay(Status),
}

impl fmt::Display for AccessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotReachable => f.write_str("sandbox is not ready"),
            Self::Lookup(status) => write!(f, "sandbox access check failed: {status}"),
            Self::Relay(status) => write!(f, "supervisor relay failed: {status}"),
        }
    }
}

impl From<AccessError> for Status {
    fn from(err: AccessError) -> Self {
        match err {
            AccessError::NotReachable => Self::failed_precondition(err.to_string()),
            AccessError::Lookup(status) => status,
            AccessError::Relay(_) => Self::unavailable(err.to_string()),
        }
    }
}

/// A sandbox that passed the access rules. Relays into it are opened here.
pub struct SandboxAccess {
    state: Arc<ServerState>,
    sandbox_id: String,
}

/// Apply the access rules to `sandbox`.
pub async fn acquire(
    state: &Arc<ServerState>,
    sandbox: &Sandbox,
) -> Result<SandboxAccess, AccessError> {
    let reachable = match SandboxPhase::try_from(sandbox.phase()).ok() {
        Some(SandboxPhase::Ready) => true,
        Some(SandboxPhase::Completed | SandboxPhase::Error) => {
            crate::supervisor_session::supervisor_connected(state, sandbox.object_id())
                .await
                .map_err(AccessError::Lookup)?
        }
        _ => false,
    };
    if !reachable {
        return Err(AccessError::NotReachable);
    }
    Ok(SandboxAccess {
        state: state.clone(),
        sandbox_id: sandbox.object_id().to_string(),
    })
}

impl SandboxAccess {
    /// Ask the supervisor to open a relay to `target`, returning the channel
    /// id and a receiver that resolves once the supervisor claims it.
    pub async fn open_relay(
        &self,
        target: relay_open::Target,
        service_id: String,
    ) -> Result<(String, oneshot::Receiver<Result<DuplexStream, Status>>), AccessError> {
        crate::supervisor_session::open_routed_relay_with_target(
            &self.state,
            &self.sandbox_id,
            target,
            service_id,
            RELAY_SESSION_WAIT,
        )
        .await
        .map_err(AccessError::Relay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn sandbox_in(id: &str, phase: SandboxPhase) -> Sandbox {
        let mut sandbox = Sandbox {
            metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                id: id.to_string(),
                name: id.to_string(),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(phase as i32);
        sandbox
    }

    #[tokio::test]
    async fn access_follows_phase_and_supervisor_session() {
        let state = crate::grpc::test_support::test_server_state().await;
        let reachable = |phase: SandboxPhase| {
            let state = state.clone();
            async move {
                match acquire(&state, &sandbox_in("access", phase)).await {
                    Ok(_) => true,
                    Err(AccessError::NotReachable) => false,
                    Err(err) => panic!("unexpected access error: {err:?}"),
                }
            }
        };

        // Without a supervisor, only Ready is usable; relay opening waits for
        // its supervisor.
        assert!(reachable(SandboxPhase::Ready).await);
        for phase in [
            SandboxPhase::Provisioning,
            SandboxPhase::Completed,
            SandboxPhase::Error,
            SandboxPhase::Stopped,
            SandboxPhase::Deleting,
        ] {
            assert!(!reachable(phase).await, "{phase:?}");
        }

        // A connected supervisor keeps Completed and Error sandboxes usable,
        // but never revives one that is not running.
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, _shutdown_rx) = oneshot::channel();
        state.supervisor_sessions.register(
            "access".to_string(),
            "session".to_string(),
            tx,
            shutdown_tx,
        );
        for phase in [
            SandboxPhase::Ready,
            SandboxPhase::Completed,
            SandboxPhase::Error,
        ] {
            assert!(reachable(phase).await, "{phase:?}");
        }
        for phase in [
            SandboxPhase::Provisioning,
            SandboxPhase::Stopped,
            SandboxPhase::Deleting,
        ] {
            assert!(!reachable(phase).await, "{phase:?}");
        }
    }

    #[test]
    fn not_reachable_keeps_the_existing_status() {
        let status = Status::from(AccessError::NotReachable);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(status.message(), "sandbox is not ready");
    }
}
