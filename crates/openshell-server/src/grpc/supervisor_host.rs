// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The private `openshell.supervisor.host.v1` service: the gateway end of the
//! supervisor assignment streams. Shared hosts attach with gateway-issued host
//! tokens; dedicated warm supervisors register with driver-authenticated physical
//! identities and wait for their own durable claim. Neither bootstrap identity
//! is accepted on the ordinary sandbox APIs.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures::StreamExt as _;
use openshell_core::proto::supervisor_host::v1::supervisor_host_server::SupervisorHost;
use openshell_core::proto::supervisor_host::v1::{
    HostGatewayMessage, HostMessage, RegisterSupervisorRequest, RegisterSupervisorResponse,
};
use openshell_supervisor_control::controller::redirect;
use tonic::{Request, Response, Status, Streaming};

use crate::ServerState;
use crate::auth::principal::Principal;

/// gRPC path prefix of the supervisor host service.
pub const SUPERVISOR_HOST_PATH_PREFIX: &str = "/openshell.supervisor.host.v1.SupervisorHost/";

#[derive(Clone)]
pub struct SupervisorHostService {
    state: Arc<ServerState>,
}

impl SupervisorHostService {
    #[must_use]
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl SupervisorHost for SupervisorHostService {
    type RegisterSupervisorStream = Pin<
        Box<
            dyn tokio_stream::Stream<Item = Result<RegisterSupervisorResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn register_supervisor(
        &self,
        request: Request<RegisterSupervisorRequest>,
    ) -> Result<Response<Self::RegisterSupervisorStream>, Status> {
        let expected = match request.extensions().get::<Principal>() {
            Some(Principal::SupervisorRegistration(identity)) => identity.clone(),
            _ => {
                return Err(Status::permission_denied(
                    "registration requires physical supervisor authentication",
                ));
            }
        };
        let credential = crate::auth::authenticator::bearer_credential(request.metadata().as_ref())
            .ok_or_else(|| Status::unauthenticated("missing bootstrap credential"))?
            .to_string();
        let pool = self
            .state
            .dedicated_warm_pool
            .clone()
            .ok_or_else(|| Status::failed_precondition("dedicated warm pooling is disabled"))?;
        let state = self.state.clone();
        tracing::info!(route = %expected.route, "dedicated supervisor registration pending");
        let mut shutdown = state.supervisor_sessions.subscribe_shutdown();
        let wait = async move {
            loop {
                let changed = pool.claim_changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if pool.dedicated_registration(&expected).await?.is_some() {
                    // The original Pod/CR binding must still exist at delivery.
                    // Re-reading also fences replaced Pods and namespace retirement.
                    let observed = state
                        .compute
                        .authenticate_compute_credential(&credential, true)
                        .await?;
                    if observed.supervisor_registration.as_ref() != Some(&expected)
                        || !observed.sandbox_id.is_empty()
                    {
                        return Err(Status::permission_denied(
                            "physical supervisor binding changed",
                        ));
                    }
                    // Recheck durable identity/epoch after the external identity read.
                    let launch_material = pool
                        .dedicated_registration(&expected)
                        .await?
                        .ok_or_else(|| Status::permission_denied("claim was withdrawn"))?;
                    tracing::info!(route = %expected.route, "dedicated supervisor claim delivered");
                    return Ok(RegisterSupervisorResponse { launch_material });
                }
                tokio::select! {
                    () = &mut changed => {},
                    // Other replicas commit to the same durable store. This is
                    // server-side observation, not a registration retry.
                    () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {},
                }
            }
        };
        let outbound = futures::stream::once(async move {
            tokio::select! {
                result = wait => result,
                _ = shutdown.wait_for(|stopping| *stopping) => Err(Status::unavailable("gateway is shutting down")),
            }
        });
        Ok(Response::new(Box::pin(outbound)))
    }

    type AttachStream = Pin<
        Box<dyn tokio_stream::Stream<Item = Result<HostGatewayMessage, Status>> + Send + 'static>,
    >;

    async fn attach(
        &self,
        request: Request<Streaming<HostMessage>>,
    ) -> Result<Response<Self::AttachStream>, Status> {
        let identity = match request.extensions().get::<Principal>() {
            Some(Principal::Supervisor(supervisor)) => supervisor.identity.clone(),
            _ => {
                return Err(Status::permission_denied(
                    "the supervisor assignment stream requires a supervisor token",
                ));
            }
        };
        let controller = self
            .state
            .compute
            .supervisor_host()
            .ok_or_else(|| {
                Status::failed_precondition("this gateway does not host a shared supervisor")
            })?
            .clone();
        // A stopping replica sheds its hosts so they reattach to a live one
        // before their sandbox sessions follow them there.
        let mut shutdown = self.state.supervisor_sessions.subscribe_shutdown();
        if *shutdown.borrow() {
            return Err(Status::unavailable("gateway is shutting down"));
        }
        let state = self.state.clone();
        let (member_id, outbound) = controller
            .attach(
                identity,
                request.into_inner(),
                |member_id, accepts_redirect| host_home(&state, member_id, accepts_redirect),
            )
            .await?;
        let handoff = futures::stream::once(async move {
            let stopping = *state.supervisor_sessions.subscribe_shutdown().borrow();
            stopping
                .then(|| host_home(&state, &member_id, true))
                .flatten()
                .map(|peer_endpoint| Ok(redirect(peer_endpoint)))
        })
        .filter_map(std::future::ready);
        let outbound = outbound
            .take_until(async move {
                let _ = shutdown.wait_for(|shutdown| *shutdown).await;
            })
            .chain(handoff);
        Ok(Response::new(Box::pin(outbound)))
    }
}

/// Peer endpoint of the replica that should serve the shared supervisor
/// `member_id` when that is not this replica. A stopping replica leaves
/// itself out.
fn host_home(state: &ServerState, member_id: &str, accepts_redirect: bool) -> Option<String> {
    if state.store.is_single_replica() {
        return None;
    }
    let ring = state.gateway_ring.read().ok()?;
    let ring = if state.gateway_shutting_down.load(Ordering::Acquire) {
        ring.without(&state.replica_id)
    } else {
        ring.clone()
    };
    let home =
        state
            .supervisor_spread
            .route(&ring, &state.replica_id, member_id, accepts_redirect)?;
    state
        .gateway_peers
        .read()
        .ok()?
        .get(&home)
        .filter(|endpoint| !endpoint.is_empty())
        .cloned()
}
