// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The private `openshell.supervisor.host.v1` service: the gateway end of the
//! shared supervisor's assignment stream.
//!
//! The router admits only requests bearing a verified supervisor token, so
//! the handler sees a [`Principal::Supervisor`] and hands the stream to the
//! controller the in-process compute driver installed.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use futures::StreamExt as _;
use openshell_core::proto::supervisor_host::v1::supervisor_host_server::SupervisorHost;
use openshell_core::proto::supervisor_host::v1::{HostGatewayMessage, HostMessage};
use openshell_supervisor_control::MemberView;
use openshell_supervisor_control::controller::redirect;
use tonic::{Request, Response, Status, Streaming};

use crate::ServerState;
use crate::auth::principal::Principal;
use crate::gateway_ring::GatewayRing;

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
            .attach(identity, request.into_inner(), |member_id| {
                host_home(
                    &state,
                    &controller.pool_view().unwrap_or_default().members,
                    member_id,
                )
            })
            .await?;
        let handoff = futures::stream::once(async move {
            let stopping = *state.supervisor_sessions.subscribe_shutdown().borrow();
            let members = controller.pool_view().unwrap_or_default().members;
            stopping
                .then(|| host_home(&state, &members, &member_id))
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
fn host_home(state: &ServerState, members: &[MemberView], member_id: &str) -> Option<String> {
    if state.store.is_single_replica() {
        return None;
    }
    let ring = state.gateway_ring.read().ok()?;
    let ring = if state.gateway_shutting_down.load(Ordering::Acquire) {
        ring.without(&state.replica_id)
    } else {
        ring.clone()
    };
    let home = spread_home(&ring, members, member_id)?;
    if home == state.replica_id {
        return None;
    }
    state
        .gateway_peers
        .read()
        .ok()?
        .get(home)
        .filter(|endpoint| !endpoint.is_empty())
        .cloned()
}

/// The first replica clockwise from `member_id` on the gateway ring that
/// serves fewer than an even share of the pool's other supervisors.
fn spread_home<'a>(
    ring: &'a GatewayRing,
    members: &[MemberView],
    member_id: &str,
) -> Option<&'a str> {
    let mut load = HashMap::<&str, usize>::new();
    let mut supervisors = 1_usize;
    for member in members
        .iter()
        .filter(|member| member.member_id != member_id && !member.leaving)
    {
        supervisors += 1;
        *load.entry(member.gateway_replica.as_str()).or_default() += 1;
    }
    let cap = supervisors.div_ceil(ring.replica_count().max(1));
    ring.first_below(member_id, cap, |replica| {
        load.get(replica).copied().unwrap_or(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(member_id: &str, gateway_replica: &str) -> MemberView {
        MemberView {
            member_id: member_id.to_string(),
            process_id: String::new(),
            runtime_address: String::new(),
            leaving: false,
            gateway_replica: gateway_replica.to_string(),
        }
    }

    #[test]
    fn a_supervisor_goes_to_a_replica_below_its_even_share() {
        let ring = GatewayRing::new(["gw-a", "gw-b"]);
        let owner = ring.owner_for("sup-2").unwrap();
        let other = if owner == "gw-a" { "gw-b" } else { "gw-a" };

        assert_eq!(
            spread_home(&ring, &[member("sup-1", owner)], "sup-2"),
            Some(other)
        );
        assert_eq!(
            spread_home(&ring, &[member("sup-1", other)], "sup-2"),
            Some(owner)
        );
        // Its own record and leaving members do not count against a replica.
        let mut leaving = member("sup-3", owner);
        leaving.leaving = true;
        assert_eq!(
            spread_home(&ring, &[member("sup-2", owner), leaving], "sup-2"),
            Some(owner)
        );
    }
}
