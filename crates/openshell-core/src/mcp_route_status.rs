// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Redacted runtime observations for configured MCP routes.
//!
//! The types in this module deliberately cannot carry request URLs, headers,
//! bodies, tool arguments, credentials, or upstream error text. Network
//! enforcement reports only the configured route subject and a typed outcome.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

/// Maximum number of pending route observations between network enforcement
/// and the sandbox orchestrator.
///
/// Network callers use a non-blocking send and drop observations when this
/// bound is reached, so status reporting cannot delay proxied traffic.
pub const MCP_ROUTE_STATUS_CHANNEL_CAPACITY: usize = 64;

/// Derive the stable, non-secret subject reported for a configured MCP route.
///
/// The digest covers only the endpoint's lowercase host, effective sorted port
/// set, and canonical path. Every value is length-prefixed and the digest is
/// domain-separated, so concatenation cannot make distinct routes collide.
/// The modern `ports` field takes precedence over the legacy singular `port`.
#[must_use]
pub fn mcp_route_subject(endpoint: &crate::proto::NetworkEndpoint) -> String {
    const DOMAIN: &[u8] = b"openshell:mcp-route-subject:v1";

    let host = endpoint.host.to_ascii_lowercase();
    let path = match endpoint.path.as_str() {
        "" | "**" | "/**" => "/**",
        path => path,
    };
    let mut ports = if endpoint.ports.is_empty() {
        (endpoint.port != 0)
            .then_some(endpoint.port)
            .into_iter()
            .collect()
    } else {
        endpoint.ports.clone()
    };
    ports.sort_unstable();
    ports.dedup();

    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    hash_subject_value(&mut digest, host.as_bytes());
    hash_subject_value(&mut digest, path.as_bytes());
    let port_count = u64::try_from(ports.len()).unwrap_or(u64::MAX);
    hash_subject_value(&mut digest, &port_count.to_be_bytes());
    for port in ports {
        hash_subject_value(&mut digest, &port.to_be_bytes());
    }

    let mut subject = String::with_capacity("mcp-route:v1:".len() + 64);
    subject.push_str("mcp-route:v1:");
    for byte in digest.finalize() {
        // Writing to a String is infallible; ignore fmt's Result without
        // weakening the subject derivation contract with a panic path.
        let _ = write!(subject, "{byte:02x}");
    }
    subject
}

fn hash_subject_value(digest: &mut Sha256, value: &[u8]) {
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(value_len.to_be_bytes());
    digest.update(value);
}

/// A version of the policy and provider environment installed in a sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRouteStatusEpoch {
    /// Hash of the installed sandbox policy.
    pub policy_hash: String,
    /// Revision of the installed provider environment.
    pub provider_env_revision: u64,
}

/// One configured MCP endpoint in the current route inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRouteInventoryItem {
    /// Stable `OpenShell`-derived identifier validated against gateway inventory.
    pub subject: String,
    /// Whether this route depends on provider-managed credentials.
    pub provider_credentialed: bool,
}

/// A redacted outcome observed for an MCP route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum McpRouteOutcome {
    /// No MCP exchange has been observed since the route became current.
    #[default]
    NoObservedExchange,
    /// An MCP exchange reached the configured upstream successfully.
    Reachable,
    /// `OpenShell` policy denied the MCP exchange.
    PolicyDenied,
    /// A required provider credential was unavailable.
    CredentialUnavailable,
    /// TLS establishment or verification failed.
    TlsFailed,
    /// The transport could not reach or communicate with the upstream.
    TransportFailed,
    /// The upstream rejected an otherwise completed MCP exchange.
    UpstreamRejected,
}

/// A request-scoped handle that binds an observation to the installed epoch.
///
/// Its fields are private so callers cannot attach arbitrary request material.
/// Capture the handle before starting an upstream exchange and submit it only
/// after the exchange reaches a terminal outcome.
#[derive(Clone, Debug)]
pub struct McpRouteObservation {
    epoch: McpRouteStatusEpoch,
    subject: String,
}

/// Commands consumed in FIFO order by the sandbox route-status tracker.
#[derive(Debug)]
pub enum McpRouteStatusCommand {
    /// Replace the complete configured route inventory for an installed epoch.
    Reset {
        /// Policy and provider version represented by this inventory.
        epoch: McpRouteStatusEpoch,
        /// Complete set of configured MCP routes.
        routes: Vec<McpRouteInventoryItem>,
    },
    /// Apply one redacted runtime outcome to a route in the captured epoch.
    Observe {
        /// Epoch captured when the request started.
        epoch: McpRouteStatusEpoch,
        /// Stable configured route identifier.
        subject: String,
        /// Typed, non-sensitive terminal outcome.
        outcome: McpRouteOutcome,
    },
}

/// Receiving half of the bounded MCP route-status channel.
pub type McpRouteStatusReceiver = mpsc::Receiver<McpRouteStatusCommand>;

/// Non-blocking observation sender shared with network enforcement.
///
/// Inventory resets reserve bounded channel capacity and publish their epoch
/// before new requests can capture it. Runtime observations never wait for
/// capacity and therefore cannot add backpressure to network traffic.
#[derive(Clone, Debug)]
pub struct McpRouteObservationSender {
    commands: mpsc::Sender<McpRouteStatusCommand>,
    current_epoch: watch::Receiver<Option<McpRouteStatusEpoch>>,
    epoch_updates: watch::Sender<Option<McpRouteStatusEpoch>>,
}

impl McpRouteObservationSender {
    /// Enqueue a complete inventory reset and make its epoch available to new
    /// request observations.
    ///
    /// # Errors
    ///
    /// Returns the reset command when the sandbox tracker has stopped.
    pub async fn reset(
        &self,
        epoch: McpRouteStatusEpoch,
        routes: Vec<McpRouteInventoryItem>,
    ) -> Result<(), mpsc::error::SendError<McpRouteStatusCommand>> {
        // Publish the new epoch only after its reset is in the FIFO. A request
        // racing in the narrow interval conservatively captures the old epoch
        // and is ignored after reset; it can never enqueue a new-epoch outcome
        // ahead of the inventory that defines that epoch.
        let permit = self.commands.reserve().await.map_err(|_| {
            mpsc::error::SendError(McpRouteStatusCommand::Reset {
                epoch: epoch.clone(),
                routes: routes.clone(),
            })
        })?;
        permit.send(McpRouteStatusCommand::Reset {
            epoch: epoch.clone(),
            routes,
        });
        self.epoch_updates.send_replace(Some(epoch));
        Ok(())
    }

    /// Capture the current installed epoch and a route subject at request start.
    ///
    /// Returns `None` until the first complete route inventory is installed.
    #[must_use]
    pub fn begin(&self, subject: String) -> Option<McpRouteObservation> {
        self.current_epoch
            .borrow()
            .clone()
            .map(|epoch| McpRouteObservation { epoch, subject })
    }

    /// Try to enqueue a terminal observation without waiting for capacity.
    ///
    /// Returns `false` for `NoObservedExchange`, if the bounded channel is
    /// full, or if its receiver has stopped. Callers must treat a rejected
    /// update as status loss, never as a network failure.
    #[must_use]
    pub fn try_observe(&self, observation: McpRouteObservation, outcome: McpRouteOutcome) -> bool {
        if outcome == McpRouteOutcome::NoObservedExchange {
            return false;
        }
        self.commands
            .try_send(McpRouteStatusCommand::Observe {
                epoch: observation.epoch,
                subject: observation.subject,
                outcome,
            })
            .is_ok()
    }
}

/// Create the bounded channel used for MCP route inventory and observations.
#[must_use]
pub fn mcp_route_status_channel() -> (McpRouteObservationSender, McpRouteStatusReceiver) {
    let (commands, receiver) = mpsc::channel(MCP_ROUTE_STATUS_CHANNEL_CAPACITY);
    let (epoch_updates, current_epoch) = watch::channel(None);
    (
        McpRouteObservationSender {
            commands,
            current_epoch,
            epoch_updates,
        },
        receiver,
    )
}

/// One route outcome in a complete status snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRouteStatus {
    /// Stable `OpenShell`-derived identifier validated against gateway inventory.
    pub subject: String,
    /// Latest outcome observed for the route in the current epoch.
    pub outcome: McpRouteOutcome,
}

/// Complete MCP route status for one installed policy and provider revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpRouteStatusSnapshot {
    /// Policy and provider version represented by this snapshot.
    pub epoch: McpRouteStatusEpoch,
    /// Complete, subject-sorted set of configured route statuses.
    pub routes: Vec<McpRouteStatus>,
    /// Subjects that carried at least one new route outcome in this report batch.
    ///
    /// The gateway uses this set to advance observation timestamps only for
    /// routes actually observed since the previous accepted report. It
    /// validates every value against `routes` and the current policy.
    pub observed_subjects: Vec<String>,
    /// Active supervisor session authorized to report this snapshot.
    ///
    /// The route reporter fills this field after the gateway accepts the
    /// `ConnectSupervisor` stream. Trackers leave it empty.
    pub supervisor_session_id: String,
    /// Monotonic sequence within one session and configuration epoch.
    ///
    /// A retry must preserve the complete snapshot and this sequence so the
    /// gateway can acknowledge a lost response without advancing timestamps.
    pub report_sequence: u64,
}

#[derive(Clone, Copy, Debug)]
struct TrackedRoute {
    outcome: McpRouteOutcome,
}

/// FIFO state machine that turns inventory and observations into snapshots.
#[derive(Debug, Default)]
pub struct McpRouteStatusTracker {
    epoch: Option<McpRouteStatusEpoch>,
    routes: BTreeMap<String, TrackedRoute>,
}

impl McpRouteStatusTracker {
    /// Apply one FIFO command.
    ///
    /// Returns `true` when the command must publish a fresh snapshot. Repeated
    /// outcomes still return `true` so the gateway can advance observation
    /// freshness. Observations for an old epoch or an unknown subject are
    /// ignored, which prevents an in-flight pre-reset exchange from updating
    /// post-reset readiness.
    pub fn apply(&mut self, command: McpRouteStatusCommand) -> bool {
        match command {
            McpRouteStatusCommand::Reset { epoch, routes } => {
                self.reset(epoch, routes);
                true
            }
            McpRouteStatusCommand::Observe {
                epoch,
                subject,
                outcome,
            } => {
                if self.epoch.as_ref() != Some(&epoch) {
                    return false;
                }
                let Some(route) = self.routes.get_mut(&subject) else {
                    return false;
                };
                // Repeated outcomes are material observations: the gateway
                // advances route freshness even when the classification is
                // unchanged.
                route.outcome = outcome;
                true
            }
        }
    }

    /// Return the complete current snapshot, or `None` before the first reset.
    #[must_use]
    pub fn snapshot(&self) -> Option<McpRouteStatusSnapshot> {
        let epoch = self.epoch.clone()?;
        let routes = self
            .routes
            .iter()
            .map(|(subject, route)| McpRouteStatus {
                subject: subject.clone(),
                outcome: route.outcome,
            })
            .collect();
        Some(McpRouteStatusSnapshot {
            epoch,
            routes,
            observed_subjects: Vec::new(),
            supervisor_session_id: String::new(),
            report_sequence: 0,
        })
    }

    /// Forget outcomes learned by a previous authenticated supervisor session.
    ///
    /// A replacement session is a new observation authority. Retaining its
    /// predecessor's outcomes would let a reconnect restore stale readiness
    /// immediately after the gateway resets the public conditions.
    pub fn clear_observations(&mut self) -> bool {
        let Some(_epoch) = self.epoch.as_ref() else {
            return false;
        };
        for route in self.routes.values_mut() {
            route.outcome = McpRouteOutcome::NoObservedExchange;
        }
        true
    }

    fn reset(&mut self, epoch: McpRouteStatusEpoch, inventory: Vec<McpRouteInventoryItem>) {
        let policy_changed = self
            .epoch
            .as_ref()
            .is_none_or(|current| current.policy_hash != epoch.policy_hash);
        let provider_changed = self
            .epoch
            .as_ref()
            .is_some_and(|current| current.provider_env_revision != epoch.provider_env_revision);
        let previous = std::mem::take(&mut self.routes);

        self.routes = inventory
            .into_iter()
            .map(|route| {
                // A policy change invalidates every observation. A provider
                // revision invalidates only routes whose runtime behavior can
                // depend on provider-managed credentials.
                let preserve =
                    !policy_changed && (!provider_changed || !route.provider_credentialed);
                let outcome = if preserve {
                    previous
                        .get(&route.subject)
                        .map_or(McpRouteOutcome::NoObservedExchange, |old| old.outcome)
                } else {
                    McpRouteOutcome::NoObservedExchange
                };
                (route.subject, TrackedRoute { outcome })
            })
            .collect();
        self.epoch = Some(epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(policy_hash: &str, provider_env_revision: u64) -> McpRouteStatusEpoch {
        McpRouteStatusEpoch {
            policy_hash: policy_hash.to_string(),
            provider_env_revision,
        }
    }

    fn inventory() -> Vec<McpRouteInventoryItem> {
        vec![
            McpRouteInventoryItem {
                subject: "route:credentialed".to_string(),
                provider_credentialed: true,
            },
            McpRouteInventoryItem {
                subject: "route:public".to_string(),
                provider_credentialed: false,
            },
        ]
    }

    fn endpoint(
        host: &str,
        port: u32,
        ports: Vec<u32>,
        path: &str,
    ) -> crate::proto::NetworkEndpoint {
        crate::proto::NetworkEndpoint {
            host: host.to_string(),
            port,
            ports,
            path: path.to_string(),
            protocol: "mcp".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn route_subject_is_stable_across_equivalent_endpoint_spelling() {
        let legacy = endpoint("MCP.EXAMPLE.COM", 443, Vec::new(), "");
        let modern = endpoint("mcp.example.com", 0, vec![443, 443], "/**");

        let subject = mcp_route_subject(&legacy);
        assert_eq!(subject, mcp_route_subject(&modern));
        assert_eq!(
            subject,
            "mcp-route:v1:4fb7e79cc7b9ddb102af3117d0a6276911d63bbbe8f1547053432d9ef0e2780d"
        );
    }

    #[test]
    fn route_subject_normalizes_effective_port_set() {
        let unsorted = endpoint("mcp.example.com", 8443, vec![8443, 443, 443], "**");
        let sorted = endpoint("mcp.example.com", 0, vec![443, 8443], "/**");

        assert_eq!(
            mcp_route_subject(&unsorted),
            mcp_route_subject(&sorted),
            "the repeated ports field takes precedence and is a set"
        );
    }

    #[test]
    fn route_subject_distinguishes_scoped_paths() {
        let root = endpoint("mcp.example.com", 443, Vec::new(), "/**");
        let scoped = endpoint("mcp.example.com", 443, Vec::new(), "/mcp");

        assert_ne!(mcp_route_subject(&root), mcp_route_subject(&scoped));
    }

    fn observe(
        epoch: McpRouteStatusEpoch,
        subject: &str,
        outcome: McpRouteOutcome,
    ) -> McpRouteStatusCommand {
        McpRouteStatusCommand::Observe {
            epoch,
            subject: subject.to_string(),
            outcome,
        }
    }

    #[test]
    fn policy_change_resets_every_route() {
        let mut tracker = McpRouteStatusTracker::default();
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: inventory(),
        });
        tracker.apply(observe(
            epoch("policy-a", 1),
            "route:credentialed",
            McpRouteOutcome::Reachable,
        ));
        tracker.apply(observe(
            epoch("policy-a", 1),
            "route:public",
            McpRouteOutcome::Reachable,
        ));

        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-b", 1),
            routes: inventory(),
        });

        let snapshot = tracker.snapshot().expect("reset creates a snapshot");
        assert!(
            snapshot
                .routes
                .iter()
                .all(|route| route.outcome == McpRouteOutcome::NoObservedExchange)
        );
    }

    #[test]
    fn reset_rebuilds_inventory_and_preserves_matching_current_routes() {
        let mut tracker = McpRouteStatusTracker::default();
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: inventory(),
        });
        tracker.apply(observe(
            epoch("policy-a", 1),
            "route:public",
            McpRouteOutcome::Reachable,
        ));

        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: vec![
                McpRouteInventoryItem {
                    subject: "route:new".to_string(),
                    provider_credentialed: false,
                },
                McpRouteInventoryItem {
                    subject: "route:public".to_string(),
                    provider_credentialed: false,
                },
            ],
        });

        assert_eq!(
            tracker.snapshot().expect("reset creates a snapshot").routes,
            vec![
                McpRouteStatus {
                    subject: "route:new".to_string(),
                    outcome: McpRouteOutcome::NoObservedExchange,
                },
                McpRouteStatus {
                    subject: "route:public".to_string(),
                    outcome: McpRouteOutcome::Reachable,
                },
            ]
        );
    }

    #[test]
    fn provider_change_preserves_only_uncredentialed_routes() {
        let mut tracker = McpRouteStatusTracker::default();
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: inventory(),
        });
        for subject in ["route:credentialed", "route:public"] {
            tracker.apply(observe(
                epoch("policy-a", 1),
                subject,
                McpRouteOutcome::Reachable,
            ));
        }

        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 2),
            routes: inventory(),
        });

        let snapshot = tracker.snapshot().expect("reset creates a snapshot");
        assert_eq!(
            snapshot.routes,
            vec![
                McpRouteStatus {
                    subject: "route:credentialed".to_string(),
                    outcome: McpRouteOutcome::NoObservedExchange,
                },
                McpRouteStatus {
                    subject: "route:public".to_string(),
                    outcome: McpRouteOutcome::Reachable,
                },
            ]
        );
    }

    #[test]
    fn stale_observation_cannot_update_new_epoch() {
        let mut tracker = McpRouteStatusTracker::default();
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: inventory(),
        });
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 2),
            routes: inventory(),
        });

        assert!(!tracker.apply(observe(
            epoch("policy-a", 1),
            "route:credentialed",
            McpRouteOutcome::Reachable,
        )));
        assert_eq!(
            tracker.snapshot().expect("reset creates a snapshot").routes[0].outcome,
            McpRouteOutcome::NoObservedExchange
        );
    }

    #[test]
    fn repeated_outcome_remains_a_reportable_observation() {
        let mut tracker = McpRouteStatusTracker::default();
        tracker.apply(McpRouteStatusCommand::Reset {
            epoch: epoch("policy-a", 1),
            routes: inventory(),
        });
        let first = tracker.apply(observe(
            epoch("policy-a", 1),
            "route:public",
            McpRouteOutcome::Reachable,
        ));
        let second = tracker.apply(observe(
            epoch("policy-a", 1),
            "route:public",
            McpRouteOutcome::Reachable,
        ));

        assert!(first);
        assert!(second);
    }

    #[tokio::test]
    async fn sender_captures_epochs_without_sensitive_payload_fields() {
        let (sender, mut receiver) = mcp_route_status_channel();
        assert!(sender.begin("route:public".to_string()).is_none());
        sender
            .reset(epoch("policy-a", 1), inventory())
            .await
            .expect("receiver remains active");
        let observation = sender
            .begin("route:public".to_string())
            .expect("reset publishes the epoch");
        assert!(!sender.try_observe(observation.clone(), McpRouteOutcome::NoObservedExchange));
        assert!(sender.try_observe(observation, McpRouteOutcome::Reachable));

        assert!(matches!(
            receiver.recv().await,
            Some(McpRouteStatusCommand::Reset { .. })
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(McpRouteStatusCommand::Observe {
                subject,
                outcome: McpRouteOutcome::Reachable,
                ..
            }) if subject == "route:public"
        ));
    }
}
