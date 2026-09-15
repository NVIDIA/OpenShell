// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Last observed network results for configured external tool endpoints.
//!
//! MCP-over-HTTP enforcement currently supplies the observations. Results are
//! passive evidence and do not determine sandbox readiness or present health.
//!
//! The types in this module deliberately cannot carry request URLs, headers,
//! bodies, tool arguments, credentials, or upstream error text. Network
//! enforcement reports only the configured endpoint identifier and a typed result.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};

/// Maximum number of pending endpoint observations between network enforcement
/// and the sandbox orchestrator.
///
/// Network callers use a non-blocking send and drop observations when this
/// bound is reached, so status reporting cannot delay proxied traffic.
pub const ENDPOINT_STATUS_CHANNEL_CAPACITY: usize = 64;

/// Derive the stable, non-secret identifier reported for a configured tool server endpoint.
///
/// The digest covers only the endpoint's lowercase host, effective sorted port
/// set, and canonical path. Every value is length-prefixed and the digest is
/// domain-separated, so concatenation cannot make distinct endpoints collide.
/// The modern `ports` field takes precedence over the legacy singular `port`.
#[must_use]
pub fn endpoint_id(endpoint: &crate::proto::NetworkEndpoint) -> String {
    initial_endpoint_status(endpoint).endpoint_id
}

/// Describe a configured tool server endpoint using the canonical identity and an unobserved result.
///
/// Only configured host, port, and path selectors are exposed. Observed request
/// URLs, query strings, caller identities, and credentials never enter this value.
#[must_use]
pub fn initial_endpoint_status(
    endpoint: &crate::proto::NetworkEndpoint,
) -> crate::proto::EndpointStatus {
    const DOMAIN: &[u8] = b"openshell:endpoint:v1";

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
    hash_identity_value(&mut digest, host.as_bytes());
    hash_identity_value(&mut digest, path.as_bytes());
    let port_count = u64::try_from(ports.len()).unwrap_or(u64::MAX);
    hash_identity_value(&mut digest, &port_count.to_be_bytes());
    for port in &ports {
        hash_identity_value(&mut digest, &port.to_be_bytes());
    }

    let mut endpoint_id = String::with_capacity("endpoint:v1:".len() + 64);
    endpoint_id.push_str("endpoint:v1:");
    for byte in digest.finalize() {
        // Writing to a String is infallible; ignore fmt's Result without
        // weakening the identity derivation contract with a panic path.
        let _ = write!(endpoint_id, "{byte:02x}");
    }
    crate::proto::EndpointStatus {
        endpoint_id,
        host,
        ports,
        path: path.to_string(),
        last_result: crate::proto::EndpointResult::NoObservedExchange.into(),
        last_reported_at: String::new(),
    }
}

fn hash_identity_value(digest: &mut Sha256, value: &[u8]) {
    let value_len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    digest.update(value_len.to_be_bytes());
    digest.update(value);
}

/// A version of the policy and provider environment installed in a sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointConfigVersion {
    /// Hash of the installed sandbox policy.
    pub policy_hash: String,
    /// Revision of the installed provider environment.
    pub provider_env_revision: u64,
}

/// Opaque identity for one inventory installation or observation authority.
///
/// Identity follows the allocation, not configuration values or a counter.
/// A retained handle keeps its allocation alive, so its identity cannot recur.
#[derive(Clone, Debug)]
pub struct EndpointObservationGeneration(Arc<()>);

impl EndpointObservationGeneration {
    fn new() -> Self {
        Self(Arc::new(()))
    }

    fn matches(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Debug)]
struct InstalledInventory {
    config_version: EndpointConfigVersion,
    generation: EndpointObservationGeneration,
}

#[derive(Debug)]
struct ObservationState {
    inventory: Option<InstalledInventory>,
    authority_generation: EndpointObservationGeneration,
}

/// One configured MCP endpoint in the current endpoint inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointInventoryEntry {
    /// Stable `OpenShell`-derived identifier validated against gateway inventory.
    pub endpoint_id: String,
    /// Whether this endpoint depends on provider-managed credentials.
    pub uses_provider_credentials: bool,
}

/// A redacted network result observed for a configured tool endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EndpointResult {
    /// No MCP exchange has been observed since the endpoint became current.
    #[default]
    NoObservedExchange,
    /// The last observed upstream HTTP response had a status below 400.
    /// This does not establish MCP protocol success or current availability.
    HttpResponseReceived,
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

/// A request-scoped handle bound to an inventory and supervisor authority.
///
/// Its fields are private so callers cannot attach arbitrary request material.
/// Capture the handle before starting an upstream exchange and submit it only
/// after the exchange reaches a terminal result.
#[derive(Clone, Debug)]
pub struct EndpointObservationHandle {
    config_version: EndpointConfigVersion,
    endpoint_id: String,
    inventory_generation: EndpointObservationGeneration,
    authority_generation: EndpointObservationGeneration,
}

/// Observation authority captured before a request selects policy or credentials.
///
/// Selection can cross asynchronous work and a configuration installation. The
/// captured identities let the eventual endpoint binding reject that mixed state,
/// including installations whose policy and provider values recur.
#[derive(Clone, Debug)]
pub struct EndpointObservationContext {
    inventory: InstalledInventory,
    authority_generation: EndpointObservationGeneration,
}

/// Commands consumed in FIFO order by the sandbox endpoint-status tracker.
#[derive(Debug)]
pub enum EndpointStatusCommand {
    /// Replace the complete configured endpoint inventory for an installed configuration version.
    Reset {
        /// Policy and provider version represented by this inventory.
        config_version: EndpointConfigVersion,
        /// Complete set of configured tool server endpoints.
        endpoints: Vec<EndpointInventoryEntry>,
        /// Unique identity minted when this reset is enqueued.
        inventory_generation: EndpointObservationGeneration,
    },
    /// Apply one redacted runtime result to an endpoint in the captured configuration version.
    Observe {
        /// Configuration captured when the request started.
        config_version: EndpointConfigVersion,
        /// Stable configured endpoint identifier.
        endpoint_id: String,
        /// Typed, non-sensitive terminal result.
        result: EndpointResult,
        /// Inventory installation captured when the request started.
        inventory_generation: EndpointObservationGeneration,
        /// Supervisor observation authority captured when the request started.
        authority_generation: EndpointObservationGeneration,
    },
}

/// Receiving half of the bounded tool server endpoint-status channel.
///
/// Construct its tracker before consuming commands so supervisor replacement
/// can invalidate handles even while the first inventory reset is queued.
#[derive(Debug)]
pub struct EndpointStatusReceiver {
    commands: mpsc::Receiver<EndpointStatusCommand>,
    current: watch::Sender<ObservationState>,
}

impl EndpointStatusReceiver {
    /// Create the FIFO tracker sharing this channel's observation authority.
    #[must_use]
    pub fn tracker(&self) -> EndpointStatusTracker {
        EndpointStatusTracker {
            config_version: None,
            inventory_generation: None,
            current: self.current.clone(),
            endpoints: BTreeMap::new(),
        }
    }

    /// Receive the next command, or `None` once all senders have stopped.
    pub async fn recv(&mut self) -> Option<EndpointStatusCommand> {
        self.commands.recv().await
    }

    /// Receive a queued command without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when the queue is empty or all senders have stopped.
    pub fn try_recv(&mut self) -> Result<EndpointStatusCommand, mpsc::error::TryRecvError> {
        self.commands.try_recv()
    }
}

/// Non-blocking observation sender shared with network enforcement.
///
/// Inventory resets reserve bounded channel capacity and publish their configuration version
/// before new requests can capture it. Runtime observations never wait for
/// capacity and therefore cannot add backpressure to network traffic.
#[derive(Clone, Debug)]
pub struct EndpointObservationSender {
    commands: mpsc::Sender<EndpointStatusCommand>,
    current: watch::Sender<ObservationState>,
}

impl EndpointObservationSender {
    /// Capture the installed observation authority before selecting request state.
    ///
    /// Returns `None` until the first complete endpoint inventory is installed.
    #[must_use]
    pub fn capture(&self) -> Option<EndpointObservationContext> {
        let current = self.current.borrow();
        Some(EndpointObservationContext {
            inventory: current.inventory.clone()?,
            authority_generation: current.authority_generation.clone(),
        })
    }

    /// Bind a selected endpoint to the authority captured at request start.
    ///
    /// The selected policy hash and any request-scoped provider revision must
    /// match that authority. A replaced inventory or supervisor also rejects the
    /// binding, even when their configuration values recur. Requests without a
    /// provider snapshot pass `None`; their policy selection is still checked.
    #[must_use]
    pub fn begin_captured(
        &self,
        context: &EndpointObservationContext,
        endpoint_id: String,
        policy_hash: &str,
        provider_env_revision: Option<u64>,
    ) -> Option<EndpointObservationHandle> {
        let config = &context.inventory.config_version;
        if config.policy_hash != policy_hash
            || provider_env_revision
                .is_some_and(|revision| revision != config.provider_env_revision)
        {
            // Runtime activation and inventory publication are separate. Reject
            // observations during that gap instead of assigning another policy's result.
            return None;
        }
        let current = self.current.borrow();
        let inventory = current.inventory.as_ref()?;
        if !inventory.generation.matches(&context.inventory.generation)
            || !current
                .authority_generation
                .matches(&context.authority_generation)
        {
            return None;
        }
        Some(EndpointObservationHandle {
            config_version: config.clone(),
            endpoint_id,
            inventory_generation: context.inventory.generation.clone(),
            authority_generation: context.authority_generation.clone(),
        })
    }

    /// Enqueue a complete inventory reset and make its configuration version available to new
    /// request observations.
    ///
    /// # Errors
    ///
    /// Returns the reset command when the sandbox tracker has stopped.
    pub async fn reset(
        &self,
        config_version: EndpointConfigVersion,
        endpoints: Vec<EndpointInventoryEntry>,
    ) -> Result<(), mpsc::error::SendError<EndpointStatusCommand>> {
        let inventory_generation = EndpointObservationGeneration::new();
        let permit = self.commands.reserve().await.map_err(|_| {
            mpsc::error::SendError(EndpointStatusCommand::Reset {
                config_version: config_version.clone(),
                endpoints: endpoints.clone(),
                inventory_generation: inventory_generation.clone(),
            })
        })?;
        // One short write lock orders FIFO insertion and publication across
        // cloned senders. Capacity is reserved before locking, so no await
        // holds the state lock and no new handle precedes its inventory.
        self.current.send_modify(|current| {
            permit.send(EndpointStatusCommand::Reset {
                config_version: config_version.clone(),
                endpoints,
                inventory_generation: inventory_generation.clone(),
            });
            current.inventory = Some(InstalledInventory {
                config_version,
                generation: inventory_generation,
            });
        });
        Ok(())
    }

    /// Capture the current inventory and supervisor authority at request start.
    ///
    /// Returns `None` until the first complete endpoint inventory is installed.
    #[must_use]
    pub fn begin(&self, endpoint_id: String) -> Option<EndpointObservationHandle> {
        let current = self.current.borrow();
        let inventory = current.inventory.as_ref()?;
        Some(EndpointObservationHandle {
            config_version: inventory.config_version.clone(),
            endpoint_id,
            inventory_generation: inventory.generation.clone(),
            authority_generation: current.authority_generation.clone(),
        })
    }

    /// Try to enqueue a terminal observation without waiting for capacity.
    ///
    /// Returns `false` for `NoObservedExchange`, if the bounded channel is
    /// full, or if its receiver has stopped. Callers must treat a rejected
    /// update as status loss, never as a network failure.
    #[must_use]
    pub fn try_observe(
        &self,
        observation: EndpointObservationHandle,
        result: EndpointResult,
    ) -> bool {
        if result == EndpointResult::NoObservedExchange {
            return false;
        }
        self.commands
            .try_send(EndpointStatusCommand::Observe {
                config_version: observation.config_version,
                endpoint_id: observation.endpoint_id,
                result,
                inventory_generation: observation.inventory_generation,
                authority_generation: observation.authority_generation,
            })
            .is_ok()
    }
}

/// Create the bounded channel used for tool server endpoint inventory and observations.
#[must_use]
pub fn endpoint_status_channel() -> (EndpointObservationSender, EndpointStatusReceiver) {
    let (commands, receiver) = mpsc::channel(ENDPOINT_STATUS_CHANNEL_CAPACITY);
    let (current, _) = watch::channel(ObservationState {
        inventory: None,
        authority_generation: EndpointObservationGeneration::new(),
    });
    (
        EndpointObservationSender {
            commands,
            current: current.clone(),
        },
        EndpointStatusReceiver {
            commands: receiver,
            current,
        },
    )
}

/// One endpoint result in a complete status snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointObservation {
    /// Stable `OpenShell`-derived identifier validated against gateway inventory.
    pub endpoint_id: String,
    /// Latest result observed for the endpoint in the current configuration version.
    pub result: EndpointResult,
}

/// Complete tool server endpoint status for one installed policy and provider revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointStatusSnapshot {
    /// Policy and provider version represented by this snapshot.
    pub config_version: EndpointConfigVersion,
    /// Complete, identifier-sorted set of configured endpoint statuses.
    pub endpoints: Vec<EndpointObservation>,
    /// Endpoints that carried at least one new result in this report batch.
    ///
    /// The gateway uses this set to advance observation timestamps only for
    /// endpoints actually observed since the previous accepted report. It
    /// validates every value against `endpoints` and the current policy.
    pub observed_endpoint_ids: Vec<String>,
    /// Active supervisor session authorized to report this snapshot.
    ///
    /// The endpoint reporter fills this field after the gateway accepts the
    /// `ConnectSupervisor` stream. Trackers leave it empty.
    pub supervisor_session_id: String,
    /// Monotonic sequence within one authenticated supervisor session.
    ///
    /// Each frozen snapshot reserves a sequence, including snapshots superseded
    /// by an inventory reset. Gaps are valid. A retry preserves its complete body
    /// and sequence so a lost response cannot advance observation timestamps.
    pub report_sequence: u64,
}

/// FIFO state machine that turns inventory and observations into snapshots.
#[derive(Debug)]
pub struct EndpointStatusTracker {
    config_version: Option<EndpointConfigVersion>,
    inventory_generation: Option<EndpointObservationGeneration>,
    current: watch::Sender<ObservationState>,
    endpoints: BTreeMap<String, EndpointResult>,
}

impl EndpointStatusTracker {
    /// Apply one FIFO command.
    ///
    /// Returns `true` when the command must publish a fresh snapshot. Repeated
    /// results still return `true` so the gateway can advance observation
    /// freshness. Observations for an obsolete inventory, supervisor authority,
    /// or unknown endpoint identifier are ignored. Reinstalling equal configuration values
    /// cannot make an in-flight exchange from an older installation current.
    pub fn apply(&mut self, command: EndpointStatusCommand) -> bool {
        match command {
            EndpointStatusCommand::Reset {
                config_version,
                endpoints,
                inventory_generation,
            } => {
                self.reset(config_version, endpoints);
                // A queued reset installs only its inventory identity. It
                // cannot restore authority invalidated by a session change.
                self.inventory_generation = Some(inventory_generation);
                true
            }
            EndpointStatusCommand::Observe {
                config_version,
                endpoint_id,
                result,
                inventory_generation,
                authority_generation,
            } => {
                if self.config_version.as_ref() != Some(&config_version)
                    || !self
                        .inventory_generation
                        .as_ref()
                        .is_some_and(|current| current.matches(&inventory_generation))
                    || !self
                        .current
                        .borrow()
                        .authority_generation
                        .matches(&authority_generation)
                {
                    // Stale evidence must not change results or freshness.
                    return false;
                }
                let Some(endpoint) = self.endpoints.get_mut(&endpoint_id) else {
                    return false;
                };
                // Repeated results are material observations: the gateway
                // advances endpoint freshness even when the classification is
                // unchanged.
                *endpoint = result;
                true
            }
        }
    }

    /// Return the complete current snapshot, or `None` before the first reset.
    #[must_use]
    pub fn snapshot(&self) -> Option<EndpointStatusSnapshot> {
        let config_version = self.config_version.clone()?;
        let endpoints = self
            .endpoints
            .iter()
            .map(|(endpoint_id, endpoint)| EndpointObservation {
                endpoint_id: endpoint_id.clone(),
                result: *endpoint,
            })
            .collect();
        Some(EndpointStatusSnapshot {
            config_version,
            endpoints,
            observed_endpoint_ids: Vec::new(),
            supervisor_session_id: String::new(),
            report_sequence: 0,
        })
    }

    /// Forget results learned by a previous authenticated supervisor session.
    ///
    /// A replacement session is a new observation authority. Retaining its
    /// predecessor's results would let a reconnect restore stale evidence
    /// immediately after the gateway resets the endpoint statuses.
    pub fn clear_observations(&mut self) -> bool {
        // Rotate even before the first reset is consumed: its sender may
        // already have issued handles. Inventory resets never replace this
        // authority, so pending resets cannot revive pre-replacement handles.
        self.current.send_modify(|current| {
            current.authority_generation = EndpointObservationGeneration::new();
        });
        let Some(_config_version) = self.config_version.as_ref() else {
            return false;
        };
        for endpoint in self.endpoints.values_mut() {
            *endpoint = EndpointResult::NoObservedExchange;
        }
        true
    }

    fn reset(
        &mut self,
        config_version: EndpointConfigVersion,
        inventory: Vec<EndpointInventoryEntry>,
    ) {
        let policy_changed = self
            .config_version
            .as_ref()
            .is_none_or(|current| current.policy_hash != config_version.policy_hash);
        let provider_changed = self.config_version.as_ref().is_some_and(|current| {
            current.provider_env_revision != config_version.provider_env_revision
        });
        let previous = std::mem::take(&mut self.endpoints);

        self.endpoints = inventory
            .into_iter()
            .map(|endpoint| {
                // A policy change invalidates every observation. A provider
                // revision invalidates only endpoints whose runtime behavior can
                // depend on provider-managed credentials.
                let preserve =
                    !policy_changed && (!provider_changed || !endpoint.uses_provider_credentials);
                let result = if preserve {
                    previous
                        .get(&endpoint.endpoint_id)
                        .copied()
                        .unwrap_or(EndpointResult::NoObservedExchange)
                } else {
                    EndpointResult::NoObservedExchange
                };
                (endpoint.endpoint_id, result)
            })
            .collect();
        self.config_version = Some(config_version);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_version(policy_hash: &str, provider_env_revision: u64) -> EndpointConfigVersion {
        EndpointConfigVersion {
            policy_hash: policy_hash.to_string(),
            provider_env_revision,
        }
    }

    fn inventory() -> Vec<EndpointInventoryEntry> {
        vec![
            EndpointInventoryEntry {
                endpoint_id: "endpoint:credentialed".to_string(),
                uses_provider_credentials: true,
            },
            EndpointInventoryEntry {
                endpoint_id: "endpoint:public".to_string(),
                uses_provider_credentials: false,
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
    fn endpoint_identity_is_stable_across_equivalent_endpoint_spelling() {
        let legacy = endpoint("MCP.EXAMPLE.COM", 443, Vec::new(), "");
        let modern = endpoint("mcp.example.com", 0, vec![443, 443], "/**");

        let identifier = endpoint_id(&legacy);
        assert_eq!(identifier, endpoint_id(&modern));
        assert_eq!(
            identifier,
            "endpoint:v1:82a2b0fc1e462408e15e5e9ad55b851e9e688cdf091da695ba177bb0403916af"
        );
    }

    #[test]
    fn endpoint_identity_normalizes_effective_port_set() {
        let unsorted = endpoint("mcp.example.com", 8443, vec![8443, 443, 443], "**");
        let sorted = endpoint("mcp.example.com", 0, vec![443, 8443], "/**");

        assert_eq!(
            endpoint_id(&unsorted),
            endpoint_id(&sorted),
            "the repeated ports field takes precedence and is a set"
        );
    }

    #[test]
    fn endpoint_identity_distinguishes_scoped_paths() {
        let root = endpoint("mcp.example.com", 443, Vec::new(), "/**");
        let scoped = endpoint("mcp.example.com", 443, Vec::new(), "/mcp");

        assert_ne!(endpoint_id(&root), endpoint_id(&scoped));
    }

    #[test]
    fn initial_status_contains_canonical_address_and_unobserved_result() {
        let configured = endpoint("MCP.EXAMPLE.COM", 1234, vec![8443, 443, 443], "**");
        let descriptor = initial_endpoint_status(&configured);
        assert_eq!(descriptor.host, "mcp.example.com");
        assert_eq!(descriptor.ports, vec![443, 8443]);
        assert_eq!(descriptor.path, "/**");
        assert_eq!(
            descriptor.last_result,
            crate::proto::EndpointResult::NoObservedExchange as i32,
        );
        assert!(descriptor.last_reported_at.is_empty());

        let reconstructed = endpoint(
            &descriptor.host,
            0,
            descriptor.ports.clone(),
            &descriptor.path,
        );
        assert_eq!(descriptor.endpoint_id, endpoint_id(&reconstructed));
        assert_eq!(descriptor, initial_endpoint_status(&reconstructed));
        assert_eq!(
            initial_endpoint_status(&endpoint("MCP.EXAMPLE.COM", 443, Vec::new(), "")),
            initial_endpoint_status(&endpoint("mcp.example.com", 0, vec![443], "/**")),
        );
    }

    #[test]
    fn initial_status_preserves_scoped_paths_without_inventing_ports() {
        let descriptor = initial_endpoint_status(&endpoint("MCP.EXAMPLE.COM", 0, vec![], "/mcp"));
        assert_eq!(descriptor.host, "mcp.example.com");
        assert!(descriptor.ports.is_empty());
        assert_eq!(descriptor.path, "/mcp");
        assert_ne!(
            descriptor.endpoint_id,
            endpoint_id(&endpoint("mcp.example.com", 443, vec![], "/mcp")),
        );
    }

    fn observe(
        tracker: &EndpointStatusTracker,
        config_version: EndpointConfigVersion,
        endpoint_id: &str,
        result: EndpointResult,
    ) -> EndpointStatusCommand {
        EndpointStatusCommand::Observe {
            inventory_generation: tracker
                .inventory_generation
                .clone()
                .expect("inventory installed"),
            authority_generation: tracker.current.borrow().authority_generation.clone(),
            config_version,
            endpoint_id: endpoint_id.to_string(),
            result,
        }
    }

    #[test]
    fn policy_change_resets_every_endpoint() {
        let mut tracker = endpoint_status_channel().1.tracker();
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: inventory(),
        });
        tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:credentialed",
            EndpointResult::HttpResponseReceived,
        ));
        tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:public",
            EndpointResult::HttpResponseReceived,
        ));

        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-b", 1),
            endpoints: inventory(),
        });

        let snapshot = tracker.snapshot().expect("reset creates a snapshot");
        assert!(
            snapshot
                .endpoints
                .iter()
                .all(|endpoint| endpoint.result == EndpointResult::NoObservedExchange)
        );
    }

    #[test]
    fn reset_rebuilds_inventory_and_preserves_matching_current_endpoints() {
        let mut tracker = endpoint_status_channel().1.tracker();
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: inventory(),
        });
        tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:public",
            EndpointResult::HttpResponseReceived,
        ));

        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: vec![
                EndpointInventoryEntry {
                    endpoint_id: "endpoint:new".to_string(),
                    uses_provider_credentials: false,
                },
                EndpointInventoryEntry {
                    endpoint_id: "endpoint:public".to_string(),
                    uses_provider_credentials: false,
                },
            ],
        });

        assert_eq!(
            tracker
                .snapshot()
                .expect("reset creates a snapshot")
                .endpoints,
            vec![
                EndpointObservation {
                    endpoint_id: "endpoint:new".to_string(),
                    result: EndpointResult::NoObservedExchange,
                },
                EndpointObservation {
                    endpoint_id: "endpoint:public".to_string(),
                    result: EndpointResult::HttpResponseReceived,
                },
            ]
        );
    }

    #[test]
    fn provider_change_preserves_only_uncredentialed_endpoints() {
        let mut tracker = endpoint_status_channel().1.tracker();
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: inventory(),
        });
        for endpoint_id in ["endpoint:credentialed", "endpoint:public"] {
            tracker.apply(observe(
                &tracker,
                config_version("policy-a", 1),
                endpoint_id,
                EndpointResult::HttpResponseReceived,
            ));
        }

        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 2),
            endpoints: inventory(),
        });

        let snapshot = tracker.snapshot().expect("reset creates a snapshot");
        assert_eq!(
            snapshot.endpoints,
            vec![
                EndpointObservation {
                    endpoint_id: "endpoint:credentialed".to_string(),
                    result: EndpointResult::NoObservedExchange,
                },
                EndpointObservation {
                    endpoint_id: "endpoint:public".to_string(),
                    result: EndpointResult::HttpResponseReceived,
                },
            ]
        );
    }

    #[test]
    fn stale_observation_cannot_update_new_configuration() {
        let mut tracker = endpoint_status_channel().1.tracker();
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: inventory(),
        });
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 2),
            endpoints: inventory(),
        });

        assert!(!tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:credentialed",
            EndpointResult::HttpResponseReceived,
        )));
        assert_eq!(
            tracker
                .snapshot()
                .expect("reset creates a snapshot")
                .endpoints[0]
                .result,
            EndpointResult::NoObservedExchange
        );
    }

    #[test]
    fn repeated_outcome_remains_a_reportable_observation() {
        let mut tracker = endpoint_status_channel().1.tracker();
        tracker.apply(EndpointStatusCommand::Reset {
            inventory_generation: EndpointObservationGeneration::new(),
            config_version: config_version("policy-a", 1),
            endpoints: inventory(),
        });
        let first = tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:public",
            EndpointResult::HttpResponseReceived,
        ));
        let second = tracker.apply(observe(
            &tracker,
            config_version("policy-a", 1),
            "endpoint:public",
            EndpointResult::HttpResponseReceived,
        ));

        assert!(first);
        assert!(second);
    }

    #[tokio::test]
    async fn handles_remain_stale_after_supervisor_replacement() {
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(config_version("policy-a", 1), inventory())
            .await
            .unwrap();
        assert!(tracker.apply(receiver.recv().await.unwrap()));
        let stale = sender.begin("endpoint:public".to_string()).unwrap();
        assert!(sender.try_observe(stale.clone(), EndpointResult::HttpResponseReceived));
        assert!(tracker.apply(receiver.recv().await.unwrap()));

        for _ in 0..2 {
            assert!(tracker.clear_observations());
            assert!(sender.try_observe(stale.clone(), EndpointResult::HttpResponseReceived));
            assert!(!tracker.apply(receiver.recv().await.unwrap()));
            assert!(
                tracker
                    .snapshot()
                    .unwrap()
                    .endpoints
                    .iter()
                    .all(|endpoint| { endpoint.result == EndpointResult::NoObservedExchange })
            );

            let fresh = sender.begin("endpoint:public".to_string()).unwrap();
            assert!(sender.try_observe(fresh, EndpointResult::PolicyDenied));
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            assert_eq!(
                tracker.snapshot().unwrap().endpoints[1].result,
                EndpointResult::PolicyDenied
            );
        }
    }

    #[tokio::test]
    async fn handles_remain_stale_when_inventory_values_recur() {
        // Exercise policy cycles, provider cycles, and same-value reinstallations.
        for intermediate in [
            config_version("policy-b", 1),
            config_version("policy-a", 2),
            config_version("policy-a", 1),
        ] {
            let (sender, mut receiver) = endpoint_status_channel();
            let mut tracker = receiver.tracker();
            let original = config_version("policy-a", 1);
            sender.reset(original.clone(), inventory()).await.unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            let stale = sender.begin("endpoint:public".to_string()).unwrap();

            sender.reset(intermediate, inventory()).await.unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            sender.reset(original, inventory()).await.unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));

            assert!(sender.try_observe(stale, EndpointResult::HttpResponseReceived));
            assert!(!tracker.apply(receiver.recv().await.unwrap()));
            assert!(
                tracker
                    .snapshot()
                    .unwrap()
                    .endpoints
                    .iter()
                    .all(|endpoint| { endpoint.result == EndpointResult::NoObservedExchange })
            );
            let fresh = sender.begin("endpoint:public".to_string()).unwrap();
            assert!(sender.try_observe(fresh, EndpointResult::PolicyDenied));
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            assert_eq!(
                tracker.snapshot().unwrap().endpoints[1].result,
                EndpointResult::PolicyDenied
            );
        }
    }

    #[tokio::test]
    async fn captured_context_rejects_mixed_policy_and_provider_selection() {
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(config_version("policy-a", 1), inventory())
            .await
            .unwrap();
        assert!(tracker.apply(receiver.recv().await.unwrap()));
        let context = sender.capture().unwrap();
        assert!(
            sender
                .begin_captured(&context, "endpoint:public".into(), "policy-b", Some(1))
                .is_none()
        );
        assert!(
            sender
                .begin_captured(&context, "endpoint:public".into(), "policy-a", Some(2))
                .is_none()
        );
        let current = sender
            .begin_captured(&context, "endpoint:public".into(), "policy-a", Some(1))
            .unwrap();
        assert!(sender.try_observe(current, EndpointResult::PolicyDenied));
        assert!(tracker.apply(receiver.recv().await.unwrap()));
        assert_eq!(
            tracker.snapshot().unwrap().endpoints[1].result,
            EndpointResult::PolicyDenied
        );
    }

    #[tokio::test]
    async fn captured_context_stays_retired_across_policy_provider_and_session_cycles() {
        for intermediate in [
            config_version("policy-b", 1),
            config_version("policy-a", 2),
            config_version("policy-a", 1),
        ] {
            let (sender, mut receiver) = endpoint_status_channel();
            let mut tracker = receiver.tracker();
            sender
                .reset(config_version("policy-a", 1), inventory())
                .await
                .unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            let stale = sender.capture().unwrap();
            sender.reset(intermediate, inventory()).await.unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            sender
                .reset(config_version("policy-a", 1), inventory())
                .await
                .unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            assert!(
                sender
                    .begin_captured(&stale, "endpoint:public".into(), "policy-a", Some(1))
                    .is_none()
            );
            let replaced = sender.capture().unwrap();
            assert!(tracker.clear_observations());
            assert!(
                sender
                    .begin_captured(&replaced, "endpoint:public".into(), "policy-a", Some(1))
                    .is_none()
            );
            let fresh = sender.capture().unwrap();
            let current = sender
                .begin_captured(&fresh, "endpoint:public".into(), "policy-a", Some(1))
                .unwrap();
            assert!(sender.try_observe(current, EndpointResult::PolicyDenied));
            assert!(tracker.apply(receiver.recv().await.unwrap()));
        }
    }

    #[tokio::test]
    async fn queued_inventory_cannot_restore_replaced_authority() {
        for already_installed in [false, true] {
            let (sender, mut receiver) = endpoint_status_channel();
            let mut tracker = receiver.tracker();
            if already_installed {
                sender
                    .reset(config_version("policy-a", 1), inventory())
                    .await
                    .unwrap();
                assert!(tracker.apply(receiver.recv().await.unwrap()));
            }
            sender
                .reset(config_version("policy-b", 1), inventory())
                .await
                .unwrap();
            let stale = sender.begin("endpoint:public".to_string()).unwrap();

            assert_eq!(tracker.clear_observations(), already_installed);
            let fresh = sender.begin("endpoint:public".to_string()).unwrap();
            assert!(tracker.apply(receiver.recv().await.unwrap()));
            assert!(sender.try_observe(stale, EndpointResult::HttpResponseReceived));
            assert!(!tracker.apply(receiver.recv().await.unwrap()));
            assert!(
                tracker
                    .snapshot()
                    .unwrap()
                    .endpoints
                    .iter()
                    .all(|endpoint| { endpoint.result == EndpointResult::NoObservedExchange })
            );
            assert!(sender.try_observe(fresh, EndpointResult::PolicyDenied));
            assert!(tracker.apply(receiver.recv().await.unwrap()));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_resets_publish_in_fifo_order() {
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut resets = Vec::new();
        for policy in ["policy-a", "policy-b"] {
            let sender = sender.clone();
            let barrier = barrier.clone();
            resets.push(tokio::spawn(async move {
                barrier.wait().await;
                sender
                    .reset(config_version(policy, 1), inventory())
                    .await
                    .unwrap();
            }));
        }
        for reset in resets {
            reset.await.unwrap();
        }
        for _ in 0..2 {
            assert!(tracker.apply(receiver.recv().await.unwrap()));
        }

        let fresh = sender.begin("endpoint:public".to_string()).unwrap();
        assert_eq!(
            tracker.snapshot().unwrap().config_version,
            fresh.config_version
        );
        assert!(sender.try_observe(fresh, EndpointResult::HttpResponseReceived));
        assert!(tracker.apply(receiver.recv().await.unwrap()));
    }

    #[tokio::test]
    async fn full_channel_drops_observations_without_publishing_a_cancelled_reset() {
        let (sender, mut receiver) = endpoint_status_channel();
        let mut tracker = receiver.tracker();
        sender
            .reset(config_version("policy-a", 1), inventory())
            .await
            .unwrap();
        assert!(tracker.apply(receiver.recv().await.unwrap()));
        let observation = sender.begin("endpoint:public".to_string()).unwrap();
        for _ in 0..ENDPOINT_STATUS_CHANNEL_CAPACITY {
            assert!(sender.try_observe(observation.clone(), EndpointResult::HttpResponseReceived));
        }
        assert!(!sender.try_observe(observation.clone(), EndpointResult::HttpResponseReceived));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                sender.reset(config_version("policy-b", 1), inventory()),
            )
            .await
            .is_err()
        );
        let current = sender.begin("endpoint:public".to_string()).unwrap();
        assert!(
            current
                .inventory_generation
                .matches(&observation.inventory_generation)
        );
        assert!(tracker.apply(receiver.recv().await.unwrap()));
        drop(receiver);
        assert!(!sender.try_observe(current, EndpointResult::HttpResponseReceived));
        assert!(
            sender
                .reset(config_version("policy-b", 1), inventory())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn sender_captures_configuration_without_sensitive_payload_fields() {
        let (sender, mut receiver) = endpoint_status_channel();
        assert!(sender.begin("endpoint:public".to_string()).is_none());
        sender
            .reset(config_version("policy-a", 1), inventory())
            .await
            .expect("receiver remains active");
        let observation = sender
            .begin("endpoint:public".to_string())
            .expect("reset publishes the config_version");
        assert!(!sender.try_observe(observation.clone(), EndpointResult::NoObservedExchange));
        assert!(sender.try_observe(observation, EndpointResult::HttpResponseReceived));

        assert!(matches!(
            receiver.recv().await,
            Some(EndpointStatusCommand::Reset { .. })
        ));
        assert!(matches!(
            receiver.recv().await,
            Some(EndpointStatusCommand::Observe {
                endpoint_id,
                result: EndpointResult::HttpResponseReceived,
                ..
            }) if endpoint_id == "endpoint:public"
        ));
    }
}
