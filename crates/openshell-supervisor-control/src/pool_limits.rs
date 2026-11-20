// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Size limits of a shared supervisor pool.
//!
//! The gateway never places more than [`PoolLimits::max_instances_per_member`]
//! sandbox instances on one member, and a member refuses snapshots beyond the
//! same bound, so a sandbox is never created that its member could not
//! accept. Across the pool, the gateway runs at most
//! [`PoolLimits::max_pool_instances`] instances: its live replicas times the
//! members each serves times each member's cap, never past
//! [`MAX_POOL_INSTANCES_CEILING`]. Buffers sized by these limits follow the
//! configured cap, not the largest one allowed.

use crate::registration::MAX_LAUNCH_MATERIAL_BYTES;

/// Sandbox instances one pool member runs unless the gateway configures
/// another cap.
pub const DEFAULT_MAX_INSTANCES_PER_MEMBER: usize = 128;
/// Largest per-member cap a gateway and a member may configure.
pub const MAX_INSTANCES_PER_MEMBER: usize = 1024;
/// Pool members one gateway replica is sized to serve unless configured.
pub const DEFAULT_MAX_MEMBERS_PER_GATEWAY: usize = 32;
/// Most sandbox instances a pool runs, whatever its configuration.
pub const MAX_POOL_INSTANCES_CEILING: usize = 131_072;

/// Framing allowance per assignment in a snapshot, beyond its launch material.
const ASSIGNMENT_FRAMING_BYTES: usize = 1024;
/// Allowance per instance in a status report; one is a few hundred bytes.
const REPORTED_INSTANCE_BYTES: usize = 1024;
/// Smallest bound on a host message.
const MIN_HOST_MESSAGE_BYTES: usize = 1024 * 1024;
/// Allowance per entry of the pool-wide route directory every snapshot
/// carries: a route handle of up to 64 bytes, an `IP:port`, and framing.
const ROUTE_DIRECTORY_ENTRY_BYTES: usize = 128;
/// Fewest instances a status report may describe, so a member with a small
/// cap can still report instances it is removing or keeping.
const MIN_REPORTED_INSTANCES: usize = 64;

/// A pool limit outside its allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PoolLimitsError {
    #[error("max_instances_per_member must be between 1 and 1024")]
    InstancesPerMember,
    #[error("max_members_per_gateway must be at least 1")]
    MembersPerGateway,
}

/// Validated size limits of a supervisor pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    max_instances_per_member: usize,
    max_members_per_gateway: usize,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_instances_per_member: DEFAULT_MAX_INSTANCES_PER_MEMBER,
            max_members_per_gateway: DEFAULT_MAX_MEMBERS_PER_GATEWAY,
        }
    }
}

impl PoolLimits {
    /// # Errors
    ///
    /// Either limit is outside its range.
    pub fn new(
        max_instances_per_member: usize,
        max_members_per_gateway: usize,
    ) -> Result<Self, PoolLimitsError> {
        if !(1..=MAX_INSTANCES_PER_MEMBER).contains(&max_instances_per_member) {
            return Err(PoolLimitsError::InstancesPerMember);
        }
        if max_members_per_gateway == 0 {
            return Err(PoolLimitsError::MembersPerGateway);
        }
        Ok(Self {
            max_instances_per_member,
            max_members_per_gateway,
        })
    }

    /// Most sandbox instances one member runs.
    #[must_use]
    pub fn max_instances_per_member(self) -> usize {
        self.max_instances_per_member
    }

    /// Most sandbox instances the pool runs while `gateway_replicas` live
    /// replicas serve it; a gateway always counts itself.
    #[must_use]
    pub fn max_pool_instances(self, gateway_replicas: usize) -> usize {
        gateway_replicas
            .max(1)
            .saturating_mul(self.max_members_per_gateway)
            .saturating_mul(self.max_instances_per_member)
            .min(MAX_POOL_INSTANCES_CEILING)
    }

    /// Most instances one member's status report may describe: every
    /// assignment plus instances still being removed.
    #[must_use]
    pub fn max_reported_instances(self) -> usize {
        (4 * self.max_instances_per_member).max(MIN_REPORTED_INSTANCES)
    }

    /// Largest gateway message a member decodes: a full snapshot of its cap
    /// of assignments at their largest, plus the route directory of the
    /// largest pool.
    #[must_use]
    pub fn max_gateway_message_bytes(self) -> usize {
        self.max_instances_per_member * (MAX_LAUNCH_MATERIAL_BYTES + ASSIGNMENT_FRAMING_BYTES)
            + MAX_POOL_INSTANCES_CEILING * ROUTE_DIRECTORY_ENTRY_BYTES
    }

    /// Largest member message: a status report of every instance it may
    /// describe.
    #[must_use]
    pub fn max_host_message_bytes(self) -> usize {
        (self.max_reported_instances() * REPORTED_INSTANCE_BYTES).max(MIN_HOST_MESSAGE_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_bounded() {
        assert_eq!(PoolLimits::new(128, 32), Ok(PoolLimits::default()));
        assert!(PoolLimits::new(1, 1).is_ok());
        assert!(PoolLimits::new(1024, 10_000).is_ok());
        for instances in [0, 1025] {
            assert_eq!(
                PoolLimits::new(instances, 32),
                Err(PoolLimitsError::InstancesPerMember)
            );
        }
        assert_eq!(
            PoolLimits::new(128, 0),
            Err(PoolLimitsError::MembersPerGateway)
        );
    }

    #[test]
    fn the_pool_cap_follows_replicas_up_to_the_ceiling() {
        let limits = PoolLimits::default();
        assert_eq!(limits.max_pool_instances(0), 32 * 128);
        assert_eq!(limits.max_pool_instances(25), 102_400);
        assert_eq!(limits.max_pool_instances(1000), MAX_POOL_INSTANCES_CEILING);
    }

    #[test]
    fn buffers_follow_the_configured_cap_above_a_floor() {
        let tiny = PoolLimits::new(1, 1).unwrap();
        let largest = PoolLimits::new(1024, 1).unwrap();
        assert_eq!(
            PoolLimits::default().max_gateway_message_bytes(),
            128 * (MAX_LAUNCH_MATERIAL_BYTES + ASSIGNMENT_FRAMING_BYTES)
                + MAX_POOL_INSTANCES_CEILING * ROUTE_DIRECTORY_ENTRY_BYTES
        );
        assert_eq!(tiny.max_host_message_bytes(), MIN_HOST_MESSAGE_BYTES);
        assert_eq!(largest.max_host_message_bytes(), 4 * 1024 * 1024);
    }

    #[test]
    fn a_small_cap_decodes_the_route_directory_of_the_largest_pool() {
        use crate::proto::{AssignmentSnapshot, RouteOwner};
        use prost::Message as _;

        let route_directory = (0..MAX_POOL_INSTANCES_CEILING)
            .map(|index| RouteOwner {
                route: format!("rt-{index:061}"),
                runtime_address: "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535".to_string(),
            })
            .collect();
        let snapshot = AssignmentSnapshot {
            route_directory,
            ..Default::default()
        };
        let limits = PoolLimits::new(1, 1).unwrap();
        let own_assignments = MAX_LAUNCH_MATERIAL_BYTES + ASSIGNMENT_FRAMING_BYTES;
        assert!(snapshot.encoded_len() <= limits.max_gateway_message_bytes() - own_assignments);
    }
}
