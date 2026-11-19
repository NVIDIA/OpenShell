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

use std::ops::RangeInclusive;

use crate::registration::MAX_LAUNCH_MATERIAL_BYTES;

/// Sandbox instances one pool member runs unless the gateway configures
/// another cap.
pub const DEFAULT_MAX_INSTANCES_PER_MEMBER: usize = 128;
/// Per-member caps a gateway and a member may configure.
pub const MAX_INSTANCES_PER_MEMBER_RANGE: RangeInclusive<usize> = 16..=1024;
/// Pool members one gateway replica is sized to serve unless configured.
pub const DEFAULT_MAX_MEMBERS_PER_GATEWAY: usize = 32;
/// Members per gateway replica a gateway may configure.
pub const MAX_MEMBERS_PER_GATEWAY_RANGE: RangeInclusive<usize> = 1..=64;
/// Most sandbox instances a pool runs, whatever its configuration.
pub const MAX_POOL_INSTANCES_CEILING: usize = 131_072;

/// Framing allowance per assignment in a snapshot, beyond its launch material.
const ASSIGNMENT_FRAMING_BYTES: usize = 1024;
/// Allowance per instance in a status report; one is a few hundred bytes.
const REPORTED_INSTANCE_BYTES: usize = 1024;
/// Smallest bound on a host message.
const MIN_HOST_MESSAGE_BYTES: usize = 1024 * 1024;

/// A pool limit outside its allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PoolLimitsError {
    #[error("max_instances_per_member must be between 16 and 1024")]
    InstancesPerMember,
    #[error("max_members_per_gateway must be between 1 and 64")]
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
        if !MAX_INSTANCES_PER_MEMBER_RANGE.contains(&max_instances_per_member) {
            return Err(PoolLimitsError::InstancesPerMember);
        }
        if !MAX_MEMBERS_PER_GATEWAY_RANGE.contains(&max_members_per_gateway) {
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

    /// Members one gateway replica is sized to serve.
    #[must_use]
    pub fn max_members_per_gateway(self) -> usize {
        self.max_members_per_gateway
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
        4 * self.max_instances_per_member
    }

    /// Largest gateway message a member decodes: a full snapshot of its cap
    /// of assignments at their largest, plus framing.
    #[must_use]
    pub fn max_gateway_message_bytes(self) -> usize {
        self.max_instances_per_member * (MAX_LAUNCH_MATERIAL_BYTES + ASSIGNMENT_FRAMING_BYTES)
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
        assert_eq!(
            PoolLimits::default(),
            PoolLimits::new(128, 32).expect("defaults are valid")
        );
        for (instances, members) in [(16, 1), (1024, 64), (128, 32)] {
            assert!(PoolLimits::new(instances, members).is_ok());
        }
        for instances in [0, 15, 1025, 4096] {
            assert_eq!(
                PoolLimits::new(instances, 32),
                Err(PoolLimitsError::InstancesPerMember)
            );
        }
        for members in [0, 65, 128] {
            assert_eq!(
                PoolLimits::new(128, members),
                Err(PoolLimitsError::MembersPerGateway)
            );
        }
    }

    #[test]
    fn the_pool_cap_follows_replicas_up_to_the_ceiling() {
        let limits = PoolLimits::default();
        assert_eq!(limits.max_pool_instances(0), 32 * 128);
        assert_eq!(limits.max_pool_instances(1), 32 * 128);
        assert_eq!(limits.max_pool_instances(25), 102_400);
        assert_eq!(limits.max_pool_instances(32), MAX_POOL_INSTANCES_CEILING);
        assert_eq!(limits.max_pool_instances(1000), MAX_POOL_INSTANCES_CEILING);
        let largest = PoolLimits::new(1024, 64).unwrap();
        assert_eq!(
            largest.max_pool_instances(usize::MAX),
            MAX_POOL_INSTANCES_CEILING
        );
    }

    #[test]
    fn buffers_follow_the_configured_cap() {
        let small = PoolLimits::new(16, 1).unwrap();
        let default = PoolLimits::default();
        let largest = PoolLimits::new(1024, 64).unwrap();
        assert_eq!(
            default.max_gateway_message_bytes(),
            128 * (MAX_LAUNCH_MATERIAL_BYTES + ASSIGNMENT_FRAMING_BYTES)
        );
        assert!(small.max_gateway_message_bytes() < default.max_gateway_message_bytes());
        assert!(default.max_gateway_message_bytes() < largest.max_gateway_message_bytes());
        assert_eq!(small.max_host_message_bytes(), MIN_HOST_MESSAGE_BYTES);
        assert_eq!(largest.max_host_message_bytes(), 4 * 1024 * 1024);
    }
}
