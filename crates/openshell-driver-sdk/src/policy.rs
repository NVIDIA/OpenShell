// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox workload identity limits that compute drivers validate against.

/// Minimum accepted UID/GID for sandbox workload identity.
///
/// Linux reserves only identity `0` for root. Non-root system identities are
/// valid workload identities when selected explicitly by the operator.
pub const MIN_SANDBOX_UID: u32 = 1;

/// Maximum accepted UID/GID for sandbox workload identity.
///
/// `u32::MAX` represents an invalid or unchanged identity in Linux APIs and
/// POSIX ACLs, so the largest usable workload identity is one less.
pub const MAX_SANDBOX_UID: u32 = u32::MAX - 1;
