// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resource-metadata markers for the destination-trust generation of a sandbox
//! startup artifact, used by the local container drivers.

pub use openshell_driver_sdk::network_trust::*;

/// Protected resource metadata key recording the destination-trust generation
/// used to build a sandbox startup artifact.
///
/// Kubernetes stores this value in an annotation because a `sha256:<hex>`
/// digest exceeds the 63-character label-value limit. Local container drivers
/// may store the same protected key in a container label.
pub const NETWORK_SUPERVISOR_TRUST_GENERATION_KEY: &str = "openshell.ai/additional-ca-generation";

/// Explicit generation marker for an omitted destination-trust configuration.
///
/// An explicit value, rather than an absent marker, lets a stopped sandbox
/// distinguish a removal from a resource created by an older gateway.
pub const NETWORK_SUPERVISOR_TRUST_GENERATION_NONE: &str = "none";
