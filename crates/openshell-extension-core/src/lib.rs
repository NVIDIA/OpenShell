// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-neutral primitives shared by `OpenShell` extension mechanisms.
//!
//! Subsystem-specific protobuf clients and orchestration do not belong here.

mod auth;
mod identity;
mod jwt;
mod transport;

pub use auth::{BearerTokenInterceptor, BearerTokenSlot, TokenSlotError};
pub use identity::{ExtensionAudience, ExtensionIdentity, ExtensionKind, IdentityError};
pub use jwt::{ExtensionCallerKind, ExtensionJwtClaims, MAX_EXTENSION_TOKEN_TTL};
pub use transport::{ExtensionChannelConfig, TransportError, connect_channel};
