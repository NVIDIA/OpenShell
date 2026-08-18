// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! APIs for building `OpenShell` extension services.
//!
//! This feature is the home for shared extension interfaces, verification, and
//! observability. It currently provides gateway-minted credential verification.

mod auth;

pub use auth::{
    AuthenticatedCaller, ExtensionCallerKind, GatewayJwtAuthenticator, VerificationError,
};
