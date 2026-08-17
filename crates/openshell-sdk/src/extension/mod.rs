// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! APIs for implementing operator-run `OpenShell` extension services.
//!
//! Enable the `extension` Cargo feature to verify gateway-minted extension
//! credentials and authorize callers without depending on gateway internals.

mod verification;

pub use verification::{
    AuthenticatedCaller, ExtensionCallerKind, GatewayJwtAuthenticator, VerificationError,
};
