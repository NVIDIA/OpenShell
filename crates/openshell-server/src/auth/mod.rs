// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication and authorization for the gateway server.
//!
//! - `oidc`: JWT validation against OIDC providers (Keycloak, Entra ID, Okta)
//! - `authz`: Role-based and scope-based access control
//! - `identity`: Provider-agnostic identity representation
//! - `http`: HTTP endpoints for auth discovery and token exchange

pub mod authz;
mod http;
pub mod identity;
pub mod oidc;

pub use http::router;
pub use identity::{Identity, IdentityProvider};
pub use oidc::JwksCache;
