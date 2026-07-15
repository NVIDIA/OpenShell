// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Authentication and authorization for the gateway server.
//!
//! - `oidc`: JWT validation against OIDC providers (Keycloak, Entra ID, Okta)
//! - `authz`: Role-based and scope-based access control
//! - `identity`: Provider-agnostic identity representation
//! - `http`: HTTP endpoints for auth discovery and token exchange

pub mod authenticator;
pub mod authz;
pub mod guard;
mod http;
pub mod identity;
pub mod k8s_sa;
pub mod method_authz;
pub mod oidc;
pub mod peer;
pub mod principal;
pub mod sandbox_jwt;
pub mod sandbox_methods;

pub use http::router;
