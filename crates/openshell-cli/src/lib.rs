// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` CLI library.
//!
//! This crate provides the CLI implementation for `OpenShell`.

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod auth;
pub mod bootstrap;
pub mod completers;
pub mod edge_tunnel;
pub mod oidc_auth;
pub(crate) mod policy_update;
pub mod run;
pub mod ssh;
pub mod tls;
