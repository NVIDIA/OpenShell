// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process component of the `OpenShell` supervisor.
//!
//! Owns the entrypoint process spawn, SSH server, supervisor session, network
//! namespace, bypass monitor, child environment construction, skills install,
//! and log push. Populated by follow-up commits as modules migrate out of
//! `openshell-sandbox`.

pub mod child_env;
pub mod debug_rpc;
pub mod log_push;
pub mod managed_children;
pub mod process;
pub mod run;
pub mod sandbox;
pub mod skills;
pub mod ssh;
pub mod supervisor_session;

#[cfg(target_os = "linux")]
pub mod bypass_monitor;
#[cfg(target_os = "linux")]
pub mod netns;
