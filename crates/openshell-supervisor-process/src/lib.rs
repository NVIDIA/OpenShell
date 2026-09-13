// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Access-plane component of the `OpenShell` supervisor.
//!
//! Owns SSH access, retained canonical-process I/O, gateway supervisor
//! sessions, skills, and log forwarding. Workload spawning and in-sandbox
//! enforcement live exclusively in `openshell-sandbox`.

pub mod debug_rpc;
pub mod delegated;
pub mod log_push;
pub mod main_session;
pub mod skills;
pub mod ssh;
pub mod supervisor_session;

mod unix_socket;
