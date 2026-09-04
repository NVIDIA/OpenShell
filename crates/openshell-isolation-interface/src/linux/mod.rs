// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Audited Linux primitives used by the capability-free sandbox.
//!
//! This module intentionally contains mechanisms, not sandbox orchestration.
//! The in-workload sandbox owns lifecycle, policy, and failure handling.

pub mod child_seccomp;
pub mod landlock;
pub mod proc_fd;
pub mod seccomp_notify;
pub mod socket_registry;
pub mod task_memory;
