// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Workspace conformance stories.
//!
//! Preconditions: a gateway that lets the test identity create and delete
//! workspaces and sandbox templates. Targets that restrict workspace creation,
//! such as Kubernetes operator-workspace mode, are not covered. Stories use
//! sandbox templates as the workspace-scoped resource because they need no
//! provider profile, credential or image from the target.
//!
//! Side effects: each story creates a workspace and templates named from the
//! run id, and removes them even when it fails.
//!
//! Known limitation: `workspace get` has no structured output, so stories check
//! its exit status and read workspace state from `workspace list --output json`.

mod crud;
mod helpers;
mod resource_scoping;
mod terminating;
