// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox template conformance stories.
//!
//! Preconditions: a gateway that lets the test identity create and delete
//! sandbox templates and sandboxes, and a target that supplies the default
//! sandbox image.
//!
//! Side effects: each story creates templates and sandboxes named from the run
//! id and removes them even when it fails.
//!
//! Known limitation: the CLI exposes no structured error, so rejections are
//! checked by exit status and by the resulting state, not by message.

mod duplicate_name;
mod from_template;
mod get_after_delete;
mod helpers;
mod missing_template;
mod round_trip;
