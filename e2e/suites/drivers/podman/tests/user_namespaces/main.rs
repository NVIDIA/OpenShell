// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Podman profiles run serially against the tmachine guest's shared gateway.

mod auto;
mod default;
mod gateway;
mod helpers;
mod keep_id;
mod private;
#[path = "../support/mod.rs"]
mod support;
