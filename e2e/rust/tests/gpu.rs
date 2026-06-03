// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-gpu")]

// GPU-consuming e2e tests use #[serial(gpu)] because common single-GPU hosts
// cannot reliably provision multiple GPU sandboxes at the same time.

#[path = "gpu/device_selection.rs"]
mod device_selection;
#[path = "gpu/workloads.rs"]
mod workloads;
