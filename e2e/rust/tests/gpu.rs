// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-gpu")]

#[path = "gpu/device_selection.rs"]
mod device_selection;
#[path = "gpu/workloads.rs"]
mod workloads;
