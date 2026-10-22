// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs a test family in one tmachine environment: builds the family's tests
//! for the guest, boots the environment with OpenShell installed, runs the
//! tests inside it, and checks the results.

pub mod bundle;
pub mod execute;
pub mod report;
