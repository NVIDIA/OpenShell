// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Runs `OpenShell` test plans: expands a plan into jobs, provisions each
//! environment through its backend, runs the selected suites inside it, and
//! reports the results.

pub mod bundle;
pub mod catalog;
pub mod environments;
pub mod execute;
pub mod jobs;
pub mod matrix;
pub mod plan;
pub mod report;
pub mod waivers;
