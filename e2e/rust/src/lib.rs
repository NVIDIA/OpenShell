// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test harness for `OpenShell` CLI end-to-end tests.
//!
//! Provides utilities for:
//! - Resolving and invoking the `openshell` CLI binary
//! - Managing sandbox lifecycle with automatic cleanup
//! - Parsing CLI output (ANSI stripping, field extraction)
//! - TCP port utilities (wait for port, find free port)

pub mod harness;
