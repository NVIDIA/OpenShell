// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: sandbox behavior that every compute driver must
//! provide. Each module is one suite.
//!
//! `cargo test` and nextest run the tests as this library's unit tests.
//! `#[testkit::test]` also registers them, so the `openshell-conformance`
//! program in `src/main.rs` runs them by linking this library.

mod attach;
mod cli;
mod credential_gating;
mod exec_cli;
mod file_transfer;
mod filesystem_policy;
mod image;
mod labels;
mod lifecycle;
mod persistent_workspace;
mod policy_advisor;
mod process;
mod settings;
mod smoke;
mod ssh;
mod templates;
