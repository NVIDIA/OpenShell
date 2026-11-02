// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Conformance suite: sandbox behavior that every compute driver must
//! provide. Each module is one suite.
//!
//! `cargo test` and nextest run the tests as this library's unit tests.
//! `#[testkit::test]` also registers them, so a test program runs them by
//! linking this crate.

mod cli;
mod file_transfer;
mod lifecycle;
mod persistent_workspace;
mod policy_advisor;
mod smoke;
