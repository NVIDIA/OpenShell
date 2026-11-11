// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell-conformance`: the conformance suite as one program, to run
//! against a gateway without cargo or nextest.
//!
//! The tests are registered by `#[testkit::test]` in this crate's library;
//! see `testkit::program` for the commands.

use std::process::ExitCode;

// A dependency that is never named is not linked, and its tests would be
// missing.
use conformance as _;

fn main() -> ExitCode {
    testkit::main()
}
