// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Continuity suite: state that must survive a disruption of the gateway or
//! of the environment it runs in, such as a restart or an upgrade.
//!
//! Each module is one scenario with two tests, `seed` and `verify`. The
//! `openshell-test-runner` runs every `seed`, applies the disruption named by
//! `--disruption`, waits for the gateway, and then runs every `verify`. A
//! scenario never learns which disruption ran between its two tests.
//!
//! The tests share state through names derived from [`id`], which the runner
//! sets once per run, so nothing is written to disk. `seed` must not leave
//! cleanup behind that deletes what `verify` reads: it creates resources
//! through the CLI, which testkit doesn't track, and `verify` adopts them so
//! its own cleanup removes them.

mod sandbox_workspace;
mod scenario;

pub use scenario::id;
