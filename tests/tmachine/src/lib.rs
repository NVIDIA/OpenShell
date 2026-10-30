// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Isolated QEMU test machines provisioned with Ansible.
//!
//! The `tmachine` binary drives one-shot `setup`, `install`, and `test`
//! commands. Callers that need to act on a running machine use [`Session`].
//! A binary that starts machines should run its work in [`until_signal`], so
//! a `SIGTERM` does not leave QEMU running.

pub mod ansible;
pub mod config;
mod qemu;

pub use qemu::{Session, install, setup, ssh_port, test, until_signal};
