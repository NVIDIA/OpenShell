// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Isolated QEMU test machines provisioned with Ansible.
//!
//! The `tmachine` binary drives one-shot `setup`, `install`, and `test`
//! commands. Callers that need to act on a running machine use [`Session`].
//! A binary that starts machines should call [`cleanup_on_signals`] once, so a
//! `SIGTERM` does not leave QEMU running.
//!
//! The session API is by Evan Lezar (NVIDIA/OpenShell#4629).

pub mod ansible;
pub mod config;
mod qemu;

pub use qemu::{DEFAULT_SSH_PORT, Session, cleanup_on_signals, install, setup, ssh_port, test};
