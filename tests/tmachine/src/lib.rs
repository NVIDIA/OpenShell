// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Isolated QEMU test machines provisioned with Ansible.
//!
//! The `tmachine` binary drives one-shot `setup`, `install`, and `test`
//! commands. Callers that need to act on a running machine use [`Session`].

pub mod ansible;
pub mod config;
mod qemu;

pub use qemu::{Session, install, setup, test};
