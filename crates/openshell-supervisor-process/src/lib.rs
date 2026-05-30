// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process component of the `OpenShell` supervisor.
//!
//! Owns the entrypoint process spawn, SSH server, supervisor session, network
//! namespace, bypass monitor, child environment construction, skills install,
//! and log push. Populated by follow-up commits as modules migrate out of
//! `openshell-sandbox`.

pub mod child_env;
pub mod skills;
