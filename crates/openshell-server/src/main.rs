// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` Gateway binary entrypoint.

use miette::Result;

#[tokio::main]
async fn main() -> Result<()> {
    openshell_server::cli::run_cli_with_compute_drivers(
        openshell_server::install_default_compute_drivers(),
    )
    .await
}
