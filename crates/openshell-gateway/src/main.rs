// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() -> miette::Result<()> {
    openshell_server::cli::run_cli_with_compute_drivers(
        openshell_gateway::install_default_compute_drivers(),
    )
    .await
}
