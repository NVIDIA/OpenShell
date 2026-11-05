// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() -> miette::Result<()> {
    // Must run before anything is spawned so every sandbox process joins the job.
    if let Err(error) = openshell_gateway::process_lifetime::kill_children_on_exit() {
        eprintln!(
            "warning: could not tie sandbox processes to the gateway lifetime; they will outlive it: {error}"
        );
    }
    openshell_server::cli::run_cli_with_compute_drivers(
        openshell_gateway::install_default_compute_drivers(),
    )
    .await
}
