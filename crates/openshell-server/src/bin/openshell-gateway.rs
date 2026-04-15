// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::Result;

#[tokio::main]
async fn main() -> Result<()> {
    openshell_server::cli::run_cli("openshell-gateway").await
}
