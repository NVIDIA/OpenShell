// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // The container runtime invokes the CNI plugin with no positional args
    // (config on stdin, CNI_COMMAND in env). The `node-ready` subcommand is only
    // reached when the installer DaemonSet calls the binary explicitly.
    let args: Vec<String> = std::env::args().collect();
    let result = if args.get(1).map(String::as_str) == Some("node-ready") {
        openshell_cni::node_ready(&args[2..])
    } else {
        openshell_cni::run()
    };
    if let Err(error) = result {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}
