// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

fn main() {
    // The container runtime invokes the CNI plugin with no positional args
    // (config on stdin, CNI_COMMAND in env). The `node-ready` subcommand is only
    // reached when the installer DaemonSet calls the binary explicitly.
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("node-ready") => openshell_cni::node_ready(&args[2..]),
        Some("daemonset-active") => openshell_cni::daemonset_active(),
        // Internal: re-exec'd inside a pod netns to probe for IPv6 (see
        // netns_requires_ipv6_enforcement). Not part of the public CLI surface.
        Some("__netns-probe-ipv6") => openshell_cni::netns_probe_ipv6(),
        _ => openshell_cni::run(),
    };
    if let Err(error) = result {
        eprintln!("{error:?}");
        std::process::exit(1);
    }
}
