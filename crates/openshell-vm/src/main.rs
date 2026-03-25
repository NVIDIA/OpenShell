// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone openshell-vm binary.
//!
//! Boots a libkrun microVM running the OpenShell control plane (k3s +
//! openshell-server). By default it uses the pre-built rootfs at
//! `~/.local/share/openshell/openshell-vm/rootfs`.
//!
//! # Codesigning (macOS)
//!
//! This binary must be codesigned with the `com.apple.security.hypervisor`
//! entitlement. See `entitlements.plist` in this crate.
//!
//! ```sh
//! codesign --entitlements crates/openshell-vm/entitlements.plist --force -s - target/debug/openshell-vm
//! ```

use std::io::IsTerminal;
use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueHint};

/// Boot the OpenShell gateway microVM.
///
/// Starts a libkrun microVM running a k3s Kubernetes cluster with the
/// OpenShell control plane. Use `--exec` to run a custom process instead.
#[derive(Parser)]
#[command(name = "openshell-vm", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<GatewayCommand>,

    /// Path to the rootfs directory (aarch64 Linux).
    /// Defaults to `~/.local/share/openshell/openshell-vm/rootfs`.
    #[arg(long, value_hint = ValueHint::DirPath)]
    rootfs: Option<PathBuf>,

    /// Executable path inside the VM. When set, runs this instead of
    /// the default k3s server.
    #[arg(long)]
    exec: Option<String>,

    /// Arguments to the executable (requires `--exec`).
    #[arg(long, num_args = 1..)]
    args: Vec<String>,

    /// Environment variables in `KEY=VALUE` form (requires `--exec`).
    #[arg(long, num_args = 1..)]
    env: Vec<String>,

    /// Working directory inside the VM.
    #[arg(long, default_value = "/")]
    workdir: String,

    /// Port mappings (`host_port:guest_port`).
    #[arg(long, short, num_args = 1..)]
    port: Vec<String>,

    /// Number of virtual CPUs (default: 4 for openshell-vm, 2 for --exec).
    #[arg(long)]
    vcpus: Option<u8>,

    /// RAM in MiB (default: 8192 for openshell-vm, 2048 for --exec).
    #[arg(long)]
    mem: Option<u32>,

    /// libkrun log level (0=Off .. 5=Trace).
    #[arg(long, default_value_t = 1)]
    krun_log_level: u32,

    /// Networking backend: "gvproxy" (default), "tsi", or "none".
    #[arg(long, default_value = "gvproxy")]
    net: String,

    /// Wipe all runtime state (containerd, kubelet, k3s) before booting.
    /// Use this to recover from a corrupted state after a crash or
    /// unclean shutdown.
    #[arg(long)]
    reset: bool,
}

#[derive(Subcommand)]
enum GatewayCommand {
    /// Execute a command inside a running openshell-vm VM.
    Exec {
        /// Working directory inside the VM.
        #[arg(long)]
        workdir: Option<String>,

        /// Environment variables in `KEY=VALUE` form.
        #[arg(long, num_args = 1..)]
        env: Vec<String>,

        /// Command and arguments to run inside the VM.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
}

fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    };

    if code != 0 {
        std::process::exit(code);
    }
}

fn run(cli: Cli) -> Result<i32, Box<dyn std::error::Error>> {
    if let Some(GatewayCommand::Exec {
        workdir,
        env,
        mut command,
    }) = cli.command
    {
        let effective_tty = std::io::stdin().is_terminal();
        if command.is_empty() {
            if effective_tty {
                command.push("sh".to_string());
            } else {
                return Err("openshell-vm exec requires a command when stdin is not a TTY".into());
            }
        }
        return Ok(openshell_vm::exec_running_vm(
            openshell_vm::VmExecOptions {
                rootfs: cli.rootfs,
                command,
                workdir,
                env,
                tty: effective_tty,
            },
        )?);
    }

    let net_backend = match cli.net.as_str() {
        "tsi" => openshell_vm::NetBackend::Tsi,
        "none" => openshell_vm::NetBackend::None,
        "gvproxy" => openshell_vm::NetBackend::Gvproxy {
            binary: openshell_vm::default_runtime_gvproxy_path(),
        },
        other => {
            return Err(
                format!("unknown --net backend: {other} (expected: gvproxy, tsi, none)").into(),
            );
        }
    };

    let rootfs = match cli.rootfs {
        Some(p) => p,
        None => openshell_bootstrap::paths::default_rootfs_dir()?,
    };

    let mut config = if let Some(exec_path) = cli.exec {
        openshell_vm::VmConfig {
            rootfs,
            vcpus: cli.vcpus.unwrap_or(2),
            mem_mib: cli.mem.unwrap_or(2048),
            exec_path,
            args: cli.args,
            env: cli.env,
            workdir: cli.workdir,
            port_map: cli.port,
            vsock_ports: vec![],
            log_level: cli.krun_log_level,
            console_output: None,
            net: net_backend.clone(),
            reset: cli.reset,
        }
    } else {
        let mut c = openshell_vm::VmConfig::gateway(rootfs);
        if !cli.port.is_empty() {
            c.port_map = cli.port;
        }
        if let Some(v) = cli.vcpus {
            c.vcpus = v;
        }
        if let Some(m) = cli.mem {
            c.mem_mib = m;
        }
        c.net = net_backend;
        c.reset = cli.reset;
        c
    };
    config.log_level = cli.krun_log_level;

    Ok(openshell_vm::launch(&config)?)
}
