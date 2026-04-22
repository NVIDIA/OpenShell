// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Standalone openshell-vm binary.
//!
//! Boots a libkrun microVM running the `OpenShell` control plane (k3s +
//! openshell-server). Each named instance gets its own rootfs extracted from
//! the embedded tarball at
//! `~/.local/share/openshell/openshell-vm/{version}/instances/<name>/rootfs`.
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

const DISABLE_STATE_DISK_ENV: &str = "OPENSHELL_VM_DISABLE_STATE_DISK";

/// Boot the `OpenShell` gateway microVM.
///
/// Starts a libkrun microVM running a k3s Kubernetes cluster with the
/// `OpenShell` control plane. Use `--exec` to run a custom process instead.
#[derive(Parser)]
#[command(name = "openshell-vm", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<GatewayCommand>,

    /// Path to the rootfs directory (aarch64 Linux).
    /// Overrides the default instance-based rootfs resolution.
    #[arg(long, value_hint = ValueHint::DirPath)]
    rootfs: Option<PathBuf>,

    /// Named VM instance.
    ///
    /// When used alone, the rootfs resolves to
    /// `~/.local/share/openshell/openshell-vm/{version}/instances/<name>/rootfs`
    /// and is extracted from the embedded tarball on first use.
    /// When combined with `--rootfs`, only provides the instance identity
    /// (for exec, gateway name, etc.) while the rootfs comes from the
    /// explicit path.
    #[arg(long, default_value = "default")]
    name: String,

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

    /// Enable GPU passthrough. Optionally specify a PCI address
    /// (e.g. `0000:41:00.0`). Uses cloud-hypervisor backend with VFIO.
    #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
    gpu: Option<String>,

    /// Hypervisor backend: "auto" (default), "libkrun", or "cloud-hypervisor".
    /// Auto selects cloud-hypervisor when --gpu is set, libkrun otherwise.
    #[arg(long, default_value = "auto")]
    backend: String,
}

#[derive(Subcommand)]
enum GatewayCommand {
    /// Ensure the target rootfs exists, extracting the embedded rootfs if needed.
    PrepareRootfs {
        /// Recreate the target rootfs even if it already exists.
        #[arg(long)]
        force: bool,
    },

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
    // On macOS, libkrun loads libkrunfw.5.dylib via dlopen() with a bare name.
    // The dynamic linker only finds it if DYLD_LIBRARY_PATH includes the runtime
    // directory, but env vars set after process start are ignored by dyld. To work
    // around this, re-exec the binary with DYLD_LIBRARY_PATH set if the runtime
    // is available and the variable is not already configured.
    #[cfg(target_os = "macos")]
    {
        if std::env::var_os("__OPENSHELL_VM_REEXEC").is_none() {
            if let Ok(runtime_dir) = openshell_vm::configured_runtime_dir() {
                let needs_reexec = std::env::var_os("DYLD_LIBRARY_PATH").map_or(true, |v| {
                    !v.to_string_lossy()
                        .contains(runtime_dir.to_str().unwrap_or(""))
                });
                if needs_reexec {
                    let mut dyld_paths = vec![runtime_dir];
                    if let Some(existing) = std::env::var_os("DYLD_LIBRARY_PATH") {
                        dyld_paths.extend(std::env::split_paths(&existing));
                    }
                    let joined = std::env::join_paths(&dyld_paths).expect("join DYLD_LIBRARY_PATH");
                    let exe = std::env::current_exe().expect("current_exe");
                    let args: Vec<String> = std::env::args().skip(1).collect();
                    let err = std::process::Command::new(exe)
                        .args(&args)
                        .env("DYLD_LIBRARY_PATH", &joined)
                        .env("__OPENSHELL_VM_REEXEC", "1")
                        .status();
                    match err {
                        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                        Err(e) => {
                            eprintln!("Error: failed to re-exec with DYLD_LIBRARY_PATH: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }

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
    if let Some(GatewayCommand::PrepareRootfs { force }) = &cli.command {
        let rootfs = openshell_vm::prepare_rootfs(cli.rootfs.clone(), &cli.name, *force)?;
        println!("{}", rootfs.display());
        return Ok(0);
    }

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
        let exec_rootfs = if let Some(explicit) = cli.rootfs {
            explicit
        } else if cli.gpu.is_some() {
            openshell_vm::named_gpu_rootfs_dir(&cli.name)?
        } else {
            openshell_vm::named_rootfs_dir(&cli.name)?
        };
        return Ok(openshell_vm::exec_running_vm(
            openshell_vm::VmExecOptions {
                rootfs: Some(exec_rootfs),
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

    let rootfs = if let Some(explicit) = cli.rootfs {
        Ok(explicit)
    } else if cli.gpu.is_some() {
        openshell_vm::ensure_gpu_rootfs(&cli.name)
    } else {
        openshell_vm::ensure_named_rootfs(&cli.name)
    }?;

    let gateway_name = openshell_vm::gateway_name(&cli.name)?;

    let (gpu_enabled, vfio_device, _gpu_guard) = match cli.gpu {
        Some(ref addr) if addr != "auto" => {
            let state = openshell_vfio::prepare_gpu_for_passthrough(Some(addr))?;
            let bdf = state.pci_addr.clone();
            (
                true,
                Some(bdf),
                Some(openshell_vfio::GpuBindGuard::new(state)),
            )
        }
        Some(_) => {
            let state = openshell_vfio::prepare_gpu_for_passthrough(None)?;
            let bdf = state.pci_addr.clone();
            (
                true,
                Some(bdf),
                Some(openshell_vfio::GpuBindGuard::new(state)),
            )
        }
        None => (false, None, None),
    };

    let backend_choice = match cli.backend.as_str() {
        "cloud-hypervisor" | "chv" => openshell_vm::VmBackendChoice::CloudHypervisor,
        "libkrun" => {
            if gpu_enabled {
                return Err(
                    "--backend libkrun is incompatible with --gpu (libkrun does not support \
                     VFIO passthrough). Use --backend auto or --backend cloud-hypervisor."
                        .into(),
                );
            }
            openshell_vm::VmBackendChoice::Libkrun
        }
        "auto" => openshell_vm::VmBackendChoice::Auto,
        other => {
            return Err(format!(
                "unknown --backend: {other} (expected: auto, libkrun, cloud-hypervisor)"
            )
            .into());
        }
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
            net: net_backend,
            reset: cli.reset,
            gateway_name,
            state_disk: None,
            gpu_enabled,
            vfio_device,
            backend: backend_choice,
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
        c.gateway_name = gateway_name;
        c.gpu_enabled = gpu_enabled;
        c.vfio_device = vfio_device;
        c.backend = backend_choice;
        if state_disk_disabled() {
            c.state_disk = None;
        }
        c
    };
    config.log_level = cli.krun_log_level;

    Ok(openshell_vm::launch(&config)?)
}

fn state_disk_disabled() -> bool {
    matches!(
        std::env::var(DISABLE_STATE_DISK_ENV).ok().as_deref(),
        Some("1" | "true" | "TRUE" | "yes" | "YES")
    )
}
