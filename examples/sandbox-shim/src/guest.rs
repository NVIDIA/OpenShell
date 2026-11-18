// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side launchers that place the shim inside a Firecracker microVM or a
//! gVisor sandbox, and expose its backend channel as a host Unix socket.
use crate::launch::{Privilege, VSOCK_PORT, write_private};
use anyhow::{Context, Result, bail, ensure};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
};

const READY_TIMEOUT: Duration = Duration::from_secs(90);

pub struct FirecrackerConfig {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    /// Initramfs holding only the static shim as `/init`; the shim's root.
    pub initramfs: PathBuf,
    /// Prepared ext4 workload rootfs; copied per sandbox.
    pub rootfs_image: PathBuf,
    pub vcpus: u8,
    pub memory_mib: u32,
}

pub struct GvisorConfig {
    /// Directory containing `runsc`.
    pub runsc_dir: PathBuf,
    /// Extracted root filesystem tree (read-only source).
    pub rootfs_dir: PathBuf,
    /// Static shim binary; the only file in the sandbox's own root.
    pub shim: PathBuf,
    /// Helper image that runs `runsc` with root inside Docker.
    pub docker_image: String,
    /// Unique per driver run; scopes container names and labels.
    pub run_id: String,
}

pub enum Substrate {
    Firecracker(FirecrackerConfig),
    Gvisor(GvisorConfig),
}

pub enum Guest {
    Firecracker {
        vm: Child,
        relay: tokio::task::JoinHandle<()>,
        dir: PathBuf,
    },
    Gvisor {
        runner: Child,
        container: String,
        dir: PathBuf,
    },
}

impl Guest {
    pub fn exited(&mut self) -> bool {
        let child = match self {
            Self::Firecracker { vm, .. } => vm,
            Self::Gvisor { runner, .. } => runner,
        };
        !matches!(child.try_wait(), Ok(None))
    }

    pub async fn stop(&mut self) {
        match self {
            Self::Firecracker { vm, relay, dir } => {
                relay.abort();
                let _ = vm.start_kill();
                let _ = vm.wait().await;
                // Keep the console log; drop the disks (the config disk
                // holds launch credentials).
                let _ = std::fs::remove_file(dir.join("rootfs.ext4"));
                let _ = std::fs::remove_file(dir.join("config.ext4"));
            }
            Self::Gvisor {
                runner,
                container,
                dir,
            } => {
                let _ = Command::new("docker")
                    .args(["rm", "-f", container.as_str()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await;
                let _ = runner.wait().await;
                let _ = std::fs::remove_dir_all(dir.join("launch"));
            }
        }
    }
}

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

async fn run(command: &mut Command, what: &str) -> Result<()> {
    let output = command
        .output()
        .await
        .with_context(|| format!("run {what}"))?;
    ensure!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Open one stream to the guest through Firecracker's vsock multiplexer.
async fn vsock_connect(uds: &Path) -> Result<UnixStream> {
    let stream = UnixStream::connect(uds).await?;
    let mut stream = BufReader::new(stream);
    stream
        .get_mut()
        .write_all(format!("CONNECT {VSOCK_PORT}\n").as_bytes())
        .await?;
    let mut line = String::new();
    stream.read_line(&mut line).await?;
    ensure!(
        line.starts_with("OK "),
        "vsock handshake refused: {}",
        line.trim()
    );
    ensure!(
        stream.buffer().is_empty(),
        "unexpected bytes after vsock handshake"
    );
    Ok(stream.into_inner())
}

/// Relay the registered backend socket to the guest's AF_VSOCK listener;
/// the supervisor dials plain Unix sockets.
fn vsock_relay(listener: UnixListener, uds: PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut host, _)) = listener.accept().await {
            let uds = uds.clone();
            tokio::spawn(async move {
                match vsock_connect(&uds).await {
                    Ok(mut guest) => {
                        let _ = tokio::io::copy_bidirectional(&mut host, &mut guest).await;
                    }
                    Err(error) => eprintln!("vsock relay: {error:#}"),
                }
            });
        }
    })
}

enum Probe {
    /// Firecracker's vsock multiplexer reaches the guest listener.
    Vsock(PathBuf),
    /// runsc created the host side of the guest's Unix listener.
    Unix(PathBuf),
}

impl Probe {
    async fn ready(&self) -> bool {
        match self {
            Self::Vsock(path) => tokio::time::timeout(Duration::from_secs(2), vsock_connect(path))
                .await
                .is_ok_and(|connected| connected.is_ok()),
            Self::Unix(path) => UnixStream::connect(path).await.is_ok(),
        }
    }
}

async fn wait_ready(probe: Probe, child: &mut Child, log: &Path) -> Result<()> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if probe.ready().await {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            bail!("guest exited during boot ({status}); see {}", log.display());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    bail!(
        "guest did not open its backend channel; see {}",
        log.display()
    )
}

impl Substrate {
    /// Start the guest with `launch_json` and return once its backend channel
    /// accepts connections at `backend_socket`.
    pub async fn start(
        &self,
        state_dir: &Path,
        sandbox_id: &str,
        launch_json: &[u8],
        privilege: Privilege,
        backend_socket: &Path,
    ) -> Result<Guest> {
        let short: String = sandbox_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(12)
            .collect();
        match self {
            Self::Firecracker(config) => {
                let dir = state_dir.join(format!("vm-{short}"));
                private_dir(&dir)?;
                let rootfs = dir.join("rootfs.ext4");
                run(
                    Command::new("cp")
                        .args(["--sparse=always", "--reflink=auto"])
                        .arg(&config.rootfs_image)
                        .arg(&rootfs),
                    "copy rootfs image",
                )
                .await?;
                let config_tree = dir.join("config");
                private_dir(&config_tree)?;
                write_private(&config_tree.join("launch.json"), launch_json)?;
                let config_disk = dir.join("config.ext4");
                let made = run(
                    Command::new("mkfs.ext4")
                        .args(["-q", "-F", "-L", "osconfig", "-d"])
                        .arg(&config_tree)
                        .arg(&config_disk)
                        .arg("8M"),
                    "build config disk",
                )
                .await;
                let _ = std::fs::remove_dir_all(&config_tree);
                made?;
                let vsock = dir.join("v.sock");
                let vm_config = serde_json::json!({
                    "boot-source": {
                        "kernel_image_path": config.kernel,
                        "initrd_path": config.initramfs,
                        "boot_args": "console=ttyS0 reboot=k panic=1 rdinit=/init -- init --substrate firecracker",
                    },
                    "drives": [
                        {"drive_id": "workload", "path_on_host": rootfs, "is_root_device": false, "is_read_only": false},
                        {"drive_id": "config", "path_on_host": config_disk, "is_root_device": false, "is_read_only": true},
                    ],
                    "machine-config": {"vcpu_count": config.vcpus, "mem_size_mib": config.memory_mib},
                    "vsock": {"guest_cid": 3, "uds_path": vsock},
                });
                let vm_config_path = dir.join("vm.json");
                write_private(&vm_config_path, &serde_json::to_vec_pretty(&vm_config)?)?;
                let log = dir.join("console.log");
                let console = std::fs::File::create(&log)?;
                let mut vm = Command::new(&config.firecracker)
                    .arg("--no-api")
                    .arg("--config-file")
                    .arg(&vm_config_path)
                    .stdin(Stdio::null())
                    .stdout(console.try_clone()?)
                    .stderr(console)
                    .kill_on_drop(true)
                    .spawn()
                    .context("start firecracker")?;
                wait_ready(Probe::Vsock(vsock.clone()), &mut vm, &log).await?;
                let _ = std::fs::remove_file(backend_socket);
                let listener = UnixListener::bind(backend_socket)?;
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(backend_socket, std::fs::Permissions::from_mode(0o600))?;
                let relay = vsock_relay(listener, vsock);
                Ok(Guest::Firecracker { vm, relay, dir })
            }
            Self::Gvisor(config) => {
                let dir = state_dir.join(format!("gv-{short}"));
                private_dir(&dir)?;
                let channel = backend_socket
                    .parent()
                    .context("backend socket needs a parent directory")?;
                std::fs::create_dir_all(channel)?;
                // runsc's gofer creates the host socket here without host
                // DAC override; the 0700 state directory still gates access.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(channel, std::fs::Permissions::from_mode(0o777))?;
                let _ = std::fs::remove_file(backend_socket);
                let launch_dir = dir.join("launch");
                private_dir(&launch_dir)?;
                write_private(&launch_dir.join("launch.json"), launch_json)?;
                write_private(
                    &launch_dir.join("config.json"),
                    &serde_json::to_vec_pretty(&oci_config())?,
                )?;
                let owner = crate::launch::workload_root_owner(privilege);
                let container = format!("openshell-sandbox-shim-{}-{short}", config.run_id);
                let workload_id = privilege.guest_id();
                // Two trees: `root` (root-owned, only the shim and its control
                // paths) is the sandbox root; `workload` is the workload's
                // rootfs, mounted into it and entered with pivot_root.
                let script = format!(
                    "set -eu
mkdir -p /bundle/root/proc /bundle/root/dev /bundle/root/sys /bundle/root/tmp \\
  /bundle/root/run/openshell/chan /bundle/root/run/openshell/workload /bundle/root/run/openshell/tls
install -o 0 -g 0 -m 0755 /src/shim /bundle/root/init
install -o 0 -g 0 -m 0600 /src/launch/launch.json /bundle/root/run/openshell/launch.json
mkdir -p /bundle/workload
cp -a /src/rootfs/. /bundle/workload/
mkdir -p /bundle/workload/proc /bundle/workload/dev /bundle/workload/sys /bundle/workload/tmp \\
  /bundle/workload/sandbox /bundle/workload/etc/openshell-tls
chown -R {owner}:{owner} /bundle/workload
chown {workload_id}:{workload_id} /bundle/workload/sandbox
chmod 1777 /bundle/workload/tmp
cp /src/launch/config.json /bundle/config.json
exec /gvisor/runsc --root=/tmp/runsc --ignore-cgroups --in-sandbox-cgroup=v2 --network=none --platform=systrap --host-uds=create --overlay2=root:memory run --bundle=/bundle sandbox
"
                );
                let log = dir.join("guest.log");
                let output = std::fs::File::create(&log)?;
                let mount = |source: &Path, target: &str, mode: &str| {
                    format!("type=bind,src={},dst={target}{mode}", source.display())
                };
                let mut runner = Command::new("docker")
                    .args(["run", "--rm", "--name", &container])
                    .args([
                        "--label",
                        &format!("openshell-sandbox-shim.run={}", config.run_id),
                    ])
                    .args(["--network", "none"])
                    // runsc needs these to build its own sandbox; Docker only
                    // supplies root. The workload runs inside runsc.
                    .args(["--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE"])
                    .args(["--security-opt", "seccomp=unconfined"])
                    .args(["--security-opt", "apparmor=unconfined"])
                    .arg("--mount")
                    .arg(mount(&config.runsc_dir, "/gvisor", ",readonly"))
                    .arg("--mount")
                    .arg(mount(&config.rootfs_dir, "/src/rootfs", ",readonly"))
                    .arg("--mount")
                    .arg(mount(&config.shim, "/src/shim", ",readonly"))
                    .arg("--mount")
                    .arg(mount(&launch_dir, "/src/launch", ",readonly"))
                    .arg("--mount")
                    .arg(mount(channel, "/bundle-chan", ""))
                    .args([
                        "--entrypoint",
                        "/bin/sh",
                        &config.docker_image,
                        "-c",
                        &script,
                    ])
                    .stdin(Stdio::null())
                    .stdout(output.try_clone()?)
                    .stderr(output)
                    .spawn()
                    .context("start docker for runsc")?;
                let ready =
                    wait_ready(Probe::Unix(backend_socket.to_path_buf()), &mut runner, &log).await;
                // The container holds its own copy; drop the host-side secret.
                let _ = std::fs::remove_file(launch_dir.join("launch.json"));
                if let Err(error) = ready {
                    let mut guest = Guest::Gvisor {
                        runner,
                        container,
                        dir,
                    };
                    guest.stop().await;
                    return Err(error);
                }
                Ok(Guest::Gvisor {
                    runner,
                    container,
                    dir,
                })
            }
        }
    }
}

fn oci_config() -> serde_json::Value {
    let capabilities: Vec<&str> = vec![
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_SETGID",
        "CAP_SETUID",
        "CAP_SETPCAP",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_NET_ADMIN",
        "CAP_SYS_CHROOT",
        "CAP_SYS_ADMIN",
        "CAP_SYS_PTRACE",
        "CAP_MKNOD",
        "CAP_AUDIT_WRITE",
        "CAP_SETFCAP",
        "CAP_SYS_RESOURCE",
    ];
    serde_json::json!({
        "ociVersion": "1.0.2",
        "hostname": "openshell",
        "process": {
            "user": {"uid": 0, "gid": 0},
            "args": ["/init", "init", "--substrate", "gvisor"],
            "env": ["PATH=/usr/sbin:/usr/bin:/sbin:/bin"],
            "cwd": "/",
            "capabilities": {
                "bounding": capabilities, "effective": capabilities,
                "permitted": capabilities, "inheritable": capabilities,
            },
        },
        "root": {"path": "root", "readonly": false},
        "mounts": [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "mode=755"]},
            {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]},
            {"destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "nodev", "mode=1777"]},
            {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
            // gVisor's own cgroup v2 emulation, delegated to privileged workloads.
            {"destination": "/sys/fs/cgroup", "type": "cgroup", "source": "cgroup", "options": ["nosuid", "noexec", "nodev"]},
            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"]},
            {"destination": crate::init::CHANNEL_DIR, "type": "bind", "source": "/bundle-chan", "options": ["rbind", "rw"]},
            {"destination": crate::launch::WORKLOAD_ROOT, "type": "bind", "source": "/bundle/workload", "options": ["rbind", "rw"]},
        ],
        "linux": {
            "namespaces": [{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}],
        },
    })
}

/// Write a newc initramfs whose only file is the shim as `/init`, plus the
/// mount points and `/dev/console` PID 1 needs. Everything is owned by root.
pub fn write_initramfs(shim: &Path, output: &Path) -> Result<()> {
    let shim = std::fs::read(shim).context("read shim binary")?;
    let mut archive = Vec::with_capacity(shim.len() + 4096);
    let mut inode = 1;
    let mut entry = |name: &str, mode: u32, rdev: (u32, u32), data: &[u8]| {
        let name_size = name.len() + 1;
        let header = format!(
            "070701{inode:08X}{mode:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{name_size:08X}{:08X}",
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            rdev.0,
            rdev.1,
            0
        );
        inode += 1;
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        archive.resize(archive.len().next_multiple_of(4), 0);
        archive.extend_from_slice(data);
        archive.resize(archive.len().next_multiple_of(4), 0);
    };
    for dir in ["dev", "proc", "sys", "run", "tmp"] {
        entry(dir, 0o040_755, (0, 0), &[]);
    }
    entry("dev/console", 0o020_600, (5, 1), &[]);
    entry("init", 0o100_755, (0, 0), &shim);
    entry("TRAILER!!!", 0, (0, 0), &[]);
    write_private(output, &archive)
}
