// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::VmError;

/// Remove a directory, safely handling symlinks.
///
/// Uses `symlink_metadata` (lstat) to detect symlinks. If the path is a
/// symlink (e.g. `var/run -> /run` in a Linux rootfs), the symlink itself
/// is removed without following it — preventing traversal attacks where a
/// symlink could redirect `remove_dir_all` to an arbitrary host path.
/// If the path is a real directory, it is removed recursively.
fn safe_remove_dir_all(path: &Path) -> Result<bool, VmError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                // Remove the symlink itself, not the target it points to.
                fs::remove_file(path).map_err(|e| {
                    VmError::RuntimeState(format!("reset: remove symlink {}: {e}", path.display()))
                })?;
                return Ok(true);
            }
            if !meta.is_dir() {
                return Ok(false); // Not a directory — nothing to remove.
            }
            fs::remove_dir_all(path).map_err(|e| {
                VmError::RuntimeState(format!("reset: remove {}: {e}", path.display()))
            })?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(VmError::RuntimeState(format!(
            "stat {}: {e}",
            path.display()
        ))),
    }
}

pub const VM_EXEC_VSOCK_PORT: u32 = 10_777;

/// How to connect to the VM exec agent.
///
/// libkrun bridges each guest vsock port to a host Unix socket via
/// `krun_add_vsock_port2`. QEMU uses kernel AF_VSOCK via vhost-vsock-pci,
/// bridged through a host Unix socket by the exec bridge thread.
#[derive(Debug, Clone)]
pub enum VsockConnectMode {
    /// Connect via a host Unix socket (libkrun per-port bridging).
    UnixSocket(PathBuf),
    /// Connect via a vsock proxy bridge (QEMU AF_VSOCK).
    /// The path points to a bridged Unix socket that connects to
    /// guest CID 3, port [`VM_EXEC_VSOCK_PORT`].
    VsockBridge(PathBuf),
}

const VM_STATE_NAME: &str = "vm-state.json";
const VM_LOCK_NAME: &str = "vm.lock";
const KUBECONFIG_ENV: &str = "KUBECONFIG=/etc/rancher/k3s/k3s.yaml";

#[derive(Debug, Clone)]
pub struct VmExecOptions {
    pub rootfs: Option<PathBuf>,
    pub command: Vec<String>,
    pub workdir: Option<String>,
    pub env: Vec<String>,
    pub tty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRuntimeState {
    pub pid: i32,
    pub exec_vsock_port: u32,
    pub socket_path: PathBuf,
    pub rootfs: PathBuf,
    pub console_log: PathBuf,
    pub started_at_ms: u128,
    /// PID of the gvproxy process (if networking uses gvproxy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gvproxy_pid: Option<u32>,
    /// Whether this VM uses vsock-bridge mode (QEMU AF_VSOCK) vs
    /// Unix socket mode (libkrun). Defaults to false for backward compat.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vsock_bridge: bool,
}

#[derive(Debug, Serialize)]
struct ExecRequest {
    argv: Vec<String>,
    env: Vec<String>,
    cwd: Option<String>,
    tty: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    Stdin { data: String },
    StdinClose,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
    Error { message: String },
}

pub fn vm_exec_socket_path(rootfs: &Path) -> PathBuf {
    // Prefer XDG_RUNTIME_DIR (per-user, restricted permissions on Linux),
    // fall back to /tmp. Ownership/symlink validation happens in
    // secure_socket_base() when the gvproxy socket dir is created; here
    // we just compute the path. The parent directory is created (with
    // permission checks) at launch time via create_dir_all.
    let base = if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg)
    } else {
        let mut base = PathBuf::from("/tmp");
        if !base.is_dir() {
            base = std::env::temp_dir();
        }
        base
    };
    let dir = base.join("ovm-exec");
    let id = hash_path_id(rootfs);
    dir.join(format!("{id}.sock"))
}

fn hash_path_id(path: &Path) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in path.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:012x}", hash & 0x0000_ffff_ffff_ffff)
}

pub fn write_vm_runtime_state(
    rootfs: &Path,
    pid: i32,
    console_log: &Path,
    gvproxy_pid: Option<u32>,
    vsock_bridge: bool,
) -> Result<(), VmError> {
    let state = VmRuntimeState {
        pid,
        exec_vsock_port: VM_EXEC_VSOCK_PORT,
        socket_path: vm_exec_socket_path(rootfs),
        rootfs: rootfs.to_path_buf(),
        console_log: console_log.to_path_buf(),
        started_at_ms: now_ms()?,
        gvproxy_pid,
        vsock_bridge,
    };
    let path = vm_state_path(rootfs);
    let bytes = serde_json::to_vec_pretty(&state)
        .map_err(|e| VmError::RuntimeState(format!("serialize VM runtime state: {e}")))?;
    fs::create_dir_all(vm_run_dir(rootfs))
        .map_err(|e| VmError::RuntimeState(format!("create VM runtime dir: {e}")))?;
    fs::write(&path, bytes)
        .map_err(|e| VmError::RuntimeState(format!("write {}: {e}", path.display())))?;
    Ok(())
}

pub fn clear_vm_runtime_state(rootfs: &Path) {
    let state_path = vm_state_path(rootfs);
    let lock_path = vm_lock_path(rootfs);
    let socket_path = vm_exec_socket_path(rootfs);
    let _ = fs::remove_file(state_path);
    let _ = fs::remove_file(lock_path);
    let _ = fs::remove_file(socket_path);
}

/// Wipe stale container runtime state from the rootfs.
///
/// After a crash or unclean shutdown, containerd and kubelet can retain
/// references to pod sandboxes and containers that no longer exist. This
/// causes `ContainerCreating` → `context deadline exceeded` loops because
/// containerd blocks trying to clean up orphaned resources.
///
/// This function removes:
/// - containerd runtime task state (running container metadata)
/// - containerd sandbox controller shim state
/// - containerd CRI plugin state (pod/container tracking)
/// - containerd tmp mounts
/// - kubelet pod state (volume mounts, pod status)
///
/// It preserves:
/// - containerd images and content (no re-pull needed)
/// - containerd snapshots (no re-extract needed)
/// - containerd metadata database (meta.db — image/snapshot tracking)
///
/// **Note:** This is the only path that wipes the kine/SQLite database.
/// Normal boots preserve `state.db` (and all cluster objects) across
/// restarts. The init script clears stale bootstrap locks via `sqlite3`,
/// and `recover_corrupt_kine_db` handles actual file corruption.
pub fn reset_runtime_state(rootfs: &Path, gateway_name: &str) -> Result<(), VmError> {
    // Full reset: wipe all runtime state so the VM cold-starts from scratch.
    //
    // With the block-device layout, k3s server/agent state, containerd, PVCs,
    // and PKI all live on the state disk — the caller in lib.rs deletes the
    // entire state disk image file, which achieves a complete wipe in one
    // operation without touching the virtiofs rootfs.
    //
    // We still clean the virtiofs rootfs for paths that are NOT on the state
    // disk: kubelet pod volumes, CNI state, and the pre-init sentinel.  These
    // paths are present in the rootfs regardless of the storage layout.
    let dirs_to_remove = [
        // Stale pod volume mounts and projected secrets
        rootfs.join("var/lib/kubelet/pods"),
        // CNI state: stale network namespace references from dead pods
        rootfs.join("var/lib/cni"),
        // Runtime state (PIDs, sockets) — on virtiofs, not block device
        rootfs.join("var/run"),
    ];

    let mut cleaned = 0usize;
    for dir in &dirs_to_remove {
        if safe_remove_dir_all(dir)? {
            cleaned += 1;
        }
    }

    // Remove the pre-initialized sentinel so the init script knows
    // this is a cold start and deploys manifests from staging.
    // We write a marker file so ensure-vm-rootfs.sh still sees the
    // rootfs as built (avoiding a full rebuild) while the init script
    // detects the cold start via the missing .initialized sentinel.
    let sentinel = rootfs.join("opt/openshell/.initialized");
    let reset_marker = rootfs.join("opt/openshell/.reset");
    if sentinel.exists() {
        fs::remove_file(&sentinel).map_err(|e| {
            VmError::RuntimeState(format!(
                "reset: remove sentinel {}: {e}",
                sentinel.display()
            ))
        })?;
        fs::write(&reset_marker, "").map_err(|e| {
            VmError::RuntimeState(format!(
                "reset: write marker {}: {e}",
                reset_marker.display()
            ))
        })?;
        cleaned += 1;
    }

    // PKI lives on the state disk; deleting the state disk image (done by
    // the caller) rotates it automatically.  Just note it for the log.
    eprintln!("Reset: PKI will be regenerated on next boot (state disk wiped)");

    // Wipe host-side mTLS credentials so bootstrap_gateway() takes the
    // first-boot path and fetches new certs from the VM via the exec agent.
    if let Ok(home) = std::env::var("HOME") {
        let config_base =
            std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
        let mtls_dir = PathBuf::from(&config_base)
            .join("openshell/gateways")
            .join(gateway_name)
            .join("mtls");
        if mtls_dir.is_dir() {
            fs::remove_dir_all(&mtls_dir).map_err(|e| {
                VmError::RuntimeState(format!(
                    "reset: remove mTLS dir {}: {e}",
                    mtls_dir.display()
                ))
            })?;
        }
        // Also remove metadata so is_warm_boot() returns false.
        let metadata = PathBuf::from(&config_base)
            .join("openshell/gateways")
            .join(gateway_name)
            .join("metadata.json");
        if metadata.is_file() {
            fs::remove_file(&metadata).map_err(|e| {
                VmError::RuntimeState(format!(
                    "reset: remove metadata {}: {e}",
                    metadata.display()
                ))
            })?;
        }
    }

    eprintln!("Reset: cleaned {cleaned} state directories (full reset)");
    Ok(())
}

/// Remove a corrupt kine (`SQLite`) database so k3s can recreate it on boot.
///
/// k3s uses kine with a `SQLite` backend at `var/lib/rancher/k3s/server/db/state.db`.
/// If the VM is killed mid-write (SIGKILL, host crash, power loss), the database
/// file may be left in a corrupt state — the `SQLite` header magic is missing or the
/// file is truncated. k3s would open the DB, get `SQLITE_NOTADB` /
/// `SQLITE_CORRUPT`, and crash at startup.
///
/// This function checks the `SQLite` file header (first 100 bytes only) and removes
/// the database plus its WAL/SHM sidecar files if the header is invalid. k3s will
/// create a fresh database on startup and cluster state will be re-applied from
/// the auto-deploy manifests in `server/manifests/`.
///
/// **Limitation — state disk:** When a state disk is configured (common with
/// `--gpu`), the kine DB lives inside the raw disk image, not on the virtiofs
/// rootfs. This host-side check only sees the virtiofs path and cannot detect
/// corruption on the state disk. The init script (`openshell-vm-init.sh`) runs
/// `PRAGMA quick_check` inside the VM where the state disk is mounted, catching
/// corruption that this function misses.
///
/// **Stale bootstrap locks** (a kine application-level issue where a killed k3s
/// server leaves a lock row that causes the next instance to hang) are handled
/// separately by the init script (`openshell-vm-init.sh`), which runs
/// `sqlite3 state.db "DELETE FROM kine WHERE name LIKE '/bootstrap/%'"` before
/// starting k3s. This allows the database — and all persistent cluster state — to
/// survive normal restarts.
///
/// **What is lost on corruption:** all cluster object records (Pods, Deployments,
/// Secrets, `ConfigMaps`, CRDs, etc.) and the bootstrap token. These are re-created
/// from manifests on the next boot.
///
/// **What is always preserved:** container images and snapshots (under
/// `k3s/agent/`), PKI, and the `.initialized` sentinel.
///
/// This function is a no-op if `state.db` does not exist (e.g. first boot or
/// after a full `--reset`).
pub fn recover_corrupt_kine_db(rootfs: &Path) -> Result<(), VmError> {
    let db_path = rootfs.join("var/lib/rancher/k3s/server/db/state.db");
    if !db_path.exists() {
        return Ok(()); // Nothing to check — first boot or post-reset.
    }

    // The SQLite file format begins with a 16-byte magic string.
    // Reference: https://www.sqlite.org/fileformat.html#the_database_header
    const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

    // Read only the first 100 bytes (the minimum valid SQLite header size)
    // instead of loading the entire database into memory.
    let has_invalid_header = match File::open(&db_path).and_then(|mut f| {
        let mut buf = [0u8; 100];
        let n = f.read(&mut buf)?;
        Ok((n, buf))
    }) {
        Err(_) => true,                // Can't read → treat as corrupt.
        Ok((n, _)) if n < 100 => true, // Too short to be a valid DB.
        Ok((_, buf)) => !buf.starts_with(SQLITE_MAGIC),
    };

    if !has_invalid_header {
        return Ok(()); // Valid database — preserve it for warm boot.
    }

    eprintln!(
        "Warning: kine database is corrupt ({}), removing for clean boot",
        db_path.display()
    );

    remove_kine_db_files(&db_path)?;

    Ok(())
}

/// Remove the kine `SQLite` database and its WAL/SHM sidecar files.
fn remove_kine_db_files(db_path: &Path) -> Result<(), VmError> {
    if let Err(e) = fs::remove_file(db_path) {
        return Err(VmError::RuntimeState(format!(
            "failed to remove kine database {}: {e}",
            db_path.display()
        )));
    }
    // Also remove any WAL/SHM sidecar files left by an interrupted write.
    let _ = fs::remove_file(db_path.with_extension("db-wal"));
    let _ = fs::remove_file(db_path.with_extension("db-shm"));
    Ok(())
}

/// Acquire an exclusive lock on the rootfs lock file.
///
/// The lock is held for the lifetime of the returned `File` handle. When
/// the process exits (even via SIGKILL), the OS releases the lock
/// automatically. This provides a reliable guard against two VM processes
/// sharing the same rootfs — even if the state file is deleted.
///
/// When the lock file already contains a PID from a previous holder that
/// is no longer alive, a warning is logged and any stale VM state files
/// are cleaned up proactively.
///
/// Returns `Ok(File)` on success. The caller must keep the `File` alive
/// for as long as the VM is running.
pub fn acquire_rootfs_lock(rootfs: &Path) -> Result<File, VmError> {
    let lock_path = vm_lock_path(rootfs);
    fs::create_dir_all(vm_run_dir(rootfs))
        .map_err(|e| VmError::RuntimeState(format!("create VM runtime dir: {e}")))?;

    // Open (or create) the lock file without truncating so we can read
    // the holder's PID for the error message if the lock is held.
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| {
            VmError::RuntimeState(format!("open lock file {}: {e}", lock_path.display()))
        })?;

    // Try non-blocking exclusive lock.
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            // Another process holds the flock. Read the PID recorded in
            // the file for diagnostics — but verify it's still alive,
            // because the file may contain a stale PID from a crashed
            // predecessor while a different process now holds the flock.
            let holder_pid = fs::read_to_string(&lock_path).unwrap_or_default();
            let holder_pid = holder_pid.trim();
            return Err(stale_lock_error(rootfs, holder_pid, &lock_path));
        }
        return Err(VmError::RuntimeState(format!(
            "lock rootfs {}: {err}",
            lock_path.display()
        )));
    }

    // Lock acquired — check for stale state from a crashed predecessor.
    // Read the previous PID before we overwrite it.
    cleanup_stale_state_on_lock_acquire(rootfs, &lock_path);

    // Write our PID (truncate first, then write).
    // This is informational only; the flock is the real guard.
    let _ = file.set_len(0);
    {
        let mut f = &file;
        let _ = write!(f, "{}", std::process::id());
    }

    Ok(file)
}

/// Build an appropriate error when flock returns EWOULDBLOCK.
///
/// If the PID recorded in the lock file is dead, the flock holder is a
/// different (unknown) process — provide enhanced diagnostics so the user
/// isn't misled by a stale PID.
fn stale_lock_error(rootfs: &Path, recorded_pid: &str, _lock_path: &Path) -> VmError {
    if let Ok(pid) = recorded_pid.parse::<i32>() {
        if pid > 0 && !process_alive(pid) {
            return VmError::RuntimeState(format!(
                "rootfs {} is locked, but the recorded holder (pid {pid}) is dead. \
                 A different openshell-vm process likely holds the lock. \
                 Check for running openshell-vm processes (`ps aux | grep openshell-vm`) \
                 and stop them before retrying.",
                rootfs.display(),
            ));
        }
    }
    VmError::RuntimeState(format!(
        "another process (pid {recorded_pid}) is using rootfs {}. \
         Stop the running VM first",
        rootfs.display()
    ))
}

/// After successfully acquiring the flock, check whether the lock file
/// contained a PID from a dead process (crash recovery). If so, log a
/// warning and clean up stale VM state/socket files.
fn cleanup_stale_state_on_lock_acquire(rootfs: &Path, lock_path: &Path) {
    let prev_contents = fs::read_to_string(lock_path).unwrap_or_default();
    let Ok(prev_pid) = prev_contents.trim().parse::<i32>() else {
        return;
    };
    if prev_pid <= 0 || process_alive(prev_pid) {
        return;
    }

    eprintln!("Warning: cleaning up stale lock from dead process (pid {prev_pid})");

    let state_path = vm_state_path(rootfs);
    if let Ok(bytes) = fs::read(&state_path) {
        if let Ok(state) = serde_json::from_slice::<VmRuntimeState>(&bytes) {
            if !process_alive(state.pid) {
                eprintln!("  Removing stale VM state (pid {})", state.pid);
                let _ = fs::remove_file(&state_path);
                let _ = fs::remove_file(vm_exec_socket_path(rootfs));
            }
        }
    }
}

/// Check whether the rootfs lock file is currently held by another process.
///
/// Returns `Ok(())` if the lock is free (or can be acquired), and an
/// `Err` if another process holds it. Does NOT acquire the lock — use
/// [`acquire_rootfs_lock`] for that.
fn check_rootfs_lock_free(rootfs: &Path) -> Result<(), VmError> {
    let lock_path = vm_lock_path(rootfs);
    if !lock_path.exists() {
        return Ok(());
    }

    let Ok(file) = File::open(&lock_path) else {
        return Ok(()); // Can't open → treat as free
    };

    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
    let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            let holder_pid = fs::read_to_string(&lock_path).unwrap_or_default();
            let holder_pid = holder_pid.trim();
            return Err(stale_lock_error(rootfs, holder_pid, &lock_path));
        }
    } else {
        // We acquired the lock — release it immediately since we're only probing.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }

    Ok(())
}

pub fn ensure_vm_not_running(rootfs: &Path) -> Result<(), VmError> {
    // The flock is the definitive guard: the kernel releases it
    // automatically when the owning process exits (even via SIGKILL).
    // If this succeeds, no VM process holds the rootfs.
    check_rootfs_lock_free(rootfs)?;

    // Flock is free — no VM process holds the rootfs lock. Any remaining
    // state file is stale (from a killed/crashed VM or PID reuse by an
    // unrelated process). Clean it up unconditionally.
    clear_vm_runtime_state(rootfs);
    Ok(())
}

pub fn exec_running_vm(options: VmExecOptions) -> Result<i32, VmError> {
    let state = load_vm_runtime_state(options.rootfs.as_deref())?;

    let connect_mode = if state.vsock_bridge {
        VsockConnectMode::VsockBridge(state.socket_path.clone())
    } else {
        VsockConnectMode::UnixSocket(state.socket_path.clone())
    };

    let socket_path = match &connect_mode {
        VsockConnectMode::UnixSocket(p) | VsockConnectMode::VsockBridge(p) => p,
    };

    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        VmError::Exec(format!(
            "connect to VM exec socket {}: {e}",
            socket_path.display()
        ))
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| VmError::Exec(format!("clone VM exec socket: {e}")))?;

    let mut env = options.env;
    validate_env_vars(&env)?;
    if !env.iter().any(|item| item.starts_with("KUBECONFIG=")) {
        env.push(KUBECONFIG_ENV.to_string());
    }

    let request = ExecRequest {
        argv: options.command,
        env,
        cwd: options.workdir,
        tty: options.tty,
    };
    send_json_line(&mut writer, &request)?;

    let stdin_writer = writer;
    thread::spawn(move || {
        let _ = pump_stdin(stdin_writer);
    });

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut stdout = stdout.lock();
    let mut stderr = stderr.lock();
    let mut exit_code = None;

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| VmError::Exec(format!("read VM exec response from guest agent: {e}")))?;
        if bytes == 0 {
            break;
        }

        let frame: ServerFrame = serde_json::from_str(line.trim_end())
            .map_err(|e| VmError::Exec(format!("decode VM exec response frame: {e}")))?;

        match frame {
            ServerFrame::Stdout { data } => {
                let bytes = decode_payload(&data)?;
                stdout
                    .write_all(&bytes)
                    .map_err(|e| VmError::Exec(format!("write guest stdout: {e}")))?;
                stdout
                    .flush()
                    .map_err(|e| VmError::Exec(format!("flush guest stdout: {e}")))?;
            }
            ServerFrame::Stderr { data } => {
                let bytes = decode_payload(&data)?;
                stderr
                    .write_all(&bytes)
                    .map_err(|e| VmError::Exec(format!("write guest stderr: {e}")))?;
                stderr
                    .flush()
                    .map_err(|e| VmError::Exec(format!("flush guest stderr: {e}")))?;
            }
            ServerFrame::Exit { code } => {
                exit_code = Some(code);
                break;
            }
            ServerFrame::Error { message } => {
                return Err(VmError::Exec(message));
            }
        }
    }

    exit_code.ok_or_else(|| {
        VmError::Exec("VM exec agent disconnected before returning an exit code".to_string())
    })
}

/// Run a command inside the guest via the exec agent and capture its stdout.
///
/// Unlike [`exec_running_vm`], this function does not pump host stdin or write
/// to the terminal. It collects all stdout frames into a `Vec<u8>` and returns
/// them on success (exit code 0). Stderr output is discarded.
///
/// This is the building block for internal host→guest queries (e.g. reading
/// files from the guest filesystem) without requiring a dedicated vsock server.
pub fn exec_capture(socket_path: &Path, argv: Vec<String>) -> Result<Vec<u8>, VmError> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        VmError::Exec(format!(
            "connect to VM exec socket {}: {e}",
            socket_path.display()
        ))
    })?;
    let mut writer = stream
        .try_clone()
        .map_err(|e| VmError::Exec(format!("clone VM exec socket: {e}")))?;

    let request = ExecRequest {
        argv,
        env: vec![],
        cwd: None,
        tty: false,
    };
    send_json_line(&mut writer, &request)?;

    // Close stdin immediately — we have no input to send.
    send_json_line(&mut writer, &ClientFrame::StdinClose)?;

    let mut reader = BufReader::new(&mut stream);
    let mut line = String::new();
    let mut stdout_buf = Vec::new();

    loop {
        line.clear();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| VmError::Exec(format!("read VM exec response: {e}")))?;
        if bytes == 0 {
            break;
        }

        let frame: ServerFrame = serde_json::from_str(line.trim_end())
            .map_err(|e| VmError::Exec(format!("decode VM exec response frame: {e}")))?;

        match frame {
            ServerFrame::Stdout { data } => {
                stdout_buf.extend_from_slice(&decode_payload(&data)?);
            }
            ServerFrame::Stderr { .. } => {
                // Discard stderr for capture mode.
            }
            ServerFrame::Exit { code } => {
                if code != 0 {
                    return Err(VmError::Exec(format!(
                        "guest command exited with code {code}"
                    )));
                }
                return Ok(stdout_buf);
            }
            ServerFrame::Error { message } => {
                return Err(VmError::Exec(message));
            }
        }
    }

    Err(VmError::Exec(
        "VM exec agent disconnected before returning an exit code".to_string(),
    ))
}

fn vm_run_dir(rootfs: &Path) -> PathBuf {
    rootfs.parent().unwrap_or(rootfs).to_path_buf()
}

pub fn vm_state_path(rootfs: &Path) -> PathBuf {
    vm_run_dir(rootfs).join(format!("{}-{}", rootfs_key(rootfs), VM_STATE_NAME))
}

fn vm_lock_path(rootfs: &Path) -> PathBuf {
    vm_run_dir(rootfs).join(format!("{}-{}", rootfs_key(rootfs), VM_LOCK_NAME))
}

fn rootfs_key(rootfs: &Path) -> String {
    let name = rootfs
        .file_name()
        .and_then(|part| part.to_str())
        .unwrap_or("openshell-vm");
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "openshell-vm".to_string()
    } else {
        out
    }
}

fn default_rootfs() -> Result<PathBuf, VmError> {
    crate::named_rootfs_dir("default")
}

fn load_vm_runtime_state(rootfs: Option<&Path>) -> Result<VmRuntimeState, VmError> {
    let rootfs = match rootfs {
        Some(rootfs) => rootfs.to_path_buf(),
        None => default_rootfs()?,
    };
    let path = vm_state_path(&rootfs);
    let bytes = fs::read(&path).map_err(|e| {
        VmError::RuntimeState(format!(
            "read VM runtime state {}: {e}. Start the VM with `openshell-vm` first",
            path.display()
        ))
    })?;
    let state: VmRuntimeState = serde_json::from_slice(&bytes)
        .map_err(|e| VmError::RuntimeState(format!("decode VM runtime state: {e}")))?;

    if !process_alive(state.pid) {
        clear_vm_runtime_state(&state.rootfs);
        return Err(VmError::RuntimeState(format!(
            "VM is not running (stale pid {})",
            state.pid
        )));
    }

    if !state.socket_path.exists() {
        return Err(VmError::RuntimeState(format!(
            "VM exec socket is not ready: {}",
            state.socket_path.display()
        )));
    }

    Ok(state)
}

fn validate_env_vars(items: &[String]) -> Result<(), VmError> {
    for item in items {
        let (key, _value) = item.split_once('=').ok_or_else(|| {
            VmError::Exec(format!(
                "invalid environment variable `{item}`; expected KEY=VALUE"
            ))
        })?;
        if key.is_empty()
            || !key.chars().enumerate().all(|(idx, ch)| {
                ch == '_' || (ch.is_ascii_alphanumeric() && (idx > 0 || !ch.is_ascii_digit()))
            })
        {
            return Err(VmError::Exec(format!(
                "invalid environment variable name `{key}`"
            )));
        }
    }
    Ok(())
}

fn send_json_line<T: Serialize>(writer: &mut UnixStream, value: &T) -> Result<(), VmError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|e| VmError::Exec(format!("encode VM exec request: {e}")))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .map_err(|e| VmError::Exec(format!("write VM exec request: {e}")))
}

fn pump_stdin(mut writer: UnixStream) -> Result<(), VmError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut buf = [0u8; 8192];

    loop {
        let read = stdin
            .read(&mut buf)
            .map_err(|e| VmError::Exec(format!("read local stdin: {e}")))?;
        if read == 0 {
            break;
        }
        let frame = ClientFrame::Stdin {
            data: base64::engine::general_purpose::STANDARD.encode(&buf[..read]),
        };
        send_json_line(&mut writer, &frame)?;
    }

    send_json_line(&mut writer, &ClientFrame::StdinClose)
}

fn decode_payload(data: &str) -> Result<Vec<u8>, VmError> {
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .map_err(|e| VmError::Exec(format!("decode VM exec payload: {e}")))
}

fn process_alive(pid: i32) -> bool {
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn now_ms() -> Result<u128, VmError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| VmError::RuntimeState(format!("read system clock: {e}")))?;
    Ok(duration.as_millis())
}
