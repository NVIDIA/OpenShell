// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use nix::sys::termios::{self, SetArg, Termios};
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
    Resize { cols: u16, rows: u16 },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Stdout { data: String },
    Stderr { data: String },
    Exit { code: i32 },
    Error { message: String },
}

struct RawModeGuard {
    raw_fd: i32,
    original: Termios,
}

impl RawModeGuard {
    fn enter() -> Result<Self, VmError> {
        let stdin = std::io::stdin();
        let fd = stdin.as_fd();
        let original =
            termios::tcgetattr(&fd).map_err(|e| VmError::Exec(format!("tcgetattr: {e}")))?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&fd, SetArg::TCSANOW, &raw)
            .map_err(|e| VmError::Exec(format!("tcsetattr: {e}")))?;
        Ok(Self {
            raw_fd: std::os::unix::io::AsRawFd::as_raw_fd(&stdin),
            original,
        })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let fd = unsafe { BorrowedFd::borrow_raw(self.raw_fd) };
        let _ = termios::tcsetattr(&fd, SetArg::TCSANOW, &self.original);
    }
}

fn get_terminal_size() -> Option<(u16, u16)> {
    let fd = std::os::unix::io::AsRawFd::as_raw_fd(&std::io::stdout());
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
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
) -> Result<(), VmError> {
    let state = VmRuntimeState {
        pid,
        exec_vsock_port: VM_EXEC_VSOCK_PORT,
        socket_path: vm_exec_socket_path(rootfs),
        rootfs: rootfs.to_path_buf(),
        console_log: console_log.to_path_buf(),
        started_at_ms: now_ms()?,
        gvproxy_pid,
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
    let socket_path = vm_exec_socket_path(rootfs);
    let _ = fs::remove_file(state_path);
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
            // Another process holds the lock — read its PID for diagnostics.
            let holder_pid = fs::read_to_string(&lock_path).unwrap_or_default();
            let holder_pid = holder_pid.trim();
            return Err(VmError::RuntimeState(format!(
                "another process (pid {holder_pid}) is using rootfs {}. \
                 Stop the running VM first",
                rootfs.display()
            )));
        }
        return Err(VmError::RuntimeState(format!(
            "lock rootfs {}: {err}",
            lock_path.display()
        )));
    }

    // Lock acquired — write our PID (truncate first, then write).
    // This is informational only; the flock is the real guard.
    let _ = file.set_len(0);
    {
        let mut f = &file;
        let _ = write!(f, "{}", std::process::id());
    }

    Ok(file)
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
            return Err(VmError::RuntimeState(format!(
                "another process (pid {holder_pid}) is using rootfs {}. \
                 Stop the running VM first",
                rootfs.display()
            )));
        }
    } else {
        // We acquired the lock — release it immediately since we're only probing.
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }

    Ok(())
}

pub fn ensure_vm_not_running(rootfs: &Path) -> Result<(), VmError> {
    // Primary guard: check the flock. This works even if the state file
    // has been deleted, because the kernel holds the lock until the
    // owning process exits.
    check_rootfs_lock_free(rootfs)?;

    // Secondary guard: check the state file for any stale state.
    match load_vm_runtime_state(Some(rootfs)) {
        Ok(state) => Err(VmError::RuntimeState(format!(
            "VM is already running (pid {}) with exec socket {}",
            state.pid,
            state.socket_path.display()
        ))),
        Err(VmError::RuntimeState(message))
            if message.starts_with("read VM runtime state")
                || message.starts_with("VM is not running") =>
        {
            clear_vm_runtime_state(rootfs);
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub fn exec_running_vm(options: VmExecOptions) -> Result<i32, VmError> {
    let state = load_vm_runtime_state(options.rootfs.as_deref())?;
    let mut stream = UnixStream::connect(&state.socket_path).map_err(|e| {
        VmError::Exec(format!(
            "connect to VM exec socket {}: {e}",
            state.socket_path.display()
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

    let tty = options.tty;
    let _raw_guard = if tty {
        if let Some((cols, rows)) = get_terminal_size() {
            send_json_line(&mut writer, &ClientFrame::Resize { cols, rows })?;
        }
        Some(RawModeGuard::enter()?)
    } else {
        None
    };

    let stdin_writer = writer;
    thread::spawn(move || {
        let _ = pump_stdin(stdin_writer, tty);
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

fn pump_stdin(mut writer: UnixStream, tty: bool) -> Result<(), VmError> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut buf = [0u8; 8192];
    let mut last_size: Option<(u16, u16)> = None;

    loop {
        let read = stdin
            .read(&mut buf)
            .map_err(|e| VmError::Exec(format!("read local stdin: {e}")))?;
        if read == 0 {
            break;
        }

        if tty {
            if let Some(size) = get_terminal_size() {
                if last_size != Some(size) {
                    last_size = Some(size);
                    let _ = send_json_line(
                        &mut writer,
                        &ClientFrame::Resize {
                            cols: size.0,
                            rows: size.1,
                        },
                    );
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── ExecRequest serialization ────────────────────────────────────

    #[test]
    fn exec_request_serializes_with_tty() {
        let req = ExecRequest {
            argv: vec!["sh".into()],
            env: vec!["TERM=xterm".into()],
            cwd: None,
            tty: true,
        };
        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["argv"], serde_json::json!(["sh"]));
        assert_eq!(json["tty"], true);
        assert_eq!(json["cwd"], serde_json::Value::Null);
    }

    #[test]
    fn exec_request_serializes_without_tty() {
        let req = ExecRequest {
            argv: vec!["echo".into(), "hello".into()],
            env: vec![],
            cwd: Some("/tmp".into()),
            tty: false,
        };
        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["tty"], false);
        assert_eq!(json["cwd"], "/tmp");
    }

    // ── ClientFrame serialization ────────────────────────────────────

    #[test]
    fn client_frame_stdin_serializes() {
        let frame = ClientFrame::Stdin {
            data: "aGVsbG8=".into(),
        };
        let json: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "stdin");
        assert_eq!(json["data"], "aGVsbG8=");
    }

    #[test]
    fn client_frame_stdin_close_serializes() {
        let frame = ClientFrame::StdinClose;
        let json: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "stdin_close");
    }

    #[test]
    fn client_frame_resize_serializes() {
        let frame = ClientFrame::Resize {
            cols: 120,
            rows: 40,
        };
        let json: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["type"], "resize");
        assert_eq!(json["cols"], 120);
        assert_eq!(json["rows"], 40);
    }

    // ── ServerFrame deserialization ───────────────────────────────────

    #[test]
    fn server_frame_stdout_deserializes() {
        let json = r#"{"type":"stdout","data":"aGVsbG8="}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Stdout { data } if data == "aGVsbG8="));
    }

    #[test]
    fn server_frame_stderr_deserializes() {
        let json = r#"{"type":"stderr","data":"ZXJy"}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Stderr { data } if data == "ZXJy"));
    }

    #[test]
    fn server_frame_exit_deserializes() {
        let json = r#"{"type":"exit","code":42}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Exit { code: 42 }));
    }

    #[test]
    fn server_frame_error_deserializes() {
        let json = r#"{"type":"error","message":"boom"}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Error { message } if message == "boom"));
    }

    #[test]
    fn server_frame_unknown_type_fails() {
        let json = r#"{"type":"unknown","data":"x"}"#;
        assert!(serde_json::from_str::<ServerFrame>(json).is_err());
    }

    // ── ClientFrame ↔ ServerFrame round-trip compatibility ───────────
    // Verify that what the Rust host serializes can be parsed by the
    // Python agent (same JSON shape), and vice versa.

    #[test]
    fn resize_frame_has_expected_json_shape() {
        let frame = ClientFrame::Resize { cols: 80, rows: 24 };
        let s = serde_json::to_string(&frame).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "resize");
        assert!(v["cols"].is_u64());
        assert!(v["rows"].is_u64());
    }

    // ── validate_env_vars ────────────────────────────────────────────

    #[test]
    fn validate_env_vars_accepts_valid() {
        let items = vec![
            "HOME=/root".to_string(),
            "PATH=/usr/bin".to_string(),
            "_UNDERSCORE=1".to_string(),
            "A1B2=val".to_string(),
        ];
        assert!(validate_env_vars(&items).is_ok());
    }

    #[test]
    fn validate_env_vars_rejects_missing_equals() {
        let items = vec!["NOEQUALS".to_string()];
        assert!(validate_env_vars(&items).is_err());
    }

    #[test]
    fn validate_env_vars_rejects_empty_key() {
        let items = vec!["=value".to_string()];
        assert!(validate_env_vars(&items).is_err());
    }

    #[test]
    fn validate_env_vars_rejects_leading_digit() {
        let items = vec!["1BAD=val".to_string()];
        assert!(validate_env_vars(&items).is_err());
    }

    #[test]
    fn validate_env_vars_rejects_special_chars() {
        let items = vec!["BAD-KEY=val".to_string()];
        assert!(validate_env_vars(&items).is_err());
    }

    // ── decode_payload ───────────────────────────────────────────────

    #[test]
    fn decode_payload_valid_base64() {
        let decoded = decode_payload("aGVsbG8=").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn decode_payload_empty() {
        let decoded = decode_payload("").unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn decode_payload_invalid_base64() {
        assert!(decode_payload("!!!not-base64!!!").is_err());
    }

    // ── Resize frame edge cases ──────────────────────────────────────

    #[test]
    fn resize_frame_max_dimensions() {
        let frame = ClientFrame::Resize {
            cols: u16::MAX,
            rows: u16::MAX,
        };
        let json: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["cols"], u16::MAX as u64);
        assert_eq!(json["rows"], u16::MAX as u64);
    }

    #[test]
    fn resize_frame_minimum_dimensions() {
        let frame = ClientFrame::Resize { cols: 1, rows: 1 };
        let json: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(json["cols"], 1);
        assert_eq!(json["rows"], 1);
    }

    // ── Wire format: newline-delimited JSON ──────────────────────────
    // The protocol sends one JSON object per line. Verify that
    // serialized frames produce valid single-line JSON that the
    // Python agent can split on '\n' and json.loads().

    #[test]
    fn client_frames_serialize_to_single_line_json() {
        let frames: Vec<ClientFrame> = vec![
            ClientFrame::Stdin {
                data: "dGVzdA==".into(),
            },
            ClientFrame::StdinClose,
            ClientFrame::Resize { cols: 80, rows: 24 },
        ];
        for frame in &frames {
            let s = serde_json::to_string(frame).unwrap();
            assert!(!s.contains('\n'), "frame should be single-line: {s}");
            let _: serde_json::Value = serde_json::from_str(&s).unwrap();
        }
    }

    #[test]
    fn exec_request_serializes_to_single_line_json() {
        let req = ExecRequest {
            argv: vec!["bash".into(), "-c".into(), "echo 'hello world'".into()],
            env: vec!["HOME=/root".into(), "TERM=xterm-256color".into()],
            cwd: Some("/home/user".into()),
            tty: true,
        };
        let s = serde_json::to_string(&req).unwrap();
        assert!(!s.contains('\n'));
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    // ── Stdin data encode → decode round-trip ────────────────────────
    // Mirrors the flow: host encodes payload as base64 in a Stdin
    // frame, guest decodes with decode_payload().

    #[test]
    fn stdin_payload_round_trip() {
        let original = b"echo hello\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(original);
        let frame = ClientFrame::Stdin {
            data: encoded.clone(),
        };
        let json = serde_json::to_string(&frame).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let decoded = decode_payload(parsed["data"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn stdin_payload_round_trip_binary() {
        let original: Vec<u8> = (0..=255).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&original);
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    // ── Python agent compatibility ───────────────────────────────────
    // The Python agent parses frames with json.loads() and dispatches
    // on frame["type"]. These tests verify the exact field names and
    // values match what the Python code expects.

    #[test]
    fn exec_request_tty_field_matches_python_dispatch() {
        // Python: request.get("tty") — must be a JSON boolean
        let req = ExecRequest {
            argv: vec!["sh".into()],
            env: vec![],
            cwd: None,
            tty: true,
        };
        let v: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert!(v["tty"].is_boolean());
        assert_eq!(v["tty"].as_bool().unwrap(), true);

        let req_no_tty = ExecRequest {
            argv: vec!["echo".into()],
            env: vec![],
            cwd: None,
            tty: false,
        };
        let v: serde_json::Value = serde_json::to_value(&req_no_tty).unwrap();
        assert_eq!(v["tty"].as_bool().unwrap(), false);
    }

    #[test]
    fn resize_type_tag_is_snake_case() {
        // Python: kind == "resize" — must be lowercase snake_case
        let frame = ClientFrame::Resize { cols: 80, rows: 24 };
        let v: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "resize");
    }

    #[test]
    fn stdin_close_type_tag_is_snake_case() {
        // Python: kind == "stdin_close"
        let frame = ClientFrame::StdinClose;
        let v: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert_eq!(v["type"].as_str().unwrap(), "stdin_close");
    }

    #[test]
    fn resize_fields_are_integers_not_strings() {
        // Python: frame.get("cols", 80) — expects int, not string
        let frame = ClientFrame::Resize {
            cols: 200,
            rows: 50,
        };
        let v: serde_json::Value = serde_json::to_value(&frame).unwrap();
        assert!(v["cols"].is_u64());
        assert!(v["rows"].is_u64());
    }

    // ── ServerFrame: Python agent output ─────────────────────────────
    // These mirror the exact JSON the Python agent produces with
    // json.dumps(frame, separators=(",", ":"))

    #[test]
    fn server_frame_parses_compact_json() {
        // Python uses separators=(",", ":") — no spaces
        let compact = r#"{"type":"stdout","data":"aGk="}"#;
        let frame: ServerFrame = serde_json::from_str(compact).unwrap();
        assert!(matches!(frame, ServerFrame::Stdout { data } if data == "aGk="));
    }

    #[test]
    fn server_frame_exit_code_zero() {
        let json = r#"{"type":"exit","code":0}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Exit { code: 0 }));
    }

    #[test]
    fn server_frame_exit_code_negative() {
        let json = r#"{"type":"exit","code":-1}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Exit { code: -1 }));
    }

    #[test]
    fn server_frame_tolerates_extra_fields() {
        // Future-proofing: agent may add fields we don't know about
        let json = r#"{"type":"exit","code":0,"extra":"ignored"}"#;
        let frame: ServerFrame = serde_json::from_str(json).unwrap();
        assert!(matches!(frame, ServerFrame::Exit { code: 0 }));
    }
}
