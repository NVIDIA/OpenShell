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
    let mut base = PathBuf::from("/tmp");
    if !base.is_dir() {
        base = std::env::temp_dir();
    }
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
/// - k3s server state (kine/sqlite, TLS certs, manifests)
pub fn reset_runtime_state(rootfs: &Path, gateway_name: &str) -> Result<(), VmError> {
    // Full reset: wipe all k3s state so the VM cold-starts from scratch.
    // The init script will re-import airgap images, deploy manifests,
    // and generate fresh cluster state. This is slower (~30-60s) but
    // guarantees no stale state from previous runs.
    let dirs_to_remove = [
        // All k3s server state: kine DB, TLS certs, manifests, tokens
        rootfs.join("var/lib/rancher/k3s/server"),
        // All k3s agent state: containerd images, snapshots, metadata
        rootfs.join("var/lib/rancher/k3s/agent/containerd"),
        // Stale pod volume mounts and projected secrets
        rootfs.join("var/lib/kubelet/pods"),
        // CNI state: stale network namespace references from dead pods
        rootfs.join("var/lib/cni"),
        // Runtime state (PIDs, sockets, containerd socket)
        rootfs.join("var/run"),
    ];

    let mut cleaned = 0usize;
    for dir in &dirs_to_remove {
        if dir.is_dir() {
            fs::remove_dir_all(dir).map_err(|e| {
                VmError::RuntimeState(format!("reset: remove {}: {e}", dir.display()))
            })?;
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
        fs::remove_file(&sentinel).ok();
        fs::write(&reset_marker, "").ok();
        cleaned += 1;
    }

    // Rotate PKI: wipe VM-side certs so the init script regenerates
    // them on next boot, and wipe host-side mTLS creds so
    // bootstrap_gateway() takes the first-boot path and copies the
    // new certs down.
    let pki_dir = rootfs.join("opt/openshell/pki");
    if pki_dir.is_dir() {
        fs::remove_dir_all(&pki_dir).ok();
        cleaned += 1;
        eprintln!("Reset: rotated PKI (will regenerate on next boot)");
    }

    // Wipe host-side mTLS credentials so bootstrap picks up the new certs.
    if let Ok(home) = std::env::var("HOME") {
        let config_base =
            std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| format!("{home}/.config"));
        let mtls_dir = PathBuf::from(&config_base)
            .join("openshell/gateways")
            .join(gateway_name)
            .join("mtls");
        if mtls_dir.is_dir() {
            fs::remove_dir_all(&mtls_dir).ok();
        }
        // Also remove metadata so is_warm_boot() returns false.
        let metadata = PathBuf::from(&config_base)
            .join("openshell/gateways")
            .join(gateway_name)
            .join("metadata.json");
        if metadata.is_file() {
            fs::remove_file(&metadata).ok();
        }
    }

    eprintln!("Reset: cleaned {cleaned} state directories (full reset)");
    Ok(())
}

/// Recover from a corrupt or bootstrap-locked kine (SQLite) database.
///
/// k3s uses kine with a SQLite backend at `var/lib/rancher/k3s/server/db/state.db`.
/// If the VM is killed mid-write (SIGKILL, host crash, power loss), SQLite may
/// not have checkpointed its WAL, leaving the database in one of two broken states:
///
/// 1. **Corrupt file** — the SQLite header magic is missing or the file is
///    truncated. k3s opens the DB, gets `SQLITE_NOTADB` / `SQLITE_CORRUPT`,
///    and crashes at startup.
///
/// 2. **Stale bootstrap lock** — the kine schema is intact but a previous server
///    instance left the kine bootstrap lock held. k3s loops forever on
///    "Bootstrap key already locked — waiting for data to be populated by
///    another server" every 5 s. The VM appears booted but k3s never becomes
///    ready.
///
/// Neither condition can be fixed inside the VM: k3s reads `state.db` before the
/// init script has any chance to intervene. The only reliable recovery is to
/// delete the file before boot and let k3s create a fresh one.
///
/// Since `state.db` contains only ephemeral single-node cluster state — all
/// Kubernetes objects are re-applied from the auto-deploy manifests in
/// `server/manifests/` on every cold start — removing it on every boot is safe.
///
/// **What is lost:** cluster object records (Pods, Deployments, etc.) and the
/// bootstrap token. Both are re-created from manifests on boot.
///
/// **What is preserved:** all container images and snapshots (under `k3s/agent/`),
/// PKI, and the `.initialized` sentinel.
///
/// This function is a no-op if `state.db` does not exist (e.g. first boot or
/// after a full `--reset`).
pub fn recover_stale_kine_db(rootfs: &Path) {
    let db_path = rootfs.join("var/lib/rancher/k3s/server/db/state.db");
    if !db_path.exists() {
        return; // Nothing to check.
    }

    // The SQLite file format begins with a 16-byte magic string.
    // Reference: https://www.sqlite.org/fileformat.html#the_database_header
    const SQLITE_MAGIC: &[u8] = b"SQLite format 3\x00";

    let corrupt = match fs::read(&db_path) {
        Err(_) => true,                         // Can't read → treat as corrupt.
        Ok(bytes) if bytes.len() < 100 => true, // Too short to be a valid DB.
        Ok(bytes) => !bytes.starts_with(SQLITE_MAGIC),
    };

    if corrupt {
        eprintln!(
            "Warning: kine database is corrupt ({}), removing for clean boot",
            db_path.display()
        );
        if let Err(e) = fs::remove_file(&db_path) {
            eprintln!("Warning: failed to remove corrupt kine database: {e}");
        }
        // Also remove any WAL/SHM sidecar files left by the interrupted write.
        let _ = fs::remove_file(db_path.with_extension("db-wal"));
        let _ = fs::remove_file(db_path.with_extension("db-shm"));
        return;
    }

    // The file has a valid SQLite header. Even a structurally intact DB can
    // cause k3s to hang forever with "Bootstrap key already locked — waiting
    // for data to be populated by another server". This is a kine application-
    // level lock: when a k3s server starts, kine marks bootstrap as "in
    // progress"; if that server is killed before it finishes, the lock row
    // persists and no subsequent server can complete bootstrap.
    //
    // There is no reliable way to detect this condition without executing
    // SQLite queries (which would require a dependency). However, `state.db`
    // contains only ephemeral cluster state for this single-node VM — all
    // Kubernetes objects are re-created from the auto-deploy manifests in
    // `server/manifests/` on every cold start. Removing the DB on every boot
    // is therefore safe and guarantees a clean bootstrap every time, at the
    // cost of ~1-2s extra startup time for k3s to recreate the schema.
    //
    // The DB is NOT removed under --reset (reset_runtime_state wipes the
    // entire k3s/server/ tree, which is a superset of this operation).
    eprintln!(
        "Removing stale kine database for clean boot ({})",
        db_path.display()
    );
    if let Err(e) = fs::remove_file(&db_path) {
        eprintln!("Warning: failed to remove kine database: {e}");
    }
    let _ = fs::remove_file(db_path.with_extension("db-wal"));
    let _ = fs::remove_file(db_path.with_extension("db-shm"));
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
