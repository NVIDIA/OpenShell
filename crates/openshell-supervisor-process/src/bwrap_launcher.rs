// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental fixed-function Bubblewrap launcher.
//!
//! The supervisor starts this helper before installing its inherited seccomp
//! prelude. Protocols 1/2 accept Python source. Protocol 3 accepts shell commands
//! with fixed computer mounts; no protocol accepts mount options or environment
//! variables. Protocol 2 may name the agent's own files directory:
//! the launcher shows it read-only at `/files` and its `code` subdirectory
//! read-write at `/files/code`, nothing else. Bubblewrap builds the namespace
//! and a second `OpenShell` invocation installs the final Landlock/seccomp
//! policy before executing `CPython`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use miette::{Context as _, IntoDiagnostic, Result};
use openshell_core::policy::{
    FilesystemPolicy, LandlockCompatibility, LandlockPolicy, NetworkMode, NetworkPolicy,
    ProcessPolicy, SandboxPolicy,
};
use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
use serde_json::{Value, json};

const ENABLE_ENV: &str = "OPENSHELL_EXPERIMENTAL_BWRAP_LAUNCHER";
const PROTOCOL_VERSION: u64 = 1;
const FILES_PROTOCOL_VERSION: u64 = 2;
const SHELL_PROTOCOL_VERSION: u64 = 3;
const SHELL_TIMEOUT_SECONDS: u64 = 900;
const MAX_CONNECTIONS: usize = 4;
pub const BWRAP_LAUNCHER_SUBCOMMAND: &str = "experimental-bwrap-launcher";
pub const BWRAP_CHILD_SUBCOMMAND: &str = "experimental-bwrap-child";
pub const SOCKET_PATH: &str = "/tmp/openshell-bwrap-launcher.sock";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SCRATCH_BYTES: &str = "16777216";
const RUN_TIMEOUT_SECONDS: u64 = 5;
const FILES_MOUNT: &str = "/files";
const CODE_FILES_MOUNT: &str = "/files/code";
const CHILD_FILES_FLAG: &str = "--files";

pub struct LauncherGuard {
    child: Child,
    socket: PathBuf,
}

impl Drop for LauncherGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.socket);
    }
}

#[allow(unsafe_code)]
pub fn spawn_if_enabled(
    policy: &SandboxPolicy,
    identity: crate::process::ResolvedProcessIdentity,
) -> Result<Option<LauncherGuard>> {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
        return Ok(None);
    }
    let (uid, gid, _) = crate::process::resolve_filesystem_identity(policy, identity)?;
    let uid = uid.unwrap_or_else(nix::unistd::geteuid).as_raw();
    let gid = gid.unwrap_or_else(nix::unistd::getegid).as_raw();
    if uid == 0 || gid == 0 {
        return Err(miette::miette!(
            "experimental Bubblewrap launcher requires a resolved non-root UID and GID"
        ));
    }

    // A full parent procfs permits a fresh proc mount in the nested PID
    // namespace. Docker's masked /proc alone cannot satisfy that kernel check.
    if let Err(error) = prepare_full_proc() {
        // Preserve protocols 1/2 on containers without mount privileges. A
        // protocol-3 proc mount still fails closed inside Bubblewrap there.
        tracing::warn!(%error, "full-shell procfs preparation unavailable");
    }

    let socket = PathBuf::from(SOCKET_PATH);
    match fs::symlink_metadata(&socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(&socket).into_diagnostic()?;
        }
        Ok(_) => {
            return Err(miette::miette!(
                "refusing non-socket Bubblewrap launcher path {}",
                socket.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).into_diagnostic(),
    }

    let executable = std::env::current_exe().into_diagnostic()?;
    let mut command = Command::new(executable);
    command
        .arg(BWRAP_LAUNCHER_SUBCOMMAND)
        .arg(&socket)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    configure_launcher_identity(&mut command, uid, gid);
    let mut child = command
        .spawn()
        .into_diagnostic()
        .wrap_err("failed to start experimental Bubblewrap launcher")?;

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().into_diagnostic()? {
            return Err(miette::miette!(
                "experimental Bubblewrap launcher exited before readiness: {status}"
            ));
        }
        if UnixStream::connect(&socket).is_ok() {
            return Ok(Some(LauncherGuard { child, socket }));
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut guard = LauncherGuard { child, socket };
    let _ = guard.child.kill();
    Err(miette::miette!(
        "experimental Bubblewrap launcher socket did not become ready"
    ))
}

/// Only the freshly forked helper loses privileges; supervisor setup keeps its
/// existing identity. No allocation or identity lookup occurs after fork.
#[allow(unsafe_code)]
fn configure_launcher_identity(command: &mut Command, uid: u32, gid: u32) {
    unsafe {
        command.pre_exec(move || {
            if libc::geteuid() == 0 {
                capctl::caps::bounding::clear()
                    .map_err(|error| std::io::Error::from_raw_os_error(error.code()))?;
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::geteuid() != uid || libc::getegid() != gid {
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            capctl::caps::CapState::empty()
                .set_current()
                .map_err(|error| std::io::Error::from_raw_os_error(error.code()))?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[allow(unsafe_code)]
pub fn serve(socket: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(miette::miette!(
            "Bubblewrap launcher refuses to run as root"
        ));
    }
    let rc = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    // Other same-UID workload processes must not inspect launcher memory.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    let listener = UnixListener::bind(socket)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind {}", socket.display()))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).into_diagnostic()?;

    let active = Arc::new(AtomicUsize::new(0));
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if active
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                        (count < MAX_CONNECTIONS).then_some(count + 1)
                    })
                    .is_err()
                {
                    continue;
                }
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    struct ConnectionGuard(Arc<AtomicUsize>);
                    impl Drop for ConnectionGuard {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::Release);
                        }
                    }
                    let _guard = ConnectionGuard(active);
                    let _ = serve_connection(stream);
                });
            }
            Err(error) => return Err(error).into_diagnostic(),
        }
    }
    Ok(())
}

fn serve_connection(mut stream: UnixStream) -> Result<()> {
    verify_peer(&stream)?;
    let response = handle_request(&stream).unwrap_or_else(|error| {
        json!({"protocol_version": PROTOCOL_VERSION, "status":"launcher_error", "error": error.to_string()})
    });
    let mut bytes = serde_json::to_vec(&response).into_diagnostic()?;
    bytes.push(b'\n');
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| miette::miette!("launcher response deadline exceeded"))?;
        stream
            .set_write_timeout(Some(remaining))
            .into_diagnostic()?;
        let written = stream.write(&bytes[offset..]).into_diagnostic()?;
        if written == 0 {
            return Err(miette::miette!("launcher response connection closed"));
        }
        offset += written;
    }
    Ok(())
}

#[allow(unsafe_code)]
fn verify_peer(stream: &UnixStream) -> Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = libc::socklen_t::try_from(size_of::<libc::ucred>()).into_diagnostic()?;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &raw mut length,
        )
    };
    if rc != 0 || credentials.uid != unsafe { libc::geteuid() } {
        return Err(miette::miette!(
            "Bubblewrap launcher peer is not the owning user"
        ));
    }
    Ok(())
}

struct RunRequest {
    version: u64,
    code: String,
    files: Option<AgentFiles>,
}

struct AgentFiles {
    root: PathBuf,
    code: PathBuf,
}

/// Protocol 1 is exactly `{protocol_version, code}`; protocol 2 adds only `files_root`.
fn parse_request(request: &Value) -> Result<RunRequest> {
    let fields = request
        .as_object()
        .ok_or_else(|| miette::miette!("request must be a JSON object"))?;
    let version = request.get("protocol_version").and_then(Value::as_u64);
    let expected = match version {
        Some(PROTOCOL_VERSION) => 2,
        Some(FILES_PROTOCOL_VERSION) => 3,
        _ => 0,
    };
    if fields.len() != expected || (expected == 3 && !fields.contains_key("files_root")) {
        return Err(miette::miette!(
            "request requires protocol_version 1 with only code, or 2 with code and files_root"
        ));
    }
    let code = request
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| miette::miette!("request must contain a string code field"))?;
    let files = match request.get("files_root") {
        None => None,
        Some(root) => {
            Some(prepare_agent_files(root.as_str().ok_or_else(|| {
                miette::miette!("files_root must be a string")
            })?)?)
        }
    };
    Ok(RunRequest {
        version: version.unwrap_or(PROTOCOL_VERSION),
        code: code.to_owned(),
        files,
    })
}

/// Accept only a canonical directory the launcher's own user owns and nobody else can
/// write, so code sees the caller's files and never a path the caller could not use.
fn prepare_agent_files(root: &str) -> Result<AgentFiles> {
    let root = Path::new(root);
    if !root.is_absolute() || root.components().count() < 3 {
        return Err(miette::miette!(
            "files_root must be an absolute agent directory"
        ));
    }
    if fs::canonicalize(root).into_diagnostic()? != root {
        return Err(miette::miette!("files_root must be a canonical path"));
    }
    check_owned_directory(root)?;
    let code = root.join("code");
    match fs::symlink_metadata(&code) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&code)
                .into_diagnostic()?;
        }
        Err(error) => return Err(error).into_diagnostic(),
        Ok(_) => {}
    }
    check_owned_directory(&code)?;
    Ok(AgentFiles {
        root: root.to_path_buf(),
        code,
    })
}

#[allow(unsafe_code)]
fn check_owned_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).into_diagnostic()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(miette::miette!(
            "agent files must be a directory owned and writable only by the launcher user"
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn prepare_full_proc() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let path = Path::new("/run/openshell-bwrap-proc");
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .into_diagnostic()?;
    }
    check_owned_directory(path)?;
    if fs::symlink_metadata(path).into_diagnostic()?.mode() & 0o077 != 0 {
        return Err(miette::miette!(
            "supervisor procfs directory must be root-only"
        ));
    }
    if fs::canonicalize(path).into_diagnostic()? != path {
        return Err(miette::miette!("supervisor procfs path must be canonical"));
    }
    // This root-only mount lives for the sandbox's mount namespace lifetime.
    // It is never visible in the jail and cannot be unmounted after seccomp.
    let rc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/run/openshell-bwrap-proc".as_ptr(),
            c"proc".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .into_diagnostic()
            .wrap_err("failed to prepare full supervisor procfs");
    }
    Ok(())
}

struct ShellRequest {
    command: String,
    root: PathBuf,
    socket: PathBuf,
    scratch: PathBuf,
    cwd: PathBuf,
    timeout: Duration,
}

fn parse_shell_request(request: &Value) -> Result<ShellRequest> {
    use std::path::Component;
    let fields = request
        .as_object()
        .ok_or_else(|| miette::miette!("request must be an object"))?;
    let keys = [
        "protocol_version",
        "command",
        "agent_root",
        "turn_socket",
        "cwd",
        "timeout_seconds",
    ];
    if fields.len() != keys.len()
        || !keys.iter().all(|key| fields.contains_key(*key))
        || request["protocol_version"].as_u64() != Some(SHELL_PROTOCOL_VERSION)
    {
        return Err(miette::miette!(
            "protocol 3 requires only command, agent_root, turn_socket, cwd and timeout_seconds"
        ));
    }
    let string = |key: &str| -> Result<&str> {
        request[key]
            .as_str()
            .filter(|value| !value.contains('\0'))
            .ok_or_else(|| miette::miette!("{key} must be a string without NUL bytes"))
    };
    let root = PathBuf::from(string("agent_root")?);
    if !root.is_absolute()
        || root.components().count() < 3
        || fs::canonicalize(&root).into_diagnostic()? != root
    {
        return Err(miette::miette!(
            "agent_root must be a canonical absolute agent directory"
        ));
    }
    check_owned_directory(&root)?;
    if fs::symlink_metadata(&root).into_diagnostic()?.mode() & 0o077 != 0 {
        return Err(miette::miette!(
            "agent_root must be private to the launcher user"
        ));
    }
    for folder in [
        "workspace",
        "agent",
        "skills",
        "memory",
        "run",
        "run/turns",
        "run/scratch",
    ] {
        check_owned_directory(&root.join(folder))?;
    }
    let socket = PathBuf::from(string("turn_socket")?);
    if socket.parent() != Some(root.join("run/turns").as_path())
        || fs::canonicalize(&socket).into_diagnostic()? != socket
    {
        return Err(miette::miette!(
            "turn_socket must be directly under the agent's run/turns directory"
        ));
    }
    let metadata = fs::symlink_metadata(&socket).into_diagnostic()?;
    #[allow(unsafe_code)]
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(miette::miette!(
            "turn_socket must be a private socket owned by the launcher user"
        ));
    }
    if socket.extension().and_then(|value| value.to_str()) != Some("sock") {
        return Err(miette::miette!("turn_socket must have a .sock suffix"));
    }
    let scratch = root.join("run/scratch").join(socket.file_stem().unwrap());
    check_owned_directory(&scratch)?;
    let cwd = Path::new(string("cwd")?);
    let parts: Vec<_> = cwd.components().collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(miette::miette!(
            "cwd must be relative without parent traversal"
        ));
    }
    let first = parts[0].as_os_str();
    let source = match first.to_str() {
        Some("files") => root.join("workspace"),
        Some("agent") => root.join("agent"),
        Some("tmp") => scratch.clone(),
        _ => {
            return Err(miette::miette!(
                "cwd must resolve inside files, agent or tmp"
            ));
        }
    };
    let source = source.join(parts.iter().skip(1).collect::<PathBuf>());
    check_owned_directory(&source)?;
    if fs::canonicalize(&source).into_diagnostic()? != source {
        return Err(miette::miette!("cwd must not traverse a symlink"));
    }
    let timeout = request["timeout_seconds"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or_else(|| miette::miette!("timeout_seconds must be a positive integer"))?;
    Ok(ShellRequest {
        command: string("command")?.to_owned(),
        root,
        socket,
        scratch,
        cwd: Path::new("/").join(cwd),
        timeout: Duration::from_secs(timeout.min(SHELL_TIMEOUT_SECONDS)),
    })
}

fn capped_output(mut input: impl Read) -> Result<(String, bool)> {
    let mut bytes = Vec::new();
    let limit = usize::try_from(MAX_OUTPUT_BYTES).into_diagnostic()?;
    let mut buffer = [0; 8192];
    let mut truncated = false;
    loop {
        let count = input.read(&mut buffer).into_diagnostic()?;
        if count == 0 {
            break;
        }
        let retain = count.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..retain]);
        truncated |= retain < count;
    }
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

fn run_shell(request: ShellRequest) -> Result<Value> {
    let mut command = Command::new("/usr/bin/bwrap");
    command.args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/agent",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "LD_LIBRARY_PATH",
        "/usr/local/lib",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/etc",
        "--dev",
        "/dev",
        "--size",
        "268435456",
        "--tmpfs",
        "/dev/shm",
        "--proc",
        "/proc",
    ]);
    for path in [
        "/etc/ld.so.cache",
        "/etc/fonts",
        "/etc/alternatives",
        "/etc/libreoffice",
        "/etc/xdg",
        "/etc/passwd",
        "/etc/group",
        "/etc/nsswitch.conf",
        "/etc/mime.types",
    ] {
        command.args(["--ro-bind-try", path, path]);
    }
    for (source, target, writable) in [
        (request.root.join("workspace"), "/files", true),
        (request.root.join("agent"), "/agent", true),
        (request.root.join("skills"), "/skills", false),
        (request.root.join("memory"), "/memory", false),
        (request.scratch, "/tmp", true),
        (request.socket, "/run/tools.sock", true),
    ] {
        command
            .arg(if writable { "--bind" } else { "--ro-bind" })
            .arg(source)
            .arg(target);
    }
    command
        .arg("--ro-bind")
        .arg(std::env::current_exe().into_diagnostic()?)
        .arg("/openshell-sandbox")
        .arg("--chdir")
        .arg(request.cwd)
        .args(["/openshell-sandbox", BWRAP_CHILD_SUBCOMMAND, "--shell"])
        .arg(request.command)
        .env_clear()
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().into_diagnostic()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout = thread::spawn(move || capped_output(stdout));
    let stderr = thread::spawn(move || capped_output(stderr));
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().into_diagnostic()? {
            break status;
        }
        if started.elapsed() >= request.timeout {
            timed_out = true;
            match nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(i32::try_from(child.id()).into_diagnostic()?),
                nix::sys::signal::Signal::SIGKILL,
            ) {
                Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                Err(error) => return Err(error).into_diagnostic(),
            }
            break child.wait().into_diagnostic()?;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stdout_truncated) = stdout
        .join()
        .map_err(|_| miette::miette!("stdout reader failed"))??;
    let (stderr, stderr_truncated) = stderr
        .join()
        .map_err(|_| miette::miette!("stderr reader failed"))??;
    Ok(json!({"protocol_version": SHELL_PROTOCOL_VERSION,
        "status": if timed_out { "timed_out" } else if status.success() { "succeeded" } else { "failed" },
        "exit_code": status.code(), "stdout": stdout, "stderr": stderr,
        "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated,
        "duration_ms": started.elapsed().as_millis(), "timed_out": timed_out }))
}

#[allow(unsafe_code)]
fn run_shell_child(command: &str) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 4096,
        rlim_max: 4096,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raw const limit) } != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    fs::write("/proc/self/oom_score_adj", "1000").into_diagnostic()?;
    let policy = SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            include_workdir: false,
            read_only: [
                "/usr",
                "/etc",
                "/skills",
                "/memory",
                "/proc",
                "/dev/urandom",
                "/dev/random",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            read_write: [
                "/files",
                "/agent",
                "/tmp",
                "/dev/shm",
                "/dev/null",
                "/dev/zero",
                "/dev/pts",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
        },
        landlock: LandlockPolicy {
            compatibility: LandlockCompatibility::HardRequirement,
        },
        network: NetworkPolicy {
            mode: NetworkMode::Block,
            proxy: None,
        },
        process: ProcessPolicy::default(),
    };
    crate::sandbox::apply(&policy, None)?;
    // Bubblewrap's cleared environment contains only the fixed values above.
    let error = Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-c", command])
        .exec();
    Err(error).into_diagnostic()
}

fn handle_request(stream: &UnixStream) -> Result<Value> {
    let request = read_request(stream)?;
    let request: Value = serde_json::from_slice(&request).into_diagnostic()?;
    if request.get("protocol_version").and_then(Value::as_u64) == Some(SHELL_PROTOCOL_VERSION) {
        return run_shell(parse_shell_request(&request)?);
    }
    run_code(request)
}

fn run_code(request: Value) -> Result<Value> {
    let RunRequest {
        version,
        code,
        files,
    } = parse_request(&request)?;

    let run = tempfile::Builder::new()
        .prefix("openshell-code-")
        .tempdir_in("/tmp")
        .into_diagnostic()?;
    let program = run.path().join("program.py");
    let stdout_path = run.path().join("stdout");
    let stderr_path = run.path().join("stderr");
    fs::write(&program, &code).into_diagnostic()?;

    let executable = std::env::current_exe().into_diagnostic()?;
    let stdout = File::create(&stdout_path).into_diagnostic()?;
    let stderr = File::create(&stderr_path).into_diagnostic()?;
    let started = Instant::now();
    let status = Command::new("/usr/bin/timeout")
        .args(["--signal=KILL", "--kill-after=1"])
        .arg(RUN_TIMEOUT_SECONDS.to_string())
        .arg("/usr/bin/bwrap")
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--setenv",
            "PATH",
            "/app/.venv/bin:/usr/bin",
            "--setenv",
            "LD_LIBRARY_PATH",
            "/usr/local/lib",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/app/.venv",
            "/app/.venv",
            "--symlink",
            "usr/bin",
            "/bin",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--dir",
            "/dev",
            "--ro-bind",
            "/dev/null",
            "/dev/null",
            "--ro-bind",
            "/dev/urandom",
            "/dev/urandom",
            "--size",
            SCRATCH_BYTES,
            "--tmpfs",
            "/tmp",
            "--dir",
            "/work",
            "--ro-bind",
        ])
        .arg(&program)
        .arg("/work/program.py")
        .args(["--size", SCRATCH_BYTES, "--tmpfs", "/work/output"])
        .args(files.as_ref().map_or_else(Vec::new, |files| {
            vec![
                "--ro-bind".into(),
                files.root.clone().into_os_string(),
                FILES_MOUNT.into(),
                "--bind".into(),
                files.code.clone().into_os_string(),
                CODE_FILES_MOUNT.into(),
            ]
        }))
        .args(["--ro-bind"])
        .arg(&executable)
        .arg("/openshell-sandbox")
        .args([
            "--chdir",
            "/work",
            "/openshell-sandbox",
            BWRAP_CHILD_SUBCOMMAND,
        ])
        .args(files.as_ref().map(|_| CHILD_FILES_FLAG))
        .env_clear()
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .status()
        .into_diagnostic()
        .wrap_err("failed to execute Bubblewrap")?;
    let timed_out =
        !status.success() && started.elapsed() >= Duration::from_secs(RUN_TIMEOUT_SECONDS);

    let stdout = read_bounded(&stdout_path)?;
    let stderr = read_bounded(&stderr_path)?;
    Ok(json!({
        "protocol_version": version,
        "status": if status.success() { "succeeded" } else if timed_out { "timed_out" } else { "failed" },
        "exit_code": status.code(),
        "stdout": stdout,
        "stderr": stderr,
        "artifacts": [],
    }))
}

fn read_request(mut stream: &UnixStream) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| miette::miette!("launcher request deadline exceeded"))?;
        stream.set_read_timeout(Some(remaining)).into_diagnostic()?;
        let count = stream.read(&mut buffer).into_diagnostic()?;
        if count == 0 {
            return Err(miette::miette!("incomplete launcher request"));
        }
        let newline = buffer[..count].iter().position(|byte| *byte == b'\n');
        request.extend_from_slice(&buffer[..newline.map_or(count, |offset| offset + 1)]);
        if request.len() as u64 > MAX_REQUEST_BYTES {
            return Err(miette::miette!(
                "code request exceeds {MAX_REQUEST_BYTES} bytes"
            ));
        }
        if newline.is_some() {
            return Ok(request);
        }
    }
}

fn read_bounded(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .into_diagnostic()?
        .take(MAX_OUTPUT_BYTES)
        .read_to_end(&mut bytes)
        .into_diagnostic()?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn run_hardened_child(args: &[String]) -> Result<()> {
    if let [flag, command] = args
        && flag == "--shell"
    {
        return run_shell_child(command);
    }
    let files = match args {
        [] => false,
        [flag] if flag == CHILD_FILES_FLAG => true,
        _ => return Err(miette::miette!("unexpected Bubblewrap child arguments")),
    };
    apply_resource_limits()?;
    // Install before the normal policy, which blocks further seccomp changes.
    // One Python process makes address-space and CPU limits per-run bounds.
    apply_single_process_limit()?;
    let mut read_only = vec!["/usr", "/app/.venv", "/work/program.py", "/dev/urandom"];
    let mut read_write = vec!["/tmp", "/work/output", "/dev/null"];
    if files {
        read_only.push(FILES_MOUNT);
        read_write.push(CODE_FILES_MOUNT);
    }
    let policy = SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            include_workdir: false,
            read_only: read_only.into_iter().map(PathBuf::from).collect(),
            read_write: read_write.into_iter().map(PathBuf::from).collect(),
        },
        landlock: LandlockPolicy {
            compatibility: LandlockCompatibility::HardRequirement,
        },
        network: NetworkPolicy {
            mode: NetworkMode::Block,
            proxy: None,
        },
        process: ProcessPolicy::default(),
    };
    crate::sandbox::apply(&policy, None)?;

    let error = Command::new("/app/.venv/bin/python")
        .args(["-I", "-B", "-u", "/work/program.py"])
        .env_clear()
        .env("PATH", "/app/.venv/bin:/usr/bin")
        .env("LD_LIBRARY_PATH", "/usr/local/lib")
        .current_dir("/work")
        .exec();
    Err(error).into_diagnostic()
}

#[allow(unsafe_code)]
fn apply_single_process_limit() -> Result<()> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.entry(libc::SYS_clone).or_default();
    rules.entry(libc::SYS_clone3).or_default();
    #[cfg(target_arch = "x86_64")]
    for syscall in [libc::SYS_fork, libc::SYS_vfork] {
        rules.entry(syscall).or_default();
    }
    let arch = std::env::consts::ARCH.try_into().into_diagnostic()?;
    let filter: seccompiler::BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .into_diagnostic()?
    .try_into()
    .into_diagnostic()?;
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error()).into_diagnostic();
    }
    seccompiler::apply_filter(&filter).into_diagnostic()
}

#[allow(unsafe_code)]
fn apply_resource_limits() -> Result<()> {
    for (resource, soft, hard) in [
        (libc::RLIMIT_CPU, 3, 3),
        (libc::RLIMIT_FSIZE, MAX_FILE_BYTES, MAX_FILE_BYTES),
        (libc::RLIMIT_NOFILE, 64, 64),
        (libc::RLIMIT_NPROC, 64, 64),
        (libc::RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024),
    ] {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        if unsafe { libc::setrlimit(resource, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error())
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to set rlimit {resource}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    #[test]
    fn shell_requests_are_closed_and_cannot_select_mounts_or_escape_the_cwd() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for folder in [
            "workspace",
            "agent",
            "skills",
            "memory",
            "run",
            "run/turns",
            "run/scratch",
            "run/scratch/turn",
        ] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.path().join(folder))
                .unwrap();
        }
        let socket = root.path().join("run/turns/turn.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical = fs::canonicalize(root.path()).unwrap();
        let mut request = json!({"protocol_version":3, "command":"sleep 6; echo done",
            "agent_root":canonical, "turn_socket":socket, "cwd":"files", "timeout_seconds":10000});
        let parsed = parse_shell_request(&request).unwrap();
        assert_eq!(parsed.timeout, Duration::from_secs(900));
        assert_eq!(parsed.cwd, Path::new("/files"));
        request["timeout_seconds"] = json!(0);
        assert!(parse_shell_request(&request).is_err());
        request["timeout_seconds"] = json!(30);
        request["mounts"] = json!(["/"]);
        assert!(parse_shell_request(&request).is_err());
        request.as_object_mut().unwrap().remove("mounts");
        for cwd in ["/files", "files/../runtime", "skills", "runtime"] {
            request["cwd"] = json!(cwd);
            assert!(parse_shell_request(&request).is_err());
        }
        request["cwd"] = json!("files");
        std::os::unix::fs::symlink(
            root.path().join("agent"),
            root.path().join("workspace/link"),
        )
        .unwrap();
        request["cwd"] = json!("files/link");
        assert!(parse_shell_request(&request).is_err());
        request["cwd"] = json!("files");
        request["turn_socket"] = json!(root.path().join("run/turns/not-a-socket.sock"));
        fs::write(
            root.path().join("run/turns/not-a-socket.sock"),
            "not a socket",
        )
        .unwrap();
        assert!(parse_shell_request(&request).is_err());
        request["turn_socket"] = json!(socket);
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(parse_shell_request(&request).is_err());
    }

    #[test]
    fn launcher_child_uses_non_root_identity_without_capabilities() {
        let root = nix::unistd::geteuid().is_root();
        let uid = if root {
            10001
        } else {
            nix::unistd::geteuid().as_raw()
        };
        let gid = if root {
            10001
        } else {
            nix::unistd::getegid().as_raw()
        };
        let mut command = Command::new("/bin/cat");
        command.arg("/proc/self/status");
        configure_launcher_identity(&mut command, uid, gid);
        let output = command.output().unwrap();
        assert!(output.status.success());
        let status = String::from_utf8(output.stdout).unwrap();
        for (field, expected) in [
            ("Uid:", format!("{uid} {uid} {uid} {uid}")),
            ("Gid:", format!("{gid} {gid} {gid} {gid}")),
            ("CapInh:", "0000000000000000".to_string()),
            ("CapPrm:", "0000000000000000".to_string()),
            ("CapEff:", "0000000000000000".to_string()),
            ("CapAmb:", "0000000000000000".to_string()),
            ("NoNewPrivs:", "1".to_string()),
        ] {
            let value = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .unwrap();
            assert_eq!(
                value.split_whitespace().collect::<Vec<_>>().join(" "),
                expected
            );
        }
        if root {
            let bounding = status
                .lines()
                .find_map(|line| line.strip_prefix("CapBnd:"))
                .unwrap();
            assert_eq!(bounding.trim(), "0000000000000000");
            let groups = status
                .lines()
                .find_map(|line| line.strip_prefix("Groups:"))
                .unwrap();
            assert!(
                groups.trim().is_empty(),
                "root supplementary groups must be cleared"
            );
            assert!(
                nix::unistd::geteuid().is_root(),
                "the supervisor must retain its setup identity"
            );
        }
    }

    #[test]
    fn rejects_requests_that_select_launcher_options() {
        for request in [
            json!({"protocol_version": 2, "code": "print(1)"}),
            json!({"protocol_version": 3, "code": "print(1)"}),
            json!({"protocol_version": 1, "code": "print(1)", "env": {}}),
            json!({"protocol_version": 1, "code": "print(1)", "mounts": []}),
            json!({"protocol_version": 1, "code": "print(1)", "files_root": "/tmp/a/b"}),
            json!({"protocol_version": 2, "code": "print(1)", "mounts": []}),
            json!({"protocol_version": 2, "code": "print(1)", "files_root": 7}),
            json!({"protocol_version": 1, "command": ["/bin/sh"]}),
            json!({"protocol_version": 1, "code": 42}),
        ] {
            let (mut client, server) = UnixStream::pair().unwrap();
            writeln!(client, "{request}").unwrap();
            assert!(handle_request(&server).is_err());
        }
    }

    #[test]
    fn rejects_truncated_and_oversized_requests() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(b"{\"protocol_version\":1}").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(read_request(&server).is_err());

        let (mut client, server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            let _ = client.write_all(&vec![b'x'; usize::try_from(MAX_REQUEST_BYTES).unwrap() + 1]);
        });
        assert!(read_request(&server).is_err());
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn agent_files_must_be_a_canonical_private_directory_of_the_launcher_user() {
        let parent = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(parent.path()).unwrap().join("agent-files");
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let request = |path: &Path| json!({"protocol_version": 2, "code": "print(1)", "files_root": path.to_str().unwrap()});

        let parsed = parse_request(&request(&root)).unwrap();
        let files = parsed.files.unwrap();
        assert_eq!((parsed.version, files.root.as_path()), (2, root.as_path()));
        assert_eq!(files.code, root.join("code"));
        assert!(fs::symlink_metadata(&files.code).unwrap().is_dir());

        let linked = root.parent().unwrap().join("linked-files");
        std::os::unix::fs::symlink(&root, &linked).unwrap();
        assert!(parse_request(&request(&linked)).is_err());
        assert!(parse_request(&request(&root.join("..").join("agent-files"))).is_err());
        assert!(
            parse_request(&json!({"protocol_version": 2, "code": "", "files_root": "rel/a/b"}))
                .is_err()
        );
        assert!(
            parse_request(&json!({"protocol_version": 2, "code": "", "files_root": "/"})).is_err()
        );

        fs::remove_dir(root.join("code")).unwrap();
        std::os::unix::fs::symlink(parent.path(), root.join("code")).unwrap();
        assert!(parse_request(&request(&root)).is_err());

        fs::remove_file(root.join("code")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(parse_request(&request(&root)).is_err());
    }

    #[test]
    fn child_accepts_only_the_files_flag() {
        assert!(run_hardened_child(&["--mount".to_owned()]).is_err());
        assert!(run_hardened_child(&[CHILD_FILES_FLAG.to_owned(), "x".to_owned()]).is_err());
    }

    #[test]
    fn bounds_output_reads() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("stdout");
        let limit = usize::try_from(MAX_OUTPUT_BYTES).unwrap();
        fs::write(&output, vec![b'x'; limit + 1024]).unwrap();
        assert_eq!(read_bounded(&output).unwrap().len(), limit);
    }
}
