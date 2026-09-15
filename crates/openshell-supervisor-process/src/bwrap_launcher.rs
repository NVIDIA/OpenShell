// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Experimental fixed-function Bubblewrap launcher.
//!
//! The supervisor starts this helper before installing its inherited seccomp
//! prelude. Callers submit Python source, never commands, paths, mount options,
//! or environment variables. Bubblewrap builds the namespace and a second
//! `OpenShell` invocation installs the final Landlock/seccomp policy before
//! executing `CPython`.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
pub const BWRAP_LAUNCHER_SUBCOMMAND: &str = "experimental-bwrap-launcher";
pub const BWRAP_CHILD_SUBCOMMAND: &str = "experimental-bwrap-child";
pub const SOCKET_PATH: &str = "/tmp/openshell-bwrap-launcher.sock";
const MAX_REQUEST_BYTES: u64 = 256 * 1024;
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const SCRATCH_BYTES: &str = "16777216";
const RUN_TIMEOUT_SECONDS: u64 = 5;

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
pub fn spawn_if_enabled() -> Result<Option<LauncherGuard>> {
    if std::env::var(ENABLE_ENV).as_deref() != Ok("1") {
        return Ok(None);
    }
    if unsafe { libc::geteuid() } == 0 {
        return Err(miette::miette!(
            "experimental Bubblewrap launcher refuses to run as root"
        ));
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
    let mut child = Command::new(executable)
        .arg(BWRAP_LAUNCHER_SUBCOMMAND)
        .arg(&socket)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
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

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let _ = serve_connection(stream);
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

fn handle_request(stream: &UnixStream) -> Result<Value> {
    let request = read_request(stream)?;
    let request: Value = serde_json::from_slice(&request).into_diagnostic()?;
    if request.as_object().is_none_or(|fields| fields.len() != 2)
        || request.get("protocol_version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION)
    {
        return Err(miette::miette!(
            "request requires protocol_version 1 and only the code field"
        ));
    }
    let code = request
        .get("code")
        .and_then(Value::as_str)
        .ok_or_else(|| miette::miette!("request must contain a string code field"))?;

    let run = tempfile::Builder::new()
        .prefix("openshell-code-")
        .tempdir_in("/tmp")
        .into_diagnostic()?;
    let program = run.path().join("program.py");
    let stdout_path = run.path().join("stdout");
    let stderr_path = run.path().join("stderr");
    fs::write(&program, code).into_diagnostic()?;

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
        .args(["--ro-bind"])
        .arg(&executable)
        .arg("/openshell-sandbox")
        .args([
            "--chdir",
            "/work",
            "/openshell-sandbox",
            BWRAP_CHILD_SUBCOMMAND,
        ])
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
        "protocol_version": PROTOCOL_VERSION,
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

pub fn run_hardened_child() -> Result<()> {
    apply_resource_limits()?;
    // Install before the normal policy, which blocks further seccomp changes.
    // One Python process makes address-space and CPU limits per-run bounds.
    apply_single_process_limit()?;
    let policy = SandboxPolicy {
        version: 1,
        filesystem: FilesystemPolicy {
            include_workdir: false,
            read_only: ["/usr", "/app/.venv", "/work/program.py", "/dev/urandom"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            read_write: ["/tmp", "/work/output", "/dev/null"]
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
        (libc::RLIMIT_FSIZE, MAX_OUTPUT_BYTES, MAX_OUTPUT_BYTES),
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
    fn rejects_requests_that_select_launcher_options() {
        for request in [
            json!({"protocol_version": 2, "code": "print(1)"}),
            json!({"protocol_version": 1, "code": "print(1)", "env": {}}),
            json!({"protocol_version": 1, "code": "print(1)", "mounts": []}),
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
    fn bounds_output_reads() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("stdout");
        let limit = usize::try_from(MAX_OUTPUT_BYTES).unwrap();
        fs::write(&output, vec![b'x'; limit + 1024]).unwrap();
        assert_eq!(read_bounded(&output).unwrap().len(), limit);
    }
}
