// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

pub fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 6] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("DENO_CERT", ca_cert_path),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path.clone()),
        // Ubuntu Noble's git links against libcurl-gnutls, which ignores SSL_CERT_FILE.
        // git reads GIT_SSL_CAINFO (or http.sslCAInfo) to locate the CA bundle.
        ("GIT_SSL_CAINFO", combined_bundle_path),
    ]
}

/// Shim materialized for this sandbox, or `None` when the kernel's seccomp
/// listener supports `WAIT_KILLABLE_RECV` and the broker can answer
/// `accept`/`accept4` directly.
#[cfg(target_os = "linux")]
static PRELOAD_SHIM: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Record the materialized shim path once, during sandbox startup.
#[cfg(target_os = "linux")]
pub fn set_preload_shim(path: Option<PathBuf>) {
    let _ = PRELOAD_SHIM.set(path);
}

/// Path of the materialized shim, if this sandbox installed one.
#[cfg(target_os = "linux")]
pub fn preload_shim() -> Option<&'static Path> {
    PRELOAD_SHIM.get()?.as_deref()
}

/// Build the `LD_PRELOAD` entry for a child, preserving any value the
/// workload asked for.
///
/// Children re-inherit this value when they spawn their own children, so the
/// composition must be idempotent rather than prepending on every exec.
#[cfg(any(target_os = "linux", test))]
pub fn preload_env_var(shim_path: &Path, inherited: Option<&str>) -> (&'static str, String) {
    (
        openshell_accept_shim::PRELOAD_ENV,
        openshell_accept_shim::compose_preload(&shim_path.display().to_string(), inherited),
    )
}

/// Compose after all child environment sources have been applied. Reading the
/// command's effective override preserves provider and per-session precedence.
pub fn apply_preload(command: &mut std::process::Command, inherit_environment: bool) {
    #[cfg(target_os = "linux")]
    if preload_shim().is_some() {
        apply_preload_for_child(command, inherit_environment);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (command, inherit_environment);
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_preload_for_child(
    command: &mut std::process::Command,
    inherit_environment: bool,
) {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    if !compatible_executable(command) {
        return;
    }
    let file = match openshell_accept_shim::create_child_shim() {
        Ok(file) => file,
        Err(error) => {
            openshell_ocsf::ocsf_emit!(
                openshell_ocsf::ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
                    .severity(openshell_ocsf::SeverityId::Medium)
                    .status(openshell_ocsf::StatusId::Failure)
                    .message(format!(
                        "Peer-address shim unavailable for child [error:{error}]"
                    ))
                    .build()
            );
            return;
        }
    };
    let path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    apply_preload_at(command, &path, inherit_environment);
    // CLOEXEC stays set in the shared parent fd table. Clear it only in this
    // forked child; other launches' pending objects close on its exec.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(any(target_os = "linux", test))]
fn compatible_executable(command: &std::process::Command) -> bool {
    // The shim is ELF64 for this runtime's architecture. Do not inject it
    // into a directly launched foreign ELF executable. Scripts and commands
    // resolved by a shell retain normal loader inheritance semantics.
    let program = command.get_program();
    let executable = if Path::new(program).components().count() > 1 {
        Some(
            command
                .get_current_dir()
                .unwrap_or_else(|| Path::new("."))
                .join(program),
        )
    } else {
        let path = command
            .get_envs()
            .find(|(key, _)| *key == "PATH")
            .and_then(|(_, value)| value.map(std::ffi::OsStr::to_os_string))
            .or_else(|| std::env::var_os("PATH"));
        path.and_then(|path| {
            std::env::split_paths(&path)
                .map(|directory| directory.join(program))
                .find(|path| path.is_file())
        })
    };
    if let Some(executable) = executable {
        let mut header = [0u8; 20];
        if read_executable_header(&executable, &mut header).is_ok()
            && &header[..4] == b"\x7fELF"
            && (header[4] != 2
                || header[5] != 1
                || u16::from_le_bytes([header[18], header[19]])
                    != if cfg!(target_arch = "aarch64") {
                        183
                    } else {
                        62
                    })
        {
            return false;
        }
    }
    true
}

#[cfg(any(target_os = "linux", test))]
fn read_executable_header(path: &Path, header: &mut [u8; 20]) -> std::io::Result<()> {
    use std::io::Read as _;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular executable",
        ));
    }
    file.read_exact(header)
}

#[cfg(any(target_os = "linux", test))]
fn apply_preload_at(command: &mut std::process::Command, shim: &Path, inherit_environment: bool) {
    let key = std::ffi::OsStr::new(openshell_accept_shim::PRELOAD_ENV);
    let inherited = match command.get_envs().find(|(name, _)| *name == key) {
        Some((_, value)) => value.map(|value| value.to_string_lossy().into_owned()),
        None if !inherit_environment => None,
        None => std::env::var(openshell_accept_shim::PRELOAD_ENV).ok(),
    };
    let (key, value) = preload_env_var(shim, inherited.as_deref());
    command.env(key, value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_launches_inherit_only_their_own_shim() {
        let script = r"
import os
objects = []
for name in os.listdir('/proc/self/fd'):
    try:
        if os.readlink('/proc/self/fd/' + name).startswith('/memfd:openshell-accept-shim'):
            objects.append(name)
    except FileNotFoundError:
        pass
assert len(objects) == 1, objects
os.chmod(os.environ['LD_PRELOAD'], 0)
print('isolated launch')
";
        let mut first = Command::new("python3");
        first.args(["-c", script]);
        apply_preload_for_child(&mut first, false);
        let mut second = Command::new("python3");
        second.args(["-c", script]);
        apply_preload_for_child(&mut second, false);
        let paths = [&first, &second].map(|command| {
            PathBuf::from(
                command
                    .get_envs()
                    .find(|(key, _)| *key == "LD_PRELOAD")
                    .unwrap()
                    .1
                    .unwrap(),
            )
        });
        for command in [&mut first, &mut second] {
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
            assert_eq!(output.stdout, b"isolated launch\n");
        }
        drop(first);
        drop(second);
        for path in paths {
            assert!(!path.exists(), "parent must release its descriptor");
        }
    }

    #[test]
    fn preload_composes_with_the_final_command_override() {
        let mut command = Command::new("/usr/bin/env");
        command.env("LD_PRELOAD", "/user.so");
        command.env("LD_PRELOAD", "/provider.so");
        apply_preload_at(&mut command, Path::new("/shim.so"), false);
        let preload = command
            .get_envs()
            .find(|(key, _)| *key == "LD_PRELOAD")
            .unwrap()
            .1
            .unwrap();
        assert_eq!(preload, "/shim.so:/provider.so");
    }

    #[test]
    fn foreign_elf_does_not_receive_the_shim() {
        use std::io::Write as _;
        let mut executable = tempfile::NamedTempFile::new().unwrap();
        let mut header = [0u8; 20];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 1; // ELFCLASS32
        header[5] = 1;
        executable.write_all(&header).unwrap();
        let command = Command::new(executable.path());
        assert!(!compatible_executable(&command));
    }

    #[cfg(unix)]
    #[test]
    fn executable_probe_does_not_wait_for_a_fifo_writer() {
        let directory = tempfile::tempdir().unwrap();
        let fifo = directory.path().join("program");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
        assert_eq!(
            read_executable_header(&fifo, &mut [0; 20])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn preload_env_var_keeps_a_workload_supplied_value() {
        let (key, value) = preload_env_var(Path::new("/run/openshell-compat/accept_shim.so"), None);
        assert_eq!(key, "LD_PRELOAD");
        assert_eq!(value, "/run/openshell-compat/accept_shim.so");

        let (_, value) = preload_env_var(
            Path::new("/run/openshell-compat/accept_shim.so"),
            Some("/opt/jemalloc.so"),
        );
        assert_eq!(
            value,
            "/run/openshell-compat/accept_shim.so:/opt/jemalloc.so"
        );
    }

    #[test]
    fn preload_env_var_does_not_grow_across_nested_spawns() {
        let shim = Path::new("/run/openshell-compat/accept_shim.so");
        let (_, first) = preload_env_var(shim, None);
        let (_, second) = preload_env_var(shim, Some(&first));
        assert_eq!(first, second);
    }

    #[test]
    fn apply_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        for (key, value) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("NODE_EXTRA_CA_CERTS=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("DENO_CERT=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("REQUESTS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("CURL_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("GIT_SSL_CAINFO=/etc/openshell-tls/ca-bundle.pem"));
    }
}
