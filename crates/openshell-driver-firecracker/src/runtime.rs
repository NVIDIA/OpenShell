// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Small standalone Firecracker launcher owned by this driver crate.

#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;
use serde_json::{Value, json};

const API_START_TIMEOUT: Duration = Duration::from_secs(5);
const API_IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_API_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct FirecrackerLaunchConfig {
    pub firecracker_binary: PathBuf,
    pub kernel_image: PathBuf,
    pub root_disk: PathBuf,
    pub run_dir: PathBuf,
    pub console_output: PathBuf,
    pub guest_init: String,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub vsock_cid: u32,
}

/// A configured Firecracker child. Dropping it terminates the VMM.
pub struct FirecrackerVm {
    child: Child,
    api_socket: PathBuf,
    vsock_socket: PathBuf,
}

impl FirecrackerVm {
    pub fn launch(config: &FirecrackerLaunchConfig) -> Result<Self, String> {
        validate_config(config)?;
        check_kvm_access()?;
        std::fs::create_dir_all(&config.run_dir).map_err(|error| {
            format!(
                "create Firecracker run dir {}: {error}",
                config.run_dir.display()
            )
        })?;
        let api_socket = config.run_dir.join("firecracker-api.sock");
        let vsock_socket = config.run_dir.join("firecracker-vsock.sock");
        remove_stale_socket(&api_socket)?;
        remove_stale_socket(&vsock_socket)?;

        let console = File::create(&config.console_output).map_err(|error| {
            format!(
                "create Firecracker console log {}: {error}",
                config.console_output.display()
            )
        })?;
        let stderr = console
            .try_clone()
            .map_err(|error| format!("clone Firecracker console log: {error}"))?;
        let mut command = Command::new(&config.firecracker_binary);
        command
            .arg("--api-sock")
            .arg(&api_socket)
            .stdin(Stdio::null())
            .stdout(Stdio::from(console))
            .stderr(Stdio::from(stderr));
        unsafe {
            command.pre_exec(|| {
                nix::sys::prctl::set_pdeathsig(Signal::SIGKILL)
                    .map_err(|error| io::Error::other(format!("pdeathsig: {error}")))
            });
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("start Firecracker: {error}"))?;
        if let Err(error) = configure(&mut child, &api_socket, &vsock_socket, config) {
            terminate_child(&mut child);
            return Err(error);
        }
        Ok(Self {
            child,
            api_socket,
            vsock_socket,
        })
    }

    pub fn vsock_uds_path(&self) -> &Path {
        &self.vsock_socket
    }

    pub fn wait(&mut self) -> Result<ExitStatus, String> {
        self.child
            .wait()
            .map_err(|error| format!("wait for Firecracker: {error}"))
    }

    pub fn terminate(&mut self) -> Result<(), String> {
        terminate_child(&mut self.child);
        Ok(())
    }
}

impl Drop for FirecrackerVm {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            terminate_child(&mut self.child);
        }
        let _ = std::fs::remove_file(&self.api_socket);
        let _ = std::fs::remove_file(&self.vsock_socket);
    }
}

fn validate_config(config: &FirecrackerLaunchConfig) -> Result<(), String> {
    for (label, path) in [
        ("Firecracker binary", &config.firecracker_binary),
        ("kernel image", &config.kernel_image),
        ("root disk", &config.root_disk),
    ] {
        if !path.is_file() {
            return Err(format!("{label} not found: {}", path.display()));
        }
    }
    if config.vcpus == 0 {
        return Err("Firecracker vCPU count must be nonzero".to_string());
    }
    if config.mem_mib < 128 {
        return Err("Firecracker memory must be at least 128 MiB".to_string());
    }
    if config.vsock_cid < 3 {
        return Err("Firecracker guest CID must be at least 3".to_string());
    }
    if !config.guest_init.starts_with('/') {
        return Err("Firecracker guest init path must be absolute".to_string());
    }
    Ok(())
}

fn check_kvm_access() -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map(|_| ())
        .map_err(|error| {
            format!(
                "open /dev/kvm read/write: {error}; start a login session whose supplementary groups include kvm"
            )
        })
}

fn configure(
    child: &mut Child,
    api_socket: &Path,
    vsock_socket: &Path,
    config: &FirecrackerLaunchConfig,
) -> Result<(), String> {
    wait_for_api_socket(child, api_socket)?;
    for request in configuration_requests(config, vsock_socket) {
        put_json(api_socket, request.path, &request.body)?;
    }
    Ok(())
}

struct ApiRequest {
    path: &'static str,
    body: Value,
}

fn configuration_requests(
    config: &FirecrackerLaunchConfig,
    vsock_socket: &Path,
) -> Vec<ApiRequest> {
    vec![
        ApiRequest {
            path: "/machine-config",
            body: json!({
                "vcpu_count": config.vcpus,
                "mem_size_mib": config.mem_mib,
                "smt": false
            }),
        },
        ApiRequest {
            path: "/boot-source",
            body: json!({
                "kernel_image_path": config.kernel_image,
                "boot_args": kernel_command_line(&config.guest_init)
            }),
        },
        ApiRequest {
            path: "/drives/rootfs",
            body: json!({
                "drive_id": "rootfs",
                "path_on_host": config.root_disk,
                "is_root_device": true,
                "is_read_only": false
            }),
        },
        ApiRequest {
            path: "/vsock",
            body: json!({
                "guest_cid": config.vsock_cid,
                "uds_path": vsock_socket
            }),
        },
        ApiRequest {
            path: "/actions",
            body: json!({ "action_type": "InstanceStart" }),
        },
    ]
}

fn kernel_command_line(init: &str) -> String {
    format!("console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init={init}")
}

fn wait_for_api_socket(child: &mut Child, socket: &Path) -> Result<(), String> {
    let deadline = Instant::now() + API_START_TIMEOUT;
    loop {
        if UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("check Firecracker process: {error}"))?
        {
            return Err(format!(
                "Firecracker exited before its API socket was ready: {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for Firecracker API socket {}",
                socket.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn put_json(socket: &Path, path: &str, body: &Value) -> Result<(), String> {
    let body = serde_json::to_vec(body).map_err(|error| format!("encode {path}: {error}"))?;
    let mut stream = UnixStream::connect(socket)
        .map_err(|error| format!("connect to Firecracker API {}: {error}", socket.display()))?;
    stream
        .set_read_timeout(Some(API_IO_TIMEOUT))
        .map_err(|error| format!("set API read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(API_IO_TIMEOUT))
        .map_err(|error| format!("set API write timeout: {error}"))?;
    write!(
        stream,
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .and_then(|()| stream.write_all(&body))
    .map_err(|error| format!("write Firecracker API request {path}: {error}"))?;
    let response = read_http_response(&mut stream, path)?;
    check_http_status(path, &response)
}

fn read_http_response(stream: &mut UnixStream, path: &str) -> Result<Vec<u8>, String> {
    let mut response = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 4096];
    loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|error| format!("read Firecracker API response {path}: {error}"))?;
        if count == 0 {
            return if response.is_empty() {
                Err(format!("empty Firecracker API response for {path}"))
            } else {
                Ok(response)
            };
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > MAX_API_RESPONSE_BYTES {
            return Err(format!(
                "Firecracker API response for {path} exceeds {MAX_API_RESPONSE_BYTES} bytes"
            ));
        }
        let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let body_start = header_end + 4;
        let headers = String::from_utf8_lossy(&response[..header_end]);
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        });
        match content_length {
            Some(length) if response.len() >= body_start + length => {
                response.truncate(body_start + length);
                return Ok(response);
            }
            Some(_) => {}
            None => return Ok(response),
        }
    }
}

fn check_http_status(path: &str, response: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(response);
    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| format!("empty Firecracker API response for {path}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| format!("invalid Firecracker API response for {path}: {status_line}"))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        Err(format!(
            "Firecracker API request {path} failed with status {status}: {}",
            body.trim()
        ))
    }
}

fn remove_stale_socket(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove stale socket {}: {error}", path.display())),
    }
}

fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FirecrackerLaunchConfig {
        FirecrackerLaunchConfig {
            firecracker_binary: PathBuf::from("/firecracker"),
            kernel_image: PathBuf::from("/vmlinux"),
            root_disk: PathBuf::from("/root.ext4"),
            run_dir: PathBuf::from("/run/firecracker"),
            console_output: PathBuf::from("/run/firecracker/console.log"),
            guest_init: "/opt/openshell/bin/openshell-driver-firecracker".to_string(),
            vcpus: 2,
            mem_mib: 512,
            vsock_cid: 4,
        }
    }

    #[test]
    fn configures_no_network_device() {
        let config = config();
        let requests = configuration_requests(&config, Path::new("/tmp/vsock.sock"));
        let paths = requests
            .iter()
            .map(|request| request.path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "/machine-config",
                "/boot-source",
                "/drives/rootfs",
                "/vsock",
                "/actions"
            ]
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.path == "/network-interfaces")
        );
        assert_eq!(requests[2].body["is_read_only"], false);
    }

    #[test]
    fn boot_source_uses_driver_as_init() {
        let command_line = kernel_command_line("/opt/openshell/bin/openshell-driver-firecracker");
        assert!(command_line.contains("root=/dev/vda rw"));
        assert!(command_line.contains("init=/opt/openshell/bin/openshell-driver-firecracker"));
    }

    #[test]
    fn accepts_only_successful_api_statuses() {
        assert!(check_http_status("/actions", b"HTTP/1.1 204 No Content\r\n\r\n").is_ok());
        assert!(check_http_status("/actions", b"HTTP/1.1 400 Bad\r\n\r\nnope").is_err());
    }
}
