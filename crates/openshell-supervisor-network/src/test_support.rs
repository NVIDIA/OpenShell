// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential, identity, socket-owner and request-tracing fixtures.

pub mod request_tracing;

pub fn response_request_id(response: &[u8]) -> &str {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete response headers");
    std::str::from_utf8(&response[..end])
        .expect("ASCII response headers")
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-openshell-request-id")
                .then(|| value.trim())
        })
        .expect("response carries a request receipt")
}

pub fn assert_http_request_records(
    events: &[serde_json::Value],
    expected_invocations: usize,
) -> (&serde_json::Value, Vec<&serde_json::Value>) {
    let (primary, invocations): (Vec<_>, Vec<_>) = events
        .iter()
        .filter(|event| event["class_uid"] == 4002)
        .partition(|event| event["unmapped"]["http_event_kind"] == "request");
    assert_eq!(primary.len(), 1, "{events:?}");
    assert_eq!(invocations.len(), expected_invocations, "{events:?}");
    assert!(
        invocations
            .iter()
            .all(|event| event["unmapped"]["http_event_kind"] == "middleware_invocation"),
        "unexpected HTTP Activity record: {events:?}"
    );
    (primary[0], invocations)
}

pub fn header_placement_metadata(
    keys: &[&str],
) -> std::collections::HashMap<String, openshell_core::proto::ProviderProfileCredential> {
    keys.iter()
        .map(|key| {
            (
                format!(
                    "{}{key}",
                    openshell_core::provider_credentials::STATIC_CREDENTIAL_METADATA_PREFIX
                ),
                openshell_core::proto::ProviderProfileCredential {
                    env_vars: vec![(*key).to_string()],
                    auth_style: "bearer".to_string(),
                    header_name: "Authorization".to_string(),
                    ..Default::default()
                },
            )
        })
        .collect()
}

#[cfg(target_os = "linux")]
use std::net::TcpStream;
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};

#[cfg(target_os = "linux")]
pub struct SocketHolder(pub Child);

#[cfg(target_os = "linux")]
impl Drop for SocketHolder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Keep a duplicate of the parent's connected socket in a descendant process.
/// Stdin transfers descriptor ownership through the standard process API.
#[cfg(target_os = "linux")]
pub fn spawn_socket_holder(stream: &TcpStream, exec_sleep: bool) -> SocketHolder {
    let mut command = if exec_sleep {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        command
    } else {
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "test_support::socket_holder_child",
                "--nocapture",
            ])
            .env("OPENSHELL_SOCKET_HOLDER_CHILD", "1");
        command
    };
    let fd = OwnedFd::from(stream.try_clone().expect("duplicate socket"));
    SocketHolder(
        command
            .stdin(Stdio::from(fd))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn socket holder"),
    )
}

#[cfg(target_os = "linux")]
#[test]
fn socket_holder_child() {
    if std::env::var_os("OPENSHELL_SOCKET_HOLDER_CHILD").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

use std::path::PathBuf;

/// Give rooted synthetic executable paths a drive on Windows. Preserve empty,
/// relative, and already native paths so invalid-identity tests remain useful.
pub fn executable_path(path: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    if path.starts_with('/') {
        return PathBuf::from(format!("C:{path}"));
    }
    PathBuf::from(path)
}

/// Match policy binary paths to the synthetic identities without changing HTTP
/// rule paths or other policy fields.
pub fn policy_with_native_executable_paths(data: &str) -> String {
    let mut policy: serde_yml::Value = serde_yml::from_str(data).expect("parse test policy");
    if let Some(policies) = policy["network_policies"].as_mapping_mut() {
        for (_, policy) in policies {
            if let Some(binaries) = policy["binaries"].as_sequence_mut() {
                for binary in binaries {
                    if let Some(path) = binary["path"].as_str() {
                        binary["path"] = serde_yml::Value::String(
                            executable_path(path).to_str().unwrap().to_string(),
                        );
                    }
                }
            }
        }
    }
    serde_yml::to_string(&policy).expect("serialize test policy")
}
