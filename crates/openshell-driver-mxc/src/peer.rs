// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox proxy-peer process for MXC `ProcessContainer` sandboxes.
//!
//! MXC's `runtimeConfig.networkProxy` mode lets a sandbox reach *only* its
//! proxy endpoint. This module supplies that endpoint with a small helper
//! process (`openshell-mxc-peer.exe`) that the driver starts under a
//! per-sandbox `AppContainer` profile. That profile is named as the sandbox's
//! `processContainer.network.allowedProxyPeer`, so MXC admits the workload's
//! connection to the proxy while keeping general host-loopback access denied.
//!
//! ```text
//! sandbox process -> MXC networkProxy -> peer proxy listener
//!                                      | egress pipe
//!                                   gateway -> policy proxy -> network
//! ```
//!
//! Control protocol (newline-delimited text over `\\.\pipe\<prefix>-ctl`):
//!   peer -> gateway: `READY <proxy-port>` once, after binding its proxy listener
//!
//! The peer's proxy listener is the sandbox's `networkProxy` endpoint; for every
//! connection the sandbox opens to it, the peer connects to the multi-instance
//! pipe `\\.\pipe\<prefix>-egress`
//! and pumps raw bytes. The gateway side of that pipe dials the sandbox's host
//! egress proxy (the existing per-sandbox policy proxy) and pumps bytes to it,
//! so the peer is a transparent byte tunnel and every policy decision, TLS
//! interception and credential substitution still happens in the gateway.
//! Dynamic forwarding is unavailable in proxy-peer mode: MXC admits the
//! workload's connection to this peer, not a reverse peer-to-workload dial, and
//! keeps sandbox-local loopback denied.
//!
//! Per-process policy (binary rules) keeps working through the tunnel: the first
//! line the peer writes on an egress pipe is `CLIENT <port>`, the source port the
//! sandbox process used on the peer's proxy listener. The gateway registers an
//! alias from its bridge socket to that original connection
//! (`ForwardedClients`), and the host proxy then resolves the owner of the
//! original socket rather than the owner of the gateway's bridge socket.
//!
//! The pipe names, line formats and the profile-capability list are duplicated
//! in `src/bin/openshell-mxc-peer.rs`, matching how the other relay wire
//! protocols in this crate are duplicated across their two sides.

#![allow(unsafe_code)]

use crate::peer_firewall::PeerFirewallRule;
use std::ffi::c_void;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use openshell_supervisor_network::host::ForwardedClients;
use openshell_supervisor_network::procfs::WorkloadProxyTcpConnection;
use tokio::io::AsyncReadExt;
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, InitializeProcThreadAttributeList,
    LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

/// Capabilities the peer profile needs so it can open loopback TCP connections
/// (`internetClient`, `privateNetworkClientServer`).
const PEER_CAPABILITY_SIDS: [&str; 2] = ["S-1-15-3-1", "S-1-15-3-3"];

/// Environment variables copied from the gateway to the peer (see
/// `spawn_in_app_container`).
const PEER_BOOTSTRAP_ENV: [&str; 6] = [
    "SYSTEMROOT",
    "WINDIR",
    "PATH",
    "PATHEXT",
    "COMSPEC",
    "LOCALAPPDATA",
];

/// `SE_GROUP_ENABLED`.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`.
const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7_u32.cast_signed();

const PEER_READY_TIMEOUT: Duration = Duration::from_secs(15);
const DATA_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_LINE: usize = 512;

fn win_err(error: windows::core::Error) -> io::Error {
    io::Error::other(error.to_string())
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `AppContainer` profile name for a sandbox: `openshell-mxc-<id without dashes>`
/// (profile names are limited to 64 characters of `[A-Za-z0-9._-]`).
fn profile_name_for(sandbox_id: &str) -> String {
    let id: String = sandbox_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect();
    format!("openshell-mxc-{id}")
}

/// Pipe DACL: the gateway's own user plus the peer's `AppContainer` SID, nothing
/// else. An `AppContainer` access check must succeed for both the user SID in
/// the token and the package SID, so both ACEs are required.
fn pipe_sddl(user_sid: &str, profile_sid: &str) -> String {
    format!("D:(A;;GA;;;{user_sid})(A;;GA;;;{profile_sid})")
}

fn ctl_pipe_name(prefix: &str) -> String {
    format!(r"\\.\pipe\{prefix}-ctl")
}

fn egress_pipe_name(prefix: &str) -> String {
    format!(r"\\.\pipe\{prefix}-egress")
}

/// Where the peer's egress tunnel ends: the sandbox's host egress proxy, plus the
/// registry that lets that proxy resolve the identity of the real sandbox process
/// behind each tunnelled connection.
#[derive(Clone)]
pub struct EgressTunnel {
    pub host_proxy: SocketAddr,
    pub clients: ForwardedClients,
}

/// Parse the peer's `CLIENT <port>` line: the source port the sandbox process
/// used when it connected to the peer's proxy listener.
fn parse_client_port(line: &str) -> Option<u16> {
    line.strip_prefix("CLIENT ")?.trim().parse().ok()
}

/// Peer command line: `"<exe>" <token> <egress|none>`.
fn peer_command_line(peer_exe: &str, token: &str, egress: bool) -> String {
    format!(
        "\"{peer_exe}\" {token} {}",
        if egress { "egress" } else { "none" }
    )
}

/// Parse `READY <port>`.
fn parse_ready(line: &str) -> Option<u16> {
    line.strip_prefix("READY ")?.trim().parse().ok()
}

/// Read one `\n`-terminated line one byte at a time so that no payload bytes that
/// follow the line are consumed.
async fn read_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    loop {
        if reader.read(&mut one).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "pipe closed before end of line",
            ));
        }
        if one[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        bytes.push(one[0]);
    }
    String::from_utf8(bytes)
        .map(|line| line.trim_end_matches('\r').to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line is not UTF-8"))
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` is a valid SID and `text` is a valid out pointer.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }.map_err(win_err)?;
    // SAFETY: on success `text` points to a NUL-terminated wide string allocated
    // by the OS; it is freed with LocalFree right after copying.
    let result = unsafe { text.to_string() }.map_err(|error| io::Error::other(error.to_string()));
    // SAFETY: `text` was allocated by ConvertSidToStringSidW (LocalAlloc).
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }
    result
}

fn current_user_sid() -> io::Result<String> {
    // SAFETY: standard token query with a correctly sized, 8-byte-aligned buffer.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token).map_err(win_err)?;
        let mut len = 0_u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &raw mut len);
        let mut buffer = vec![0_u64; (len as usize).div_ceil(8).max(1)];
        let query = GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &raw mut len,
        );
        let result = match query {
            Ok(()) => {
                let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
                sid_to_string(user.User.Sid)
            }
            Err(error) => Err(win_err(error)),
        };
        let _ = CloseHandle(token);
        result
    }
}

/// Self-relative security descriptor built from SDDL, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable after creation and only read by the OS.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: see above.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = wide(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `sddl` is NUL-terminated and `descriptor` is a valid out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(win_err)?;
        Ok(Self(descriptor))
    }

    fn create_pipe(&self, name: &str, first_instance: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: self.0.0,
            bInheritHandle: false.into(),
        };
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first_instance);
        options.reject_remote_clients(true);
        // SAFETY: `attributes` is a valid SECURITY_ATTRIBUTES for the call and the
        // descriptor it points to outlives the call (owned by `self`).
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                std::ptr::addr_of_mut!(attributes).cast::<c_void>(),
            )
        }
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

/// Frees a SID obtained from the `AppContainer` APIs on drop.
struct OwnedSid(PSID);

impl OwnedSid {
    fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        // SAFETY: SIDs returned by CreateAppContainerProfile and
        // DeriveAppContainerSidFromAppContainerName are released with FreeSid.
        // (The capability SIDs from ConvertStringSidToSidW are separate and are
        // intentionally not wrapped here; see `capability_sids`.)
        unsafe {
            let _ = windows::Win32::Security::FreeSid(self.0);
        }
    }
}

fn capability_sids() -> io::Result<Vec<PSID>> {
    PEER_CAPABILITY_SIDS
        .iter()
        .map(|text| {
            let text = wide(text);
            let mut sid = PSID::default();
            // SAFETY: `text` is NUL-terminated; `sid` is a valid out pointer. The
            // SID is deliberately leaked for the (short) lifetime of the gateway:
            // it is a few bytes per sandbox and freeing it would require tracking
            // it past `CreateProcessW`.
            unsafe { ConvertStringSidToSidW(PCWSTR(text.as_ptr()), &raw mut sid) }
                .map_err(win_err)?;
            Ok(sid)
        })
        .collect()
}

/// Create the profile if needed and return its SID.
fn ensure_profile(name: &str, capabilities: &[SID_AND_ATTRIBUTES]) -> io::Result<OwnedSid> {
    let name_w = wide(name);
    let name_p = PCWSTR(name_w.as_ptr());
    // SAFETY: all string arguments are NUL-terminated and outlive the call.
    let created = unsafe {
        CreateAppContainerProfile(
            name_p,
            name_p,
            name_p,
            (!capabilities.is_empty()).then_some(capabilities),
        )
    };
    match created {
        Ok(sid) => Ok(OwnedSid(sid)),
        Err(error) if error.code().0 == HRESULT_ALREADY_EXISTS => {
            // SAFETY: `name_p` is NUL-terminated.
            unsafe { DeriveAppContainerSidFromAppContainerName(name_p) }
                .map(OwnedSid)
                .map_err(win_err)
        }
        Err(error) => Err(win_err(error)),
    }
}

/// Start `exe` inside the `AppContainer` identified by `sid` with `capabilities`.
/// The child gets a minimal environment (never the gateway's, which may hold
/// secrets) and no inherited handles.
fn spawn_in_app_container(
    exe: &str,
    command_line: &str,
    sid: PSID,
    capabilities: &mut [SID_AND_ATTRIBUTES],
) -> io::Result<HANDLE> {
    let mut list_size = 0_usize;
    // SAFETY: size query; documented to fail with ERROR_INSUFFICIENT_BUFFER.
    unsafe {
        let _ = InitializeProcThreadAttributeList(None, 1, None, &raw mut list_size);
    }
    let mut list_buffer = vec![0_u64; list_size.div_ceil(8).max(1)];
    let list = LPPROC_THREAD_ATTRIBUTE_LIST(list_buffer.as_mut_ptr().cast());
    // SAFETY: `list` points to a buffer of at least `list_size` bytes.
    unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &raw mut list_size) }
        .map_err(win_err)?;

    let security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: capabilities.as_mut_ptr(),
        CapabilityCount: u32::try_from(capabilities.len()).unwrap_or(0),
        Reserved: 0,
    };
    // SAFETY: the attribute value outlives CreateProcessW below.
    let update = unsafe {
        UpdateProcThreadAttribute(
            list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(std::ptr::addr_of!(security_capabilities).cast::<c_void>()),
            size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
    };
    if let Err(error) = update {
        // SAFETY: `list` was initialized above.
        unsafe { DeleteProcThreadAttributeList(list) };
        return Err(win_err(error));
    }

    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(0),
            ..Default::default()
        },
        lpAttributeList: list,
    };
    let exe_w = wide(exe);
    let mut command_w = wide(command_line);
    // Same non-secret bootstrap set the driver gives sandboxed workloads: an
    // AppContainer `CreateProcessW` fails with ERROR_ENVVAR_NOT_FOUND (203)
    // without LOCALAPPDATA. Nothing else from the gateway's environment (which
    // can hold secrets) is passed on.
    let mut environment: Vec<u16> = Vec::new();
    for name in PEER_BOOTSTRAP_ENV {
        if let Ok(value) = std::env::var(name) {
            environment.extend(format!("{name}={value}").encode_utf16());
            environment.push(0);
        }
    }
    environment.push(0);

    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: all pointers are valid for the duration of the call; the
    // environment block is double-NUL-terminated UTF-16 as required by
    // CREATE_UNICODE_ENVIRONMENT.
    let created = unsafe {
        CreateProcessW(
            PCWSTR(exe_w.as_ptr()),
            Some(PWSTR(command_w.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast::<c_void>()),
            PCWSTR::null(),
            std::ptr::addr_of!(startup).cast::<STARTUPINFOW>(),
            &raw mut info,
        )
    };
    // SAFETY: `list` was initialized above and is no longer needed.
    unsafe { DeleteProcThreadAttributeList(list) };
    created.map_err(win_err)?;
    // SAFETY: the thread handle is not used.
    unsafe {
        let _ = CloseHandle(info.hThread);
    }
    Ok(info.hProcess)
}

/// A running proxy-peer process for one sandbox. Dropping it terminates the
/// process and deletes the `AppContainer` profile.
pub struct PeerHandle {
    profile: String,
    process: isize,
    prefix: String,
    descriptor: Arc<SecurityDescriptor>,
    control: Mutex<Option<NamedPipeServer>>,
    firewall: StdMutex<Option<PeerFirewallRule>>,
    profile_sid: String,
    proxy_addr: SocketAddr,
    terminated: AtomicBool,
    /// First instance of the egress pipe, created before the peer starts so the
    /// name cannot be squatted; handed to the accept loop once the peer is ready.
    egress_first: Option<NamedPipeServer>,
    /// Gateway-side accept loop bridging egress pipe connections to the host
    /// egress proxy. Aborted on terminate.
    egress_task: StdMutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for PeerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerHandle")
            .field("profile", &self.profile)
            .field("proxy_addr", &self.proxy_addr)
            .finish_non_exhaustive()
    }
}

impl PeerHandle {
    /// `AppContainer` profile name; this is the sandbox's `allowedProxyPeer`.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Loopback address of the peer's proxy listener; this is the sandbox's
    /// `networkProxy`.
    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_addr
    }

    /// Create the profile, start the peer under it and wait until it reports its
    /// proxy port over the control pipe.
    ///
    /// With `egress` set, the peer tunnels every connection its proxy listener
    /// accepts to the gateway's host egress proxy over a named pipe; without it
    /// the peer's proxy answers `403`.
    pub async fn spawn(
        peer_exe: &str,
        sandbox_id: &str,
        egress: Option<EgressTunnel>,
    ) -> io::Result<Self> {
        // All raw-pointer Win32 work happens in this synchronous helper so that no
        // non-`Send` value is held across the awaits below.
        let mut handle = Self::start_process(peer_exe, sandbox_id, egress.is_some())?;

        let ready = async {
            let control = handle
                .control
                .get_mut()
                .as_mut()
                .expect("control pipe exists during startup");
            tokio::time::timeout(PEER_READY_TIMEOUT, control.connect())
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "proxy peer did not connect")
                })??;
            let line = tokio::time::timeout(PEER_READY_TIMEOUT, read_line(control))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "proxy peer did not report READY")
                })??;
            parse_ready(&line).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected proxy peer greeting: {line}"),
                )
            })
        }
        .await?;
        // READY proves only that bind succeeded. Firewall authorization is
        // required before the driver may publish this endpoint to a workload.
        let name = format!("OpenShell MXC peer {}", handle.prefix);
        let exe = peer_exe.to_string();
        let sid = handle.profile_sid.clone();
        let rule =
            tokio::task::spawn_blocking(move || PeerFirewallRule::install(name, &exe, &sid, ready))
                .await
                .map_err(io::Error::other)??;
        *handle.firewall.get_mut().expect("new firewall mutex") = Some(rule);
        handle.proxy_addr = SocketAddr::from(([127, 0, 0, 1], ready));
        let egress_enabled = egress.is_some();
        if let (Some(first), Some(tunnel)) = (handle.egress_first.take(), egress) {
            let task = tokio::spawn(egress_accept_loop(
                Arc::clone(&handle.descriptor),
                egress_pipe_name(&handle.prefix),
                first,
                tunnel,
                handle.proxy_addr,
            ));
            if let Ok(mut slot) = handle.egress_task.lock() {
                *slot = Some(task);
            }
        }
        info!(
            profile = %handle.profile,
            proxy = %handle.proxy_addr,
            egress = egress_enabled,
            "MXC proxy peer started"
        );
        Ok(handle)
    }

    /// Native resource fixture: a real child, `AppContainer` profile and secured
    /// pipe. It avoids requiring an installed, AC-readable peer executable.
    #[cfg(test)]
    pub(super) fn test_fixture() -> (Self, std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
        let profile = profile_name_for(&uuid::Uuid::new_v4().to_string());
        let sid = ensure_profile(&profile, &[]).unwrap();
        let profile_sid = sid_to_string(sid.as_psid()).unwrap();
        let descriptor =
            SecurityDescriptor::from_sddl(&pipe_sddl(&current_user_sid().unwrap(), &profile_sid))
                .unwrap();
        let prefix = format!("openshell-mxc-test-{}", uuid::Uuid::new_v4());
        let control = descriptor
            .create_pipe(&ctl_pipe_name(&prefix), true)
            .unwrap();
        let root = std::env::var("SYSTEMROOT").unwrap();
        let child = std::process::Command::new(format!(
            r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe"
        ))
        .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
        let mut process = HANDLE::default();
        // SAFETY: duplicate the live child's process handle for PeerHandle to own.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(child.as_raw_handle()),
                GetCurrentProcess(),
                &raw mut process,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .unwrap();
        }
        (
            Self {
                profile,
                process: process.0 as isize,
                prefix,
                descriptor: Arc::new(descriptor),
                control: Mutex::new(Some(control)),
                firewall: StdMutex::new(None),
                profile_sid,
                proxy_addr: "127.0.0.1:0".parse().unwrap(),
                terminated: AtomicBool::new(false),
                egress_first: None,
                egress_task: StdMutex::new(None),
            },
            child,
        )
    }

    #[cfg(test)]
    pub(super) fn assert_released(&self, child: &mut std::process::Child) {
        assert!(self.terminated.load(Ordering::Acquire));
        assert!(
            child.try_wait().unwrap().is_some(),
            "peer child must be reaped before reporting termination"
        );
        assert!(
            self.control.try_lock().unwrap().is_none(),
            "retained Arc must not retain the control pipe"
        );
        // first_pipe_instance proves the old pipe was closed, even though this
        // fixture deliberately retains an Arc to the terminated PeerHandle.
        let _rebound = self
            .descriptor
            .create_pipe(&ctl_pipe_name(&self.prefix), true)
            .unwrap();
        let name = wide(&self.profile);
        // SAFETY: terminated strings, no capabilities; the returned SID is freed.
        unsafe {
            let recreated = CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                None,
            )
            .expect("retained peer Arc must not retain its AppContainer profile");
            let _sid = OwnedSid(recreated);
            DeleteAppContainerProfile(PCWSTR(name.as_ptr())).unwrap();
        }
    }

    /// Create the profile and control pipe and start the peer process. Does not
    /// wait for the peer; see [`PeerHandle::spawn`].
    fn start_process(peer_exe: &str, sandbox_id: &str, egress: bool) -> io::Result<Self> {
        let profile = profile_name_for(sandbox_id);
        let token = format!("{:032x}", rand::random::<u128>());
        let prefix = format!("openshell-mxc-{token}");

        let mut capabilities: Vec<SID_AND_ATTRIBUTES> = capability_sids()?
            .into_iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();
        let sid = ensure_profile(&profile, &capabilities)?;
        let result = (|| {
            let profile_sid = sid_to_string(sid.as_psid())?;
            let sddl = pipe_sddl(&current_user_sid()?, &profile_sid);
            let descriptor = SecurityDescriptor::from_sddl(&sddl)?;

            // The control pipe exists before the peer starts, so the peer's first
            // connect attempt succeeds and no other process can squat the name
            // (first_pipe_instance + a DACL that only admits the peer).
            let control = descriptor.create_pipe(&ctl_pipe_name(&prefix), true)?;
            let egress_first = if egress {
                Some(descriptor.create_pipe(&egress_pipe_name(&prefix), true)?)
            } else {
                None
            };

            let command_line = peer_command_line(peer_exe, &token, egress);
            let process = match spawn_in_app_container(
                peer_exe,
                &command_line,
                sid.as_psid(),
                &mut capabilities,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("failed to start proxy peer '{peer_exe}': {error}"),
                    ));
                }
            };

            // From here on the handle's Drop cleans up the process and profile.
            Ok(Self {
                profile: profile.clone(),
                process: process.0 as isize,
                prefix,
                descriptor: Arc::new(descriptor),
                control: Mutex::new(Some(control)),
                firewall: StdMutex::new(None),
                profile_sid,
                proxy_addr: "127.0.0.1:0".parse().expect("static address"),
                terminated: AtomicBool::new(false),
                egress_first,
                egress_task: StdMutex::new(None),
            })
        })();
        if result.is_err() {
            // SAFETY: profile creation succeeded; all preparation failures must
            // release it, including SID conversion, DACL and pipe creation.
            unsafe {
                let name = wide(&profile);
                let _ = DeleteAppContainerProfile(PCWSTR(name.as_ptr()));
            }
        }
        result
    }
}

/// Gateway side of the egress tunnel: accept peer connections on the egress pipe
/// and bridge each to the host egress proxy at `target`. The next pipe instance
/// is created before the accepted one is handed off, so the peer (which retries
/// on `ERROR_PIPE_BUSY`) always finds a listening instance.
async fn egress_accept_loop(
    descriptor: Arc<SecurityDescriptor>,
    name: String,
    first: NamedPipeServer,
    tunnel: EgressTunnel,
    peer_proxy: SocketAddr,
) {
    let mut server = first;
    loop {
        if let Err(error) = server.connect().await {
            warn!("MXC proxy peer egress pipe accept failed: {error}");
            return;
        }
        let connected = server;
        server = match descriptor.create_pipe(&name, false) {
            Ok(next) => next,
            Err(error) => {
                warn!("MXC proxy peer egress pipe re-create failed: {error}");
                return;
            }
        };
        let tunnel = tunnel.clone();
        tokio::spawn(bridge_egress(connected, tunnel, peer_proxy));
    }
}

/// Bridge one tunnelled sandbox connection to the host egress proxy.
async fn bridge_egress(mut pipe: NamedPipeServer, tunnel: EgressTunnel, peer_proxy: SocketAddr) {
    // First line from the peer: the sandbox process's source port on the peer's
    // proxy listener, which identifies the original connection.
    let line = match tokio::time::timeout(DATA_CONNECT_TIMEOUT, read_line(&mut pipe)).await {
        Ok(Ok(line)) => line,
        Ok(Err(error)) => {
            warn!("MXC proxy peer egress: no client line: {error}");
            return;
        }
        Err(_) => {
            warn!("MXC proxy peer egress: timed out waiting for client line");
            return;
        }
    };
    let Some(client_port) = parse_client_port(&line) else {
        warn!("MXC proxy peer egress: malformed client line");
        return;
    };
    let mut tcp = match TcpStream::connect(tunnel.host_proxy).await {
        Ok(tcp) => tcp,
        Err(error) => {
            warn!(
                "MXC proxy peer egress: cannot reach host proxy {}: {error}",
                tunnel.host_proxy
            );
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    // Register before any request bytes flow, so identity resolution for this
    // connection always finds the alias. The guard removes it when the tunnel ends.
    let _alias = tcp.local_addr().ok().map(|bridge| {
        tunnel.clients.register(
            bridge,
            WorkloadProxyTcpConnection::new(
                SocketAddr::from(([127, 0, 0, 1], client_port)),
                peer_proxy,
            ),
        )
    });
    let _ = tokio::io::copy_bidirectional(&mut pipe, &mut tcp).await;
}

impl PeerHandle {
    /// Terminate the peer process and delete its `AppContainer` profile.
    /// Idempotent. Blocks for up to two seconds waiting for the process to exit,
    /// so call it from `spawn_blocking` in async contexts. Other holders of the
    /// handle (for example forward bridges) can keep their `Arc`, so teardown does
    /// not wait for `Drop`.
    pub fn terminate(&self) {
        if self.terminated.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut slot) = self.egress_task.lock()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
        // Close the control pipe even while other Arc holders survive.
        if let Ok(mut control) = self.control.try_lock() {
            control.take();
        }
        let process = HANDLE(self.process as *mut c_void);
        // SAFETY: `process` is the handle returned by CreateProcessW and owned by
        // this struct; the `terminated` flag guarantees it is closed exactly once.
        unsafe {
            let _ = TerminateProcess(process, 1);
            let _ = WaitForSingleObject(process, 2000);
            let _ = CloseHandle(process);
            let name = wide(&self.profile);
            if let Err(error) = DeleteAppContainerProfile(PCWSTR(name.as_ptr())) {
                warn!(profile = %self.profile, "failed to delete proxy peer profile: {error}");
            }
        }
        if let Ok(mut firewall) = self.firewall.lock() {
            firewall.take();
        }
        info!(profile = %self.profile, "MXC proxy peer terminated");
    }
}

impl Drop for PeerHandle {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires a staged AC-readable helper in OPENSHELL_MXC_PEER_EXE"]
    async fn peer_startup_confirms_firewall_or_fails_before_ready() {
        let exe = std::env::var("OPENSHELL_MXC_PEER_EXE").expect("stage the real helper first");
        let id = uuid::Uuid::new_v4().to_string();
        match PeerHandle::spawn(&exe, &id, None).await {
            Ok(peer) => {
                assert_ne!(peer.proxy_addr().port(), 0);
                tokio::task::spawn_blocking(move || peer.terminate())
                    .await
                    .unwrap();
                eprintln!(
                    "EVIDENCE: actual AppContainer peer reached firewall-authorized readiness"
                );
            }
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("firewall authorization failed"),
                    "{message}"
                );
                assert!(
                    message.contains("permission to manage Windows Firewall rules"),
                    "{message}"
                );
                eprintln!(
                    "EVIDENCE: actual AppContainer peer failed before readiness with an actionable firewall diagnostic"
                );
            }
        }
        // Profile creation must succeed anew, proving cleanup on either path.
        let name = wide(&profile_name_for(&id));
        // SAFETY: terminated strings and no capabilities; SID is freed on drop.
        unsafe {
            let sid = CreateAppContainerProfile(
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                PCWSTR(name.as_ptr()),
                None,
            )
            .expect("startup failure or termination must release the peer profile");
            let _sid = OwnedSid(sid);
            DeleteAppContainerProfile(PCWSTR(name.as_ptr())).unwrap();
        }
    }

    #[test]
    fn profile_name_is_stable_and_within_limits() {
        let name = profile_name_for("6e3db1ed-8861-457f-95bd-35ac9714f4fb");
        assert_eq!(name, "openshell-mxc-6e3db1ed8861457f95bd35ac9714f4fb");
        assert!(name.len() <= 64);
        assert_eq!(profile_name_for("a/b\\c:d"), "openshell-mxc-abcd");
    }

    #[test]
    fn pipe_sddl_admits_only_user_and_profile() {
        assert_eq!(
            pipe_sddl("S-1-5-21-1", "S-1-15-2-9"),
            "D:(A;;GA;;;S-1-5-21-1)(A;;GA;;;S-1-15-2-9)"
        );
    }

    #[test]
    fn pipe_names_are_namespaced_per_prefix() {
        assert_eq!(ctl_pipe_name("p"), r"\\.\pipe\p-ctl");
        assert_eq!(egress_pipe_name("p"), r"\\.\pipe\p-egress");
    }

    #[test]
    fn client_port_line_parsing() {
        assert_eq!(parse_client_port("CLIENT 61000"), Some(61000));
        assert_eq!(parse_client_port("CLIENT  7 "), Some(7));
        assert_eq!(parse_client_port("CLIENT x"), None);
        assert_eq!(parse_client_port("CLIENT 70000"), None);
        assert_eq!(parse_client_port("READY 1"), None);
    }

    #[test]
    fn peer_command_line_carries_the_egress_mode() {
        assert_eq!(
            peer_command_line(r"C:\x\peer.exe", "tok", true),
            r#""C:\x\peer.exe" tok egress"#
        );
        assert_eq!(
            peer_command_line(r"C:\x\peer.exe", "tok", false),
            r#""C:\x\peer.exe" tok none"#
        );
    }

    #[test]
    fn ready_line_parsing() {
        assert_eq!(parse_ready("READY 4242"), Some(4242));
        assert_eq!(parse_ready("READY  17 "), Some(17));
        assert_eq!(parse_ready("READY x"), None);
        assert_eq!(parse_ready("OPEN 1 2"), None);
    }

    #[tokio::test]
    async fn read_line_stops_at_newline_and_keeps_payload() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"OK\nPAYLOAD").await.unwrap();
        assert_eq!(read_line(&mut b).await.unwrap(), "OK");
        let mut rest = [0_u8; 7];
        b.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, b"PAYLOAD");
    }

    #[tokio::test]
    async fn read_line_rejects_oversized_lines_and_eof() {
        let (mut a, mut b) = tokio::io::duplex(2048);
        a.write_all(&vec![b'x'; MAX_LINE + 10]).await.unwrap();
        assert_eq!(
            read_line(&mut b).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let (a, mut b) = tokio::io::duplex(8);
        drop(a);
        assert_eq!(
            read_line(&mut b).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
