// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Narrow, one-shot guest preparation used by the VM compute driver.

use std::ffi::OsString;
use std::fmt;
#[cfg(target_os = "linux")]
use std::mem::size_of;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::process::ExitCode;

const LOOPBACK_NAME: &[u8] = b"lo";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    PrepareNetwork,
    Version,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum InterfaceFlagOperation {
    Read,
    Write,
}

#[derive(Debug)]
struct InitError(String);

impl fmt::Display for InitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openshell-vm-init: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), InitError> {
    match parse_command(args)? {
        Command::PrepareNetwork => prepare_network(),
        Command::Version => {
            println!("openshell-vm-init {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

fn parse_command(args: impl IntoIterator<Item = OsString>) -> Result<Command, InitError> {
    let mut args = args.into_iter();
    let command = args
        .next()
        .ok_or_else(|| InitError("expected the prepare-network command".to_string()))?;
    if args.next().is_some() {
        return Err(InitError("command does not accept arguments".to_string()));
    }
    match command.to_str() {
        Some("prepare-network") => Ok(Command::PrepareNetwork),
        Some("--version") => Ok(Command::Version),
        _ => Err(InitError(format!(
            "unknown command '{}'; expected prepare-network or --version",
            command.to_string_lossy()
        ))),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn prepare_network() -> Result<(), InitError> {
    // The helper is only invoked by trusted VM guest init, before it hands the
    // workload to the capability-free sandbox identity.
    if unsafe { libc::geteuid() } != 0 {
        return Err(InitError(
            "prepare-network must run as the VM guest root user".to_string(),
        ));
    }

    // SAFETY: socket returns a fresh descriptor or -1 and does not borrow any
    // caller-owned memory.
    let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw_fd < 0 {
        return Err(last_os_error("open loopback control socket"));
    }
    // SAFETY: raw_fd was returned successfully above and ownership transfers
    // exactly once to OwnedFd.
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    let mut request = InterfaceRequest::loopback();
    ioctl_interface_flags(
        socket.as_raw_fd(),
        InterfaceFlagOperation::Read,
        &mut request,
    )
    .map_err(|error| InitError(format!("read loopback flags: {error}")))?;
    let up_flag = libc::c_short::try_from(libc::IFF_UP)
        .map_err(|_| InitError("platform IFF_UP value does not fit in ifreq flags".to_string()))?;
    let flags = request.flags();
    if flags & up_flag == 0 {
        request.set_flags(flags | up_flag);
        ioctl_interface_flags(
            socket.as_raw_fd(),
            InterfaceFlagOperation::Write,
            &mut request,
        )
        .map_err(|error| InitError(format!("enable loopback: {error}")))?;
    }

    request.set_flags(0);
    ioctl_interface_flags(
        socket.as_raw_fd(),
        InterfaceFlagOperation::Read,
        &mut request,
    )
    .map_err(|error| InitError(format!("verify loopback flags: {error}")))?;
    if request.flags() & up_flag == 0 {
        return Err(InitError(
            "loopback remained down after successful configuration".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn prepare_network() -> Result<(), InitError> {
    Err(InitError(
        "prepare-network is only supported in Linux VM guests".to_string(),
    ))
}

#[cfg(target_os = "linux")]
#[repr(C)]
union InterfaceRequestData {
    flags: libc::c_short,
    // Linux's ifreq union is 24 bytes on the supported 64-bit guest targets.
    storage: [u8; 24],
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct InterfaceRequest {
    name: [libc::c_char; libc::IFNAMSIZ],
    data: InterfaceRequestData,
}

#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<InterfaceRequest>() == size_of::<libc::ifreq>());

#[cfg(target_os = "linux")]
impl InterfaceRequest {
    #[allow(trivial_numeric_casts)]
    fn loopback() -> Self {
        let mut request = Self {
            name: [0; libc::IFNAMSIZ],
            data: InterfaceRequestData { storage: [0; 24] },
        };
        for (destination, source) in request.name.iter_mut().zip(LOOPBACK_NAME) {
            *destination = *source as libc::c_char;
        }
        request
    }

    #[allow(unsafe_code)]
    fn flags(&self) -> libc::c_short {
        // SAFETY: the request was most recently populated by SIOCGIFFLAGS or
        // set_flags, both of which initialize the flags union member.
        unsafe { self.data.flags }
    }

    fn set_flags(&mut self, flags: libc::c_short) {
        self.data.flags = flags;
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn ioctl_interface_flags(
    fd: std::os::fd::RawFd,
    operation: InterfaceFlagOperation,
    interface: &mut InterfaceRequest,
) -> std::io::Result<()> {
    let request = match operation {
        InterfaceFlagOperation::Read => libc::SIOCGIFFLAGS,
        InterfaceFlagOperation::Write => libc::SIOCSIFFLAGS,
    };
    let request = libc::Ioctl::try_from(request).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface flag ioctl request does not fit the platform ABI",
        )
    })?;
    let interface_pointer: *mut InterfaceRequest = interface;
    // SAFETY: interface points to an ifreq-compatible buffer that remains
    // valid and exclusively borrowed for the duration of ioctl.
    if unsafe { libc::ioctl(fd, request, interface_pointer) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn last_os_error(operation: &str) -> InitError {
    InitError(format!("{operation}: {}", std::io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_prepare_network_without_arguments() {
        assert_eq!(
            parse_command([OsString::from("prepare-network")]).expect("valid command"),
            Command::PrepareNetwork
        );
        assert_eq!(
            parse_command([OsString::from("--version")]).expect("valid version command"),
            Command::Version
        );
        assert!(parse_command(Vec::<OsString>::new()).is_err());
        assert!(parse_command([OsString::from("other")]).is_err());
        assert!(
            parse_command([OsString::from("prepare-network"), OsString::from("eth0")]).is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(trivial_numeric_casts)]
    fn loopback_request_has_a_fixed_interface_name() {
        let request = InterfaceRequest::loopback();
        assert_eq!(request.name[0], b'l' as libc::c_char);
        assert_eq!(request.name[1], b'o' as libc::c_char);
        assert!(request.name[2..].iter().all(|byte| *byte == 0));
    }
}
