// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows TCP socket-owner and process-image resolution.

use std::mem::{offset_of, size_of, size_of_val};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use miette::Result;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP_STATE_ESTAB, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use crate::procfs::WorkloadProxyTcpConnection;

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid handle returned by `OpenProcess`, and this
        // guard is its sole owner.
        #[allow(unsafe_code)]
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Resolve the process that owns the workload side of an accepted proxy TCP
/// connection and return its PID and executable image path.
pub fn resolve_tcp_peer_identity(connection: WorkloadProxyTcpConnection) -> Result<(PathBuf, u32)> {
    let mut owners = match (connection.workload, connection.proxy) {
        (SocketAddr::V4(workload), SocketAddr::V4(proxy)) => ipv4_owner_pids(workload, proxy)?,
        (SocketAddr::V6(workload), SocketAddr::V6(proxy)) => ipv6_owner_pids(&workload, &proxy)?,
        _ => {
            return Err(miette::miette!(
                "TCP connection address families do not match: {connection}"
            ));
        }
    };
    owners.sort_unstable();
    owners.dedup();

    let pid = match owners.as_slice() {
        [pid] => *pid,
        [] => {
            return Err(miette::miette!(
                "No Windows process owns proxy connection {connection}"
            ));
        }
        pids => {
            return Err(miette::miette!(
                "Ambiguous Windows proxy connection ownership for {connection}: PIDs [{}]",
                pids.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    };

    Ok((process_image_path(pid)?, pid))
}

fn ipv4_owner_pids(
    workload: std::net::SocketAddrV4,
    proxy: std::net::SocketAddrV4,
) -> Result<Vec<u32>> {
    let (buffer, byte_len) = tcp_table(u32::from(AF_INET.0))?;
    let rows = table_rows::<MIB_TCPROW_OWNER_PID>(
        &buffer,
        byte_len,
        offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        size_of::<MIB_TCPROW_OWNER_PID>(),
    )?;
    let established = u32::try_from(MIB_TCP_STATE_ESTAB.0).expect("TCP state constant fits u32");
    Ok(rows
        .into_iter()
        .filter(|row| {
            row.dwState == established
                && IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()))
                    == IpAddr::V4(*workload.ip())
                && tcp_port(row.dwLocalPort) == workload.port()
                && IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()))
                    == IpAddr::V4(*proxy.ip())
                && tcp_port(row.dwRemotePort) == proxy.port()
        })
        .map(|row| row.dwOwningPid)
        .collect())
}

fn ipv6_owner_pids(
    workload: &std::net::SocketAddrV6,
    proxy: &std::net::SocketAddrV6,
) -> Result<Vec<u32>> {
    let (buffer, byte_len) = tcp_table(u32::from(AF_INET6.0))?;
    let rows = table_rows::<MIB_TCP6ROW_OWNER_PID>(
        &buffer,
        byte_len,
        offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        size_of::<MIB_TCP6ROW_OWNER_PID>(),
    )?;
    let established = u32::try_from(MIB_TCP_STATE_ESTAB.0).expect("TCP state constant fits u32");
    Ok(rows
        .into_iter()
        .filter(|row| ipv6_row_matches(row, workload, proxy, established))
        .map(|row| row.dwOwningPid)
        .collect())
}

fn ipv6_row_matches(
    row: &MIB_TCP6ROW_OWNER_PID,
    workload: &std::net::SocketAddrV6,
    proxy: &std::net::SocketAddrV6,
    established: u32,
) -> bool {
    row.dwState == established
        && Ipv6Addr::from(row.ucLocalAddr) == *workload.ip()
        && u32::from_be(row.dwLocalScopeId) == workload.scope_id()
        && tcp_port(row.dwLocalPort) == workload.port()
        && Ipv6Addr::from(row.ucRemoteAddr) == *proxy.ip()
        && u32::from_be(row.dwRemoteScopeId) == proxy.scope_id()
        && tcp_port(row.dwRemotePort) == proxy.port()
}

fn tcp_port(raw: u32) -> u16 {
    let low_word = u16::try_from(raw & u32::from(u16::MAX)).expect("masked TCP port fits u16");
    u16::from_be(low_word)
}

fn tcp_table(address_family: u32) -> Result<(Vec<u32>, usize)> {
    let mut byte_len = 0u32;
    // SAFETY: A null table pointer is the documented size-query form. The
    // mutable size pointer is valid for the duration of the call.
    #[allow(unsafe_code)]
    let initial = unsafe {
        GetExtendedTcpTable(
            None,
            &raw mut byte_len,
            false,
            address_family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if initial != ERROR_INSUFFICIENT_BUFFER.0 && initial != 0 {
        return Err(miette::miette!(
            "GetExtendedTcpTable size query failed with Win32 error {initial}"
        ));
    }

    for _ in 0..3 {
        let mut buffer = vec![0u32; (byte_len as usize).div_ceil(size_of::<u32>()).max(1)];
        let mut actual_len = u32::try_from(buffer.len() * size_of::<u32>())
            .map_err(|_| miette::miette!("TCP table buffer is too large"))?;
        // SAFETY: The u32-backed buffer has sufficient alignment and capacity
        // for the requested byte count. The API writes at most `actual_len`
        // bytes and updates it when the table grows concurrently.
        #[allow(unsafe_code)]
        let status = unsafe {
            GetExtendedTcpTable(
                Some(buffer.as_mut_ptr().cast()),
                &raw mut actual_len,
                false,
                address_family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status == 0 {
            return Ok((buffer, actual_len as usize));
        }
        if status != ERROR_INSUFFICIENT_BUFFER.0 {
            return Err(miette::miette!(
                "GetExtendedTcpTable failed with Win32 error {status}"
            ));
        }
        byte_len = actual_len;
    }

    Err(miette::miette!(
        "GetExtendedTcpTable changed size during three consecutive reads"
    ))
}

fn table_rows<T: Copy>(
    buffer: &[u32],
    byte_len: usize,
    first_row_offset: usize,
    row_stride: usize,
) -> Result<Vec<T>> {
    if byte_len < size_of::<u32>() {
        return Err(miette::miette!("Windows TCP table is missing its header"));
    }
    if row_stride < size_of::<T>() {
        return Err(miette::miette!(
            "Windows TCP table row stride {row_stride} is smaller than row size {}",
            size_of::<T>()
        ));
    }
    let count = buffer[0] as usize;
    let required = if count == 0 {
        size_of::<u32>()
    } else {
        first_row_offset
            .checked_add(
                (count - 1)
                    .checked_mul(row_stride)
                    .ok_or_else(|| miette::miette!("Windows TCP row count overflow"))?,
            )
            .and_then(|last_row| last_row.checked_add(size_of::<T>()))
            .ok_or_else(|| miette::miette!("Windows TCP table size overflow"))?
    };
    if required > byte_len || required > size_of_val(buffer) {
        return Err(miette::miette!(
            "Windows TCP table is truncated: {count} rows require {required} bytes, got {byte_len}"
        ));
    }

    let mut rows = Vec::with_capacity(count);
    // SAFETY: Bounds were checked above. `read_unaligned` supports the padding
    // permitted before the first row and between generated table rows.
    #[allow(unsafe_code)]
    unsafe {
        let first = buffer.as_ptr().cast::<u8>().add(first_row_offset);
        for index in 0..count {
            rows.push(std::ptr::read_unaligned(
                first.add(index * row_stride).cast::<T>(),
            ));
        }
    }
    Ok(rows)
}

fn process_image_path(pid: u32) -> Result<PathBuf> {
    // SAFETY: The access mask and PID are plain values; the returned handle is
    // immediately placed under an RAII guard.
    #[allow(unsafe_code)]
    let handle = ProcessHandle(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .map_err(|error| miette::miette!("Failed to open socket-owning PID {pid}: {error}"))?,
    );
    let mut path = vec![0u16; 32_768];
    let mut path_len = u32::try_from(path.len()).expect("Windows path buffer length fits u32");
    // SAFETY: The handle is valid, and the UTF-16 output buffer and in/out
    // length pointer remain valid for the call.
    #[allow(unsafe_code)]
    unsafe {
        QueryFullProcessImageNameW(
            handle.0,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &raw mut path_len,
        )
    }
    .map_err(|error| {
        miette::miette!("Failed to query executable path for socket-owning PID {pid}: {error}")
    })?;
    path.truncate(path_len as usize);
    Ok(PathBuf::from(String::from_utf16(&path).map_err(
        |error| miette::miette!("Socket-owning PID {pid} returned an invalid UTF-16 path: {error}"),
    )?))
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Command, Stdio};

    use super::*;

    const CHILD_PORT_ENV: &str = "OPENSHELL_TEST_WINDOWS_SOCKET_OWNER_PORT";

    #[test]
    fn socket_owner_child() {
        let Ok(port) = std::env::var(CHILD_PORT_ENV) else {
            return;
        };
        let mut stream = TcpStream::connect(("127.0.0.1", port.parse::<u16>().unwrap())).unwrap();
        let mut byte = [0u8; 1];
        let _ = stream.read(&mut byte);
    }

    #[test]
    fn resolves_child_that_owns_ipv4_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let mut child = Command::new(&current_exe)
            .args([
                "--exact",
                "windows_process::tests::socket_owner_child",
                "--nocapture",
            ])
            .env(CHILD_PORT_ENV, proxy.port().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let (accepted, workload) = listener.accept().unwrap();
        let result = resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(workload, proxy));
        drop(accepted);
        let status = child.wait().unwrap();
        assert!(status.success());

        let (path, pid) = result.unwrap();
        assert_eq!(pid, child.id());
        assert_eq!(path, current_exe);
    }

    #[test]
    fn parses_table_with_header_and_inter_row_padding() {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct SyntheticRow {
            value: u32,
            pid: u32,
        }

        const FIRST_ROW_OFFSET: usize = 8;
        const ROW_STRIDE: usize = 12;
        let buffer = vec![
            2,           // dwNumEntries
            0xAAAA_AAAA, // header padding
            11,
            101,
            0xBBBB_BBBB, // inter-row padding
            22,
            202,
        ];
        let rows = table_rows::<SyntheticRow>(
            &buffer,
            size_of_val(buffer.as_slice()),
            FIRST_ROW_OFFSET,
            ROW_STRIDE,
        )
        .expect("padded table should parse using its declared layout");

        assert_eq!(
            rows,
            vec![
                SyntheticRow {
                    value: 11,
                    pid: 101,
                },
                SyntheticRow {
                    value: 22,
                    pid: 202,
                },
            ]
        );
    }

    #[test]
    fn matches_ipv6_scope_ids_from_network_byte_order() {
        let workload = std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 51_234, 0, 17);
        let proxy = std::net::SocketAddrV6::new("fe80::2".parse().unwrap(), 31_234, 0, 23);
        let established = u32::try_from(MIB_TCP_STATE_ESTAB.0).unwrap();
        let row = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: workload.ip().octets(),
            dwLocalScopeId: workload.scope_id().to_be(),
            dwLocalPort: u32::from(workload.port().to_be()),
            ucRemoteAddr: proxy.ip().octets(),
            dwRemoteScopeId: proxy.scope_id().to_be(),
            dwRemotePort: u32::from(proxy.port().to_be()),
            dwState: established,
            dwOwningPid: 42,
        };

        assert!(ipv6_row_matches(&row, &workload, &proxy, established));
    }
}
