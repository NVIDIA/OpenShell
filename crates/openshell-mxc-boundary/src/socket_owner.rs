// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows TCP socket-owner and process-image resolution.

use std::mem::{offset_of, size_of, size_of_val};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

type Result<T> = std::result::Result<T, String>;
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

#[derive(Clone, Copy)]
struct WorkloadProxyTcpConnection {
    workload: SocketAddr,
    proxy: SocketAddr,
}
impl std::fmt::Display for WorkloadProxyTcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.workload, self.proxy)
    }
}
impl WorkloadProxyTcpConnection {
    fn new(workload: SocketAddr, proxy: SocketAddr) -> Self {
        Self { workload, proxy }
    }
}

/// Resolve the unique owning process from the Windows kernel TCP table.
pub fn resolve_connection_owner(workload: SocketAddr, proxy: SocketAddr) -> Result<(PathBuf, u32)> {
    resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(workload, proxy))
}

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
///
/// The workload-side row is selected by its exact four-tuple and a nonzero
/// owning PID. Its reported TCP state is not used: some Windows builds report
/// an incorrect `dwState` (for example `CLOSED`, `LISTEN`, `FIN_WAIT1`, or `0`)
/// for some live IPv4 loopback connections whose addresses and owning PID are
/// correct. TCP keeps one connection per four-tuple, and the proxy holds the
/// accepted connection open while resolving its owner. Rows without an owning
/// process, such as `TIME_WAIT`, report PID 0.
fn resolve_tcp_peer_identity(connection: WorkloadProxyTcpConnection) -> Result<(PathBuf, u32)> {
    let mut owners = match (connection.workload, connection.proxy) {
        (SocketAddr::V4(workload), SocketAddr::V4(proxy)) => ipv4_owner_pids(workload, proxy)?,
        (SocketAddr::V6(workload), SocketAddr::V6(proxy)) => ipv6_owner_pids(&workload, &proxy)?,
        _ => {
            return Err(format!(
                "TCP connection address families do not match: {connection}"
            ));
        }
    };
    owners.sort_unstable();
    owners.dedup();

    let pid = match owners.as_slice() {
        [pid] => *pid,
        [] => {
            return Err(format!(
                "No Windows process owns proxy connection {connection}"
            ));
        }
        pids => {
            return Err(format!(
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
    Ok(rows
        .into_iter()
        .filter(|row| ipv4_row_matches(row, workload, proxy))
        .map(|row| row.dwOwningPid)
        .collect())
}

fn ipv4_row_matches(
    row: &MIB_TCPROW_OWNER_PID,
    workload: std::net::SocketAddrV4,
    proxy: std::net::SocketAddrV4,
) -> bool {
    row.dwOwningPid != 0
        && Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()) == *workload.ip()
        && tcp_port(row.dwLocalPort) == workload.port()
        && Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()) == *proxy.ip()
        && tcp_port(row.dwRemotePort) == proxy.port()
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
    Ok(rows
        .into_iter()
        .filter(|row| ipv6_row_matches(row, workload, proxy))
        .map(|row| row.dwOwningPid)
        .collect())
}

fn ipv6_row_matches(
    row: &MIB_TCP6ROW_OWNER_PID,
    workload: &std::net::SocketAddrV6,
    proxy: &std::net::SocketAddrV6,
) -> bool {
    row.dwOwningPid != 0
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
        return Err(format!(
            "GetExtendedTcpTable size query failed with Win32 error {initial}"
        ));
    }

    for _ in 0..3 {
        let mut buffer = vec![0u32; (byte_len as usize).div_ceil(size_of::<u32>()).max(1)];
        let mut actual_len = u32::try_from(buffer.len() * size_of::<u32>())
            .map_err(|_| "TCP table buffer is too large".to_string())?;
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
            return Err(format!(
                "GetExtendedTcpTable failed with Win32 error {status}"
            ));
        }
        byte_len = actual_len;
    }

    Err("GetExtendedTcpTable changed size during three consecutive reads".to_string())
}

fn table_rows<T: Copy>(
    buffer: &[u32],
    byte_len: usize,
    first_row_offset: usize,
    row_stride: usize,
) -> Result<Vec<T>> {
    if byte_len < size_of::<u32>() {
        return Err("Windows TCP table is missing its header".to_string());
    }
    if row_stride < size_of::<T>() {
        return Err(format!(
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
                    .ok_or_else(|| "Windows TCP row count overflow".to_string())?,
            )
            .and_then(|last_row| last_row.checked_add(size_of::<T>()))
            .ok_or_else(|| "Windows TCP table size overflow".to_string())?
    };
    if required > byte_len || required > size_of_val(buffer) {
        return Err(format!(
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
            .map_err(|error| format!("Failed to open socket-owning PID {pid}: {error}"))?,
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
        format!("Failed to query executable path for socket-owning PID {pid}: {error}")
    })?;
    path.truncate(path_len as usize);
    Ok(PathBuf::from(String::from_utf16(&path).map_err(
        |error| format!("Socket-owning PID {pid} returned an invalid UTF-16 path: {error}"),
    )?))
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use windows::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_ESTAB, MIB_TCP_STATE_RESERVED,
    };

    use super::*;

    const CHILD_PORT_ENV: &str = "OPENSHELL_TEST_WINDOWS_SOCKET_OWNER_PORT";
    const CHILD_CONNECTIONS_ENV: &str = "OPENSHELL_TEST_WINDOWS_SOCKET_OWNER_CONNECTIONS";
    const CHILD_SHUTDOWN_WRITE_ENV: &str = "OPENSHELL_TEST_WINDOWS_SOCKET_OWNER_SHUTDOWN_WRITE";

    /// Child process body: open the requested connections to the parent's
    /// listener and hold them until the parent closes its side.
    #[test]
    fn socket_owner_child() {
        let Ok(port) = std::env::var(CHILD_PORT_ENV) else {
            return;
        };
        let port = port.parse::<u16>().unwrap();
        let connections =
            std::env::var(CHILD_CONNECTIONS_ENV).map_or(1, |count| count.parse::<usize>().unwrap());
        let mut streams = (0..connections)
            .map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap())
            .collect::<Vec<_>>();
        if std::env::var_os(CHILD_SHUTDOWN_WRITE_ENV).is_some() {
            for stream in &streams {
                stream.shutdown(Shutdown::Write).unwrap();
            }
        }
        let mut byte = [0u8; 1];
        for stream in &mut streams {
            let _ = stream.read(&mut byte);
        }
    }

    fn spawn_socket_owner_child(
        port: u16,
        connections: usize,
        shutdown_write: bool,
    ) -> std::process::Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "socket_owner::tests::socket_owner_child",
                "--nocapture",
            ])
            .env(CHILD_PORT_ENV, port.to_string())
            .env(CHILD_CONNECTIONS_ENV, connections.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if shutdown_write {
            command.env(CHILD_SHUTDOWN_WRITE_ENV, "1");
        }
        command.spawn().unwrap()
    }

    fn ipv4_row(
        workload: std::net::SocketAddrV4,
        proxy: std::net::SocketAddrV4,
        state: u32,
        pid: u32,
    ) -> MIB_TCPROW_OWNER_PID {
        MIB_TCPROW_OWNER_PID {
            dwState: state,
            dwLocalAddr: u32::from_ne_bytes(workload.ip().octets()),
            dwLocalPort: u32::from(workload.port().to_be()),
            dwRemoteAddr: u32::from_ne_bytes(proxy.ip().octets()),
            dwRemotePort: u32::from(proxy.port().to_be()),
            dwOwningPid: pid,
        }
    }

    fn ipv6_row(
        workload: &std::net::SocketAddrV6,
        proxy: &std::net::SocketAddrV6,
        state: u32,
        pid: u32,
    ) -> MIB_TCP6ROW_OWNER_PID {
        MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: workload.ip().octets(),
            dwLocalScopeId: workload.scope_id().to_be(),
            dwLocalPort: u32::from(workload.port().to_be()),
            ucRemoteAddr: proxy.ip().octets(),
            dwRemoteScopeId: proxy.scope_id().to_be(),
            dwRemotePort: u32::from(proxy.port().to_be()),
            dwState: state,
            dwOwningPid: pid,
        }
    }

    /// Every `MIB_TCP_STATE` value (`CLOSED` through `DELETE_TCB`, and
    /// `RESERVED`), plus `0`, which is not a defined state but which some
    /// Windows builds report for live connections.
    fn reported_tcp_states() -> impl Iterator<Item = u32> {
        (0..=u32::try_from(MIB_TCP_STATE_DELETE_TCB.0).unwrap())
            .chain([u32::try_from(MIB_TCP_STATE_RESERVED.0).unwrap()])
    }

    #[test]
    fn resolves_child_that_owns_ipv4_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let mut child = spawn_socket_owner_child(proxy.port(), 1, false);

        let (accepted, workload) = listener.accept().unwrap();
        let result = resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(workload, proxy));
        drop(accepted);
        let status = child.wait().unwrap();
        assert!(status.success());

        let (path, pid) = result.unwrap();
        assert_eq!(pid, child.id());
        assert_eq!(path, current_exe);
    }

    /// Stress check: every connection a child holds open resolves to that
    /// child, including rows that the host reports in a state other than
    /// `ESTAB`.
    #[test]
    fn resolves_every_connection_a_child_holds_open() {
        const CONNECTIONS: usize = 64;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let mut child = spawn_socket_owner_child(proxy.port(), CONNECTIONS, false);

        let accepted = (0..CONNECTIONS)
            .map(|_| listener.accept().unwrap())
            .collect::<Vec<_>>();
        let failures = accepted
            .iter()
            .filter_map(|(_, workload)| {
                match resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(*workload, proxy)) {
                    Ok((path, pid)) if pid == child.id() && path == current_exe => None,
                    Ok((path, pid)) => Some(format!("{workload}: PID {pid} {}", path.display())),
                    Err(error) => Some(error),
                }
            })
            .collect::<Vec<_>>();
        drop(accepted);
        let status = child.wait().unwrap();
        assert!(status.success());

        assert!(
            failures.is_empty(),
            "{} of {CONNECTIONS} live connections did not resolve to the child: {failures:#?}",
            failures.len()
        );
    }

    /// A client that has shut down its send direction still owns its socket,
    /// although its row no longer reports `ESTAB`.
    #[test]
    fn resolves_half_closed_connection_to_its_owner() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let mut child = spawn_socket_owner_child(proxy.port(), 1, true);

        let (mut accepted, workload) = listener.accept().unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        // End of stream means the child's FIN has arrived.
        accepted.read_to_end(&mut Vec::new()).unwrap();
        let result = resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(workload, proxy));
        drop(accepted);
        let status = child.wait().unwrap();
        assert!(status.success());

        let (path, pid) = result.unwrap();
        assert_eq!(pid, child.id());
        assert_eq!(path, current_exe);
    }

    /// Once both sides close, the workload-side row has no owning process
    /// (`TIME_WAIT` reports PID 0) and the connection must not resolve.
    #[test]
    fn does_not_resolve_connection_after_both_sides_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap();
        let client = TcpStream::connect(proxy).unwrap();
        let (mut accepted, workload) = listener.accept().unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        drop(client);
        accepted.read_to_end(&mut Vec::new()).unwrap();
        drop(accepted);

        let error = resolve_tcp_peer_identity(WorkloadProxyTcpConnection::new(workload, proxy))
            .unwrap_err();
        assert!(
            error.starts_with("No Windows process owns proxy connection"),
            "{error}"
        );
    }

    #[test]
    fn row_match_ignores_reported_tcp_state() {
        let workload: std::net::SocketAddrV4 = "127.0.0.1:51234".parse().unwrap();
        let proxy: std::net::SocketAddrV4 = "127.0.0.1:3128".parse().unwrap();
        let workload6 = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51_234, 0, 0);
        let proxy6 = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3128, 0, 0);
        for state in reported_tcp_states() {
            assert!(
                ipv4_row_matches(&ipv4_row(workload, proxy, state, 42), workload, proxy),
                "IPv4 row in state {state}"
            );
            assert!(
                ipv6_row_matches(
                    &ipv6_row(&workload6, &proxy6, state, 42),
                    &workload6,
                    &proxy6
                ),
                "IPv6 row in state {state}"
            );
        }
    }

    #[test]
    fn row_match_requires_an_owning_process() {
        let workload: std::net::SocketAddrV4 = "127.0.0.1:51234".parse().unwrap();
        let proxy: std::net::SocketAddrV4 = "127.0.0.1:3128".parse().unwrap();
        let workload6 = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 51_234, 0, 0);
        let proxy6 = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3128, 0, 0);
        for state in reported_tcp_states() {
            assert!(
                !ipv4_row_matches(&ipv4_row(workload, proxy, state, 0), workload, proxy),
                "IPv4 row in state {state}"
            );
            assert!(
                !ipv6_row_matches(
                    &ipv6_row(&workload6, &proxy6, state, 0),
                    &workload6,
                    &proxy6
                ),
                "IPv6 row in state {state}"
            );
        }
    }

    #[test]
    fn ipv4_row_match_requires_the_exact_four_tuple() {
        let workload: std::net::SocketAddrV4 = "127.0.0.1:51234".parse().unwrap();
        let proxy: std::net::SocketAddrV4 = "127.0.0.1:3128".parse().unwrap();
        let established = u32::try_from(MIB_TCP_STATE_ESTAB.0).unwrap();
        for (row_workload, row_proxy) in [
            ("127.0.0.2:51234", "127.0.0.1:3128"),
            ("127.0.0.1:51235", "127.0.0.1:3128"),
            ("127.0.0.1:51234", "127.0.0.2:3128"),
            ("127.0.0.1:51234", "127.0.0.1:3129"),
            // The proxy's accepted socket has the reversed tuple.
            ("127.0.0.1:3128", "127.0.0.1:51234"),
        ] {
            let row = ipv4_row(
                row_workload.parse().unwrap(),
                row_proxy.parse().unwrap(),
                established,
                42,
            );
            assert!(
                !ipv4_row_matches(&row, workload, proxy),
                "{row_workload} -> {row_proxy}"
            );
        }
    }

    #[test]
    fn ipv6_row_match_requires_the_exact_four_tuple_and_scope_ids() {
        let address = |ip: &str, port: u16, scope_id: u32| {
            std::net::SocketAddrV6::new(ip.parse().unwrap(), port, 0, scope_id)
        };
        let workload = address("fe80::1", 51_234, 17);
        let proxy = address("fe80::2", 3128, 23);
        let established = u32::try_from(MIB_TCP_STATE_ESTAB.0).unwrap();
        for (row_workload, row_proxy) in [
            (address("fe80::3", 51_234, 17), proxy),
            (address("fe80::1", 51_235, 17), proxy),
            (address("fe80::1", 51_234, 18), proxy),
            (workload, address("fe80::3", 3128, 23)),
            (workload, address("fe80::2", 3129, 23)),
            (workload, address("fe80::2", 3128, 24)),
            // The proxy's accepted socket has the reversed tuple.
            (proxy, workload),
        ] {
            let row = ipv6_row(&row_workload, &row_proxy, established, 42);
            assert!(
                !ipv6_row_matches(&row, &workload, &proxy),
                "{row_workload} -> {row_proxy}"
            );
        }
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
        let row = ipv6_row(&workload, &proxy, established, 42);

        assert!(ipv6_row_matches(&row, &workload, &proxy));
    }
}
