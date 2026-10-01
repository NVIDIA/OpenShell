// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Behavioral tests for the compiled shim object.
//!
//! The shim replaces one address-bearing `accept` with `accept4(NULL)` plus
//! `getpeername`. That rewrite is only safe if it is indistinguishable from a
//! plain `accept` for the workload, so these tests load the real object and
//! compare it against libc on an ordinary socket. No seccomp broker is
//! involved: the broker is what makes the rewrite *necessary*, not what makes
//! it *correct*, and leaving it out lets these run on any Linux host.

#![cfg(target_os = "linux")]
// Loading and calling the object under test is inherently unsafe: it is a
// shared library resolved at run time and invoked through raw pointers.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::io::{Error, Read as _, Write as _};
use std::mem::{size_of, transmute};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::process::id as process_id;
use std::ptr::null_mut;
use std::sync::OnceLock;

use libc::{
    AF_INET, AF_INET6, EINVAL, RTLD_LOCAL, RTLD_NOW, c_int, c_void, sockaddr, sockaddr_in,
    sockaddr_in6, sockaddr_storage, socklen_t,
};

use openshell_accept_shim::{SHIM_OBJECT, install_object_at};

type Accept4Fn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t, c_int) -> c_int;

type AcceptFn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;

/// The shim loaded the way a workload loads it: through the dynamic loader.
struct Shim {
    accept4: Accept4Fn,
    accept: AcceptFn,
}

impl Shim {
    fn load() -> Self {
        let directory =
            std::env::temp_dir().join(format!("openshell-shim-behavior-{}", process_id()));
        let _ = std::fs::remove_dir_all(&directory);
        let path = install_object_at(&directory, SHIM_OBJECT).expect("install shim object");

        let c_path = CString::new(path.as_os_str().as_encoded_bytes())
            .expect("shim path has no interior NUL");
        // RTLD_NOW so an unresolved symbol fails here rather than at the call
        // site; the object's sole undefined symbol is `__errno_location`,
        // which the already-loaded libc provides.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        assert!(!handle.is_null(), "dlopen: {}", dl_error());

        Self {
            accept4: unsafe { transmute::<*mut c_void, Accept4Fn>(symbol(handle, c"accept4")) },
            accept: unsafe { transmute::<*mut c_void, AcceptFn>(symbol(handle, c"accept")) },
        }
    }
}

fn symbol(handle: *mut c_void, name: &CStr) -> *mut c_void {
    let resolved = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(
        !resolved.is_null(),
        "dlsym {}: {}",
        name.to_string_lossy(),
        dl_error()
    );
    resolved
}

fn dl_error() -> String {
    let message = unsafe { libc::dlerror() };
    if message.is_null() {
        return "no error reported".to_string();
    }
    unsafe { CStr::from_ptr(message) }
        .to_string_lossy()
        .into_owned()
}

fn shim() -> &'static Shim {
    static SHIM: OnceLock<Shim> = OnceLock::new();
    SHIM.get_or_init(Shim::load)
}

/// A listener with one pending connection from a known local address.
struct Pending {
    listener: TcpListener,
    client: TcpStream,
}

fn pending_connection(bind: SocketAddr) -> Pending {
    let listener = TcpListener::bind(bind).expect("bind listener");
    let client = TcpStream::connect(listener.local_addr().expect("local addr")).expect("connect");
    Pending { listener, client }
}

/// What the kernel reports for `fd`'s peer, with no truncation.
fn kernel_peer(fd: c_int) -> (Vec<u8>, socklen_t) {
    let mut storage = [0u8; size_of::<sockaddr_storage>()];
    let mut length = storage.len() as socklen_t;
    let result =
        unsafe { libc::getpeername(fd, storage.as_mut_ptr().cast::<sockaddr>(), &raw mut length) };
    assert_eq!(result, 0, "getpeername: {}", Error::last_os_error());
    (storage[..length as usize].to_vec(), length)
}

/// Accept through the shim into a sentinel-filled buffer of `capacity` bytes.
///
/// Returns the accepted descriptor, the whole buffer, and the `addrlen` the
/// shim reported, so a caller can check both what was written and what was
/// left alone.
fn shim_accept4(listener: &TcpListener, capacity: socklen_t) -> (c_int, Vec<u8>, socklen_t) {
    const SENTINEL: u8 = 0xAA;
    let mut buffer = vec![SENTINEL; size_of::<sockaddr_storage>()];
    let mut length = capacity;
    let accepted = unsafe {
        (shim().accept4)(
            listener.as_raw_fd(),
            buffer.as_mut_ptr().cast::<sockaddr>(),
            &raw mut length,
            0,
        )
    };
    assert!(accepted >= 0, "shim accept4: {}", Error::last_os_error());
    (accepted, buffer, length)
}

fn close(fd: c_int) {
    assert_eq!(unsafe { libc::close(fd) }, 0, "close accepted descriptor");
}

#[test]
fn the_reported_peer_matches_the_kernel_for_ipv4() {
    let pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let expected_port = pending
        .client
        .local_addr()
        .expect("client local addr")
        .port();

    let capacity = size_of::<sockaddr_in>() as socklen_t;
    let (accepted, buffer, length) = shim_accept4(&pending.listener, capacity);
    let (kernel, kernel_length) = kernel_peer(accepted);

    assert_eq!(length, kernel_length);
    assert_eq!(&buffer[..length as usize], &kernel[..]);

    // The whole point of the rewrite: the caller learns the *client's*
    // ephemeral port, not the listener's.
    let family = u16::from_ne_bytes([buffer[0], buffer[1]]);
    assert_eq!(c_int::from(family), AF_INET);
    let port = u16::from_be_bytes([buffer[2], buffer[3]]);
    assert_eq!(port, expected_port);
    assert_ne!(
        port,
        pending.listener.local_addr().expect("listener addr").port()
    );

    close(accepted);
}

#[test]
fn the_reported_peer_matches_the_kernel_for_ipv6() {
    let pending = pending_connection(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)));
    let expected_port = pending
        .client
        .local_addr()
        .expect("client local addr")
        .port();

    let capacity = size_of::<sockaddr_in6>() as socklen_t;
    let (accepted, buffer, length) = shim_accept4(&pending.listener, capacity);
    let (kernel, kernel_length) = kernel_peer(accepted);

    assert_eq!(length, kernel_length);
    assert_eq!(&buffer[..length as usize], &kernel[..]);

    let family = u16::from_ne_bytes([buffer[0], buffer[1]]);
    assert_eq!(c_int::from(family), AF_INET6);
    let port = u16::from_be_bytes([buffer[2], buffer[3]]);
    assert_eq!(port, expected_port);

    close(accepted);
}

#[test]
fn a_short_buffer_truncates_and_still_reports_the_full_length() {
    // Linux signals truncation by returning an `addrlen` larger than the one
    // supplied. A caller that trusts the returned length would read past its
    // own buffer if the shim reported the truncated length instead.
    let full = size_of::<sockaddr_in>() as socklen_t;

    for capacity in [0, 4, 8, full - 1] {
        let pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let (accepted, buffer, length) = shim_accept4(&pending.listener, capacity);
        let (kernel, _) = kernel_peer(accepted);

        assert_eq!(
            length, full,
            "capacity {capacity} must report the untruncated length"
        );
        assert_eq!(
            &buffer[..capacity as usize],
            &kernel[..capacity as usize],
            "capacity {capacity} wrote the wrong prefix"
        );
        assert!(
            buffer[capacity as usize..].iter().all(|byte| *byte == 0xAA),
            "capacity {capacity} wrote past the caller's buffer"
        );

        close(accepted);
    }
}

#[test]
fn an_oversized_buffer_is_filled_only_to_the_address_length() {
    let pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let oversized = size_of::<sockaddr_storage>() as socklen_t;

    let (accepted, buffer, length) = shim_accept4(&pending.listener, oversized);

    assert_eq!(length, size_of::<sockaddr_in>() as socklen_t);
    assert!(
        buffer[length as usize..].iter().all(|byte| *byte == 0xAA),
        "bytes beyond the address must be left alone"
    );

    close(accepted);
}

#[test]
fn a_v4_mapped_peer_is_reported_as_the_kernel_reports_it() {
    // A dual-stack listener reports IPv4 clients as v4-mapped IPv6. The shim
    // must not normalize that, or a workload's own address parsing diverges
    // from what it would see without the shim.
    let listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
        .expect("bind dual-stack listener");
    let port = listener.local_addr().expect("local addr").port();
    let Ok(client) = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))) else {
        // A host with `bindv6only` set has no dual-stack listener to test.
        return;
    };
    let expected_port = client.local_addr().expect("client local addr").port();

    let capacity = size_of::<sockaddr_in6>() as socklen_t;
    let (accepted, buffer, length) = shim_accept4(&listener, capacity);
    let (kernel, kernel_length) = kernel_peer(accepted);

    assert_eq!(length, kernel_length);
    assert_eq!(&buffer[..length as usize], &kernel[..]);

    let family = u16::from_ne_bytes([buffer[0], buffer[1]]);
    assert_eq!(c_int::from(family), AF_INET6);
    assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), expected_port);

    close(accepted);
}

#[test]
fn a_null_address_still_accepts_the_connection() {
    let pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));

    let accepted =
        unsafe { (shim().accept4)(pending.listener.as_raw_fd(), null_mut(), null_mut(), 0) };

    assert!(
        accepted >= 0,
        "shim accept4 with no address: {}",
        Error::last_os_error()
    );
    close(accepted);
}

#[test]
fn the_accepted_descriptor_carries_the_connection() {
    // The rewrite returns a descriptor from a second syscall. If it ever
    // returned the wrong one, addresses could still look right while the
    // stream was unusable.
    let mut pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));

    let capacity = size_of::<sockaddr_in>() as socklen_t;
    let (accepted, _, _) = shim_accept4(&pending.listener, capacity);

    pending.client.write_all(b"ping").expect("client write");
    let written = unsafe { libc::write(accepted, c"pong".as_ptr().cast(), 4) };
    assert_eq!(written, 4, "write to accepted descriptor");

    let mut received = [0u8; 4];
    let read = unsafe { libc::read(accepted, received.as_mut_ptr().cast(), 4) };
    assert_eq!(read, 4, "read from accepted descriptor");
    assert_eq!(&received, b"ping");

    let mut echoed = [0u8; 4];
    pending.client.read_exact(&mut echoed).expect("client read");
    assert_eq!(&echoed, b"pong");

    close(accepted);
}

#[test]
fn the_accept_entry_point_behaves_like_accept4_without_flags() {
    let pending = pending_connection(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
    let expected_port = pending
        .client
        .local_addr()
        .expect("client local addr")
        .port();

    let mut buffer = vec![0xAAu8; size_of::<sockaddr_storage>()];
    let mut length = size_of::<sockaddr_in>() as socklen_t;
    let accepted = unsafe {
        (shim().accept)(
            pending.listener.as_raw_fd(),
            buffer.as_mut_ptr().cast::<sockaddr>(),
            &raw mut length,
        )
    };

    assert!(accepted >= 0, "shim accept: {}", Error::last_os_error());
    assert_eq!(u16::from_be_bytes([buffer[2], buffer[3]]), expected_port);

    close(accepted);
}

#[test]
fn a_failing_accept_reports_the_kernel_error() {
    // `shim_finish` must translate a raw negative return into `-1` plus
    // `errno`; a workload that sees the raw value instead would treat a
    // failure as a valid descriptor.
    let not_a_listener = TcpStream::connect(
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind")
            .local_addr()
            .expect("addr"),
    );
    let Ok(stream) = not_a_listener else {
        return;
    };

    let mut buffer = vec![0u8; size_of::<sockaddr_storage>()];
    let mut length = buffer.len() as socklen_t;
    let result = unsafe {
        (shim().accept4)(
            stream.as_raw_fd(),
            buffer.as_mut_ptr().cast::<sockaddr>(),
            &raw mut length,
            0,
        )
    };

    assert_eq!(result, -1, "accept on a connected socket must fail");
    assert_eq!(Error::last_os_error().raw_os_error(), Some(EINVAL));
}
