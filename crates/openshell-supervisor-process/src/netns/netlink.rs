// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! In-process network-namespace programming over route netlink.
//!
//! Replaces shelling out to `ip`/`nsenter` for sandbox netns setup. All
//! `rtnetlink` (async) work is confined here, driven from synchronous callers
//! via a local `current_thread` runtime. Host-side operations run on the
//! calling thread; namespace-scoped operations run on a dedicated OS thread
//! that `setns()` into the target namespace first.

use std::ffi::CString;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::Path;

use futures_util::stream::TryStreamExt;
use miette::{IntoDiagnostic, Result, miette};
use netlink_packet_route::route::{RouteAddress, RouteAttribute};

/// Bind-mount the calling thread's network namespace onto `target`.
///
/// Equivalent to what `ip netns add` does internally, but via `mount(2)` so no
/// external binary is required. Must run on the thread that just `unshare`d.
fn bind_mount_current_netns(target: &Path) -> Result<()> {
    let src = CString::new("/proc/thread-self/ns/net").expect("static path has no NUL");
    let tgt = CString::new(target.as_os_str().as_bytes()).into_diagnostic()?;
    let fstype = CString::new("none").expect("static string has no NUL");
    // SAFETY: libc FFI; bind-mounts the netns inode onto the target file.
    #[allow(unsafe_code)]
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fstype.as_ptr(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(miette!(
            "bind-mount netns onto {} failed: {}",
            target.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Unmount and remove the netns bind-mount file at `ns_path` (best-effort
/// unmount; propagates only the file-removal error).
fn unmount_and_remove(ns_path: &Path) -> Result<()> {
    if let Ok(tgt) = CString::new(ns_path.as_os_str().as_bytes()) {
        // SAFETY: libc FFI; lazy detach so a busy mount still unwinds.
        #[allow(unsafe_code)]
        unsafe {
            libc::umount2(tgt.as_ptr(), libc::MNT_DETACH);
        }
    }
    std::fs::remove_file(ns_path).into_diagnostic()
}

/// Create a fresh, FD-owned network namespace named `name`.
///
/// Runs `unshare(CLONE_NEWNET)` on a short-lived thread and bind-mounts the new
/// namespace onto `netns_path(name)` (via `mount(2)`, not `ip netns add`) so it
/// persists and stays reachable for the `nsenter`-based nft path. Returns a raw
/// fd opened on that path for the `setns` paths. The caller owns both and frees
/// them with [`destroy_netns`].
pub fn create_netns_fd(name: &str) -> Result<RawFd> {
    let ns_path = openshell_core::container_paths::netns_path(name);
    if let Some(dir) = ns_path.parent() {
        std::fs::create_dir_all(dir).into_diagnostic()?;
    }
    // Create the mount-target file (as `ip netns add` does).
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&ns_path)
        .into_diagnostic()?;

    // Unshare a new netns on a dedicated thread and bind-mount it onto the
    // target path. `/proc/thread-self` reflects THIS thread's namespaces,
    // unlike `/proc/self` which follows the thread-group leader.
    let target = ns_path.clone();
    let (tx, rx) = std::sync::mpsc::channel::<Result<()>>();
    std::thread::spawn(move || {
        let result = (|| -> Result<()> {
            // SAFETY: unshare affects only this dedicated, short-lived thread.
            #[allow(unsafe_code)]
            if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                return Err(miette!(
                    "unshare(CLONE_NEWNET) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            bind_mount_current_netns(&target)
        })();
        let _ = tx.send(result);
    });
    if let Err(e) = rx
        .recv()
        .map_err(|_| miette!("netns creation thread panicked"))?
    {
        let _ = std::fs::remove_file(&ns_path);
        return Err(e);
    }

    // Open a persistent fd on the bind-mounted netns for the `setns` paths.
    match nix::fcntl::open(
        ns_path.as_path(),
        nix::fcntl::OFlag::O_RDONLY,
        nix::sys::stat::Mode::empty(),
    ) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            let _ = unmount_and_remove(&ns_path);
            Err(e).into_diagnostic()
        }
    }
}

/// Tear down a namespace created by [`create_netns_fd`]: close the fd, unmount
/// the bind mount, and remove the target file.
pub fn destroy_netns(name: &str, fd: RawFd) -> Result<()> {
    // SAFETY: fd is owned by the caller and dropped here.
    #[allow(unsafe_code)]
    unsafe {
        libc::close(fd);
    }
    let ns_path = openshell_core::container_paths::netns_path(name);
    unmount_and_remove(&ns_path)
}

/// Build a local current-thread runtime, open a route-netlink connection
/// scoped to the current thread's network namespace, run `f`, then tear the
/// connection task down.
fn block_on_netlink<T, F>(f: impl FnOnce(rtnetlink::Handle) -> F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .into_diagnostic()?;
    rt.block_on(async move {
        let (connection, handle, _) = rtnetlink::new_connection().into_diagnostic()?;
        let conn_task = tokio::spawn(connection);
        let result = f(handle).await;
        conn_task.abort();
        result
    })
}

/// Resolve a link index by interface name in the current netns.
async fn link_index_by_name(handle: &rtnetlink::Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();
    let msg = links
        .try_next()
        .await
        .into_diagnostic()?
        .ok_or_else(|| miette!("link {name} not found"))?;
    Ok(msg.header.index)
}

/// Create the veth pair, move the sandbox peer into `ns_fd`, and configure the
/// host end (address + up). Runs in the caller's (host) network namespace.
pub fn setup_host_side(
    veth_host: &str,
    veth_sandbox: &str,
    host_ip: IpAddr,
    prefix: u8,
    ns_fd: RawFd,
) -> Result<()> {
    let veth_host = veth_host.to_string();
    let veth_sandbox = veth_sandbox.to_string();
    block_on_netlink(move |handle| async move {
        // Create veth pair.
        handle
            .link()
            .add()
            .veth(veth_host.clone(), veth_sandbox.clone())
            .execute()
            .await
            .into_diagnostic()?;

        // Move the sandbox peer into the target namespace by fd.
        let sandbox_idx = link_index_by_name(&handle, &veth_sandbox).await?;
        handle
            .link()
            .set(sandbox_idx)
            .setns_by_fd(ns_fd)
            .execute()
            .await
            .into_diagnostic()?;

        // Configure the host end: address + up.
        let host_idx = link_index_by_name(&handle, &veth_host).await?;
        handle
            .address()
            .add(host_idx, host_ip, prefix)
            .execute()
            .await
            .into_diagnostic()?;
        handle
            .link()
            .set(host_idx)
            .up()
            .execute()
            .await
            .into_diagnostic()?;
        Ok(())
    })
}

/// Run `work` on a dedicated OS thread that has `setns()`'d into `ns_fd`.
///
/// Mirrors the existing `bind_tcp_in_netns` pattern: a short-lived thread
/// enters the network namespace and exits, so no thread-pool worker is left
/// with contaminated namespace state.
fn in_netns_thread<T, W>(ns_fd: RawFd, work: W) -> Result<T>
where
    T: Send + 'static,
    W: FnOnce() -> Result<T> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel::<Result<T>>();
    std::thread::spawn(move || {
        let result = (|| -> Result<T> {
            // SAFETY: setns on a dedicated, short-lived thread.
            #[allow(unsafe_code)]
            if unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) } != 0 {
                return Err(miette!("setns failed: {}", std::io::Error::last_os_error()));
            }
            work()
        })();
        let _ = tx.send(result);
    });
    rx.recv()
        .map_err(|_| miette!("netns worker thread panicked"))?
}

/// Configure the sandbox end inside the namespace: address, link up, loopback
/// up, and default route via the host gateway.
pub fn setup_sandbox_side(
    ns_fd: RawFd,
    veth_sandbox: &str,
    sandbox_ip: IpAddr,
    prefix: u8,
    gateway: IpAddr,
) -> Result<()> {
    let veth_sandbox = veth_sandbox.to_string();
    in_netns_thread(ns_fd, move || {
        block_on_netlink(move |handle| async move {
            let sandbox_idx = link_index_by_name(&handle, &veth_sandbox).await?;
            handle
                .address()
                .add(sandbox_idx, sandbox_ip, prefix)
                .execute()
                .await
                .into_diagnostic()?;
            handle
                .link()
                .set(sandbox_idx)
                .up()
                .execute()
                .await
                .into_diagnostic()?;

            let lo_idx = link_index_by_name(&handle, "lo").await?;
            handle
                .link()
                .set(lo_idx)
                .up()
                .execute()
                .await
                .into_diagnostic()?;

            // Default route via the host gateway.
            let route = handle.route().add();
            match gateway {
                IpAddr::V4(gw) => route.v4().gateway(gw).execute().await.into_diagnostic()?,
                IpAddr::V6(gw) => route.v6().gateway(gw).execute().await.into_diagnostic()?,
            }
            Ok(())
        })
    })
}

/// Delete a link by name in the current (host) network namespace. Removing a
/// veth end removes its peer too.
pub fn delete_link(name: &str) -> Result<()> {
    let name = name.to_string();
    block_on_netlink(move |handle| async move {
        let idx = link_index_by_name(&handle, &name).await?;
        handle.link().del(idx).execute().await.into_diagnostic()?;
        Ok(())
    })
}

/// Replace a route for `cidr` with output interface `lo`, inside `ns_fd`.
/// Used to attract the synthetic IPv6 pool to the local transparent listener.
pub fn replace_route_dev_lo_in_netns(ns_fd: RawFd, cidr: ipnet::IpNet) -> Result<()> {
    in_netns_thread(ns_fd, move || {
        block_on_netlink(move |handle| async move {
            let lo = link_index_by_name(&handle, "lo").await?;
            match cidr {
                ipnet::IpNet::V4(n) => handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(n.addr(), n.prefix_len())
                    .output_interface(lo)
                    .replace()
                    .execute()
                    .await
                    .into_diagnostic()?,
                ipnet::IpNet::V6(n) => handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix(n.addr(), n.prefix_len())
                    .output_interface(lo)
                    .replace()
                    .execute()
                    .await
                    .into_diagnostic()?,
            }
            Ok(())
        })
    })
}

/// Dump destination prefixes of all routes for one family inside `ns_fd`. A
/// missing destination attribute denotes the default route and is returned as
/// `0.0.0.0/0` or `::/0`.
pub fn dump_route_prefixes_in_netns(ns_fd: RawFd, v6: bool) -> Result<Vec<ipnet::IpNet>> {
    in_netns_thread(ns_fd, move || {
        block_on_netlink(move |handle| async move {
            let ip_version = if v6 {
                rtnetlink::IpVersion::V6
            } else {
                rtnetlink::IpVersion::V4
            };
            let mut routes = handle.route().get(ip_version).execute();
            let mut out = Vec::new();
            while let Some(route) = routes.try_next().await.into_diagnostic()? {
                let prefix_len = route.header.destination_prefix_length;
                let dst = route.attributes.iter().find_map(|attr| match attr {
                    RouteAttribute::Destination(RouteAddress::Inet(a)) => Some(IpAddr::V4(*a)),
                    RouteAttribute::Destination(RouteAddress::Inet6(a)) => Some(IpAddr::V6(*a)),
                    _ => None,
                });
                let addr = dst.unwrap_or(if v6 {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                });
                if let Ok(net) = ipnet::IpNet::new(addr, prefix_len) {
                    out.push(net);
                }
            }
            Ok(out)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Root-only: creating an FD-owned netns yields an fd pointing at a
    /// different network namespace than the caller's.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn create_netns_fd_is_isolated() {
        let self_ns = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        let fd = create_netns_fd("nl-test-iso").expect("create netns fd");
        let created_ns = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert_ne!(
            self_ns, created_ns,
            "created namespace must differ from the caller's"
        );
        let _ = destroy_netns("nl-test-iso", fd);
    }

    /// Root-only: host-side setup creates veth-h on the host and moves veth-s
    /// out of the host namespace.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn setup_host_side_creates_and_moves() {
        let ns_fd = create_netns_fd("nl-test-host").expect("netns fd");
        let host_ip: IpAddr = "10.200.0.1".parse().unwrap();
        let veth_h = "veth-h-test0001";
        let veth_s = "veth-s-test0001";

        setup_host_side(veth_h, veth_s, host_ip, 24, ns_fd).expect("host side");

        let host_has_h = block_on_netlink(|h| async move {
            Ok(link_index_by_name(&h, "veth-h-test0001").await.is_ok())
        })
        .unwrap();
        assert!(host_has_h, "veth-h must exist on host");
        let host_has_s = block_on_netlink(|h| async move {
            Ok(link_index_by_name(&h, "veth-s-test0001").await.is_ok())
        })
        .unwrap();
        assert!(!host_has_s, "veth-s must have moved into the netns");

        let _ = delete_link(veth_h);
        let _ = destroy_netns("nl-test-host", ns_fd);
    }

    /// Root-only: after host setup, sandbox-side setup installs the sandbox
    /// address and a default route inside the namespace.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn setup_sandbox_side_installs_addr_and_route() {
        let ns_fd = create_netns_fd("nl-test-sbx").expect("netns fd");
        let host_ip: IpAddr = "10.200.0.1".parse().unwrap();
        let sandbox_ip: IpAddr = "10.200.0.2".parse().unwrap();
        let veth_h = "veth-h-test0002";
        let veth_s = "veth-s-test0002";

        setup_host_side(veth_h, veth_s, host_ip, 24, ns_fd).expect("host side");
        setup_sandbox_side(ns_fd, veth_s, sandbox_ip, 24, host_ip).expect("sandbox side");

        let routes = dump_route_prefixes_in_netns(ns_fd, false).expect("dump v4 routes");
        assert!(
            routes.iter().any(|p| p.prefix_len() == 0),
            "default route must be present in the namespace"
        );

        let _ = delete_link(veth_h);
        let _ = destroy_netns("nl-test-sbx", ns_fd);
    }

    /// Root-only: delete_link removes a host veth end.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn delete_link_removes_interface() {
        let ns_fd = create_netns_fd("nl-test-del").expect("netns fd");
        let host_ip: IpAddr = "10.200.0.1".parse().unwrap();
        setup_host_side("veth-h-test0003", "veth-s-test0003", host_ip, 24, ns_fd)
            .expect("host side");

        delete_link("veth-h-test0003").expect("delete");

        let still_there = block_on_netlink(|h| async move {
            Ok(link_index_by_name(&h, "veth-h-test0003").await.is_ok())
        })
        .unwrap();
        assert!(!still_there, "veth-h must be gone after delete_link");
        let _ = destroy_netns("nl-test-del", ns_fd);
    }

    /// Root-only: dump_route_prefixes_in_netns sees a route added on lo.
    #[test]
    #[ignore = "requires root / CAP_NET_ADMIN"]
    fn replace_and_dump_lo_route() {
        let ns_fd = create_netns_fd("nl-test-route").expect("netns fd");
        // lo must be up for a route to install.
        in_netns_thread(ns_fd, || {
            block_on_netlink(|h| async move {
                let lo = link_index_by_name(&h, "lo").await?;
                h.link().set(lo).up().execute().await.into_diagnostic()?;
                Ok(())
            })
        })
        .unwrap();

        let cidr: ipnet::IpNet = "fd00:dead:beef::/48".parse().unwrap();
        replace_route_dev_lo_in_netns(ns_fd, cidr).expect("route replace");

        let routes = dump_route_prefixes_in_netns(ns_fd, true).expect("dump v6");
        assert!(
            routes.contains(&cidr),
            "installed route must appear in dump"
        );
        let _ = destroy_netns("nl-test-route", ns_fd);
    }
}
