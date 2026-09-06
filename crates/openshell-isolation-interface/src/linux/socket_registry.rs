// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded registry for socket-time seccomp virtualization.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::io;
use std::mem::size_of;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::fstat;

use super::proc_fd;

/// Stable identity for one mediated socket within a listener generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketIdentity {
    /// Generation of the seccomp listener that created the socket.
    pub listener_generation: u64,
    /// Socket inode observed from the source descriptor.
    pub inode: u64,
    /// Kernel `SO_COOKIE` value.
    pub cookie: u64,
}

/// Supported INET address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InetFamily {
    /// `AF_INET`.
    V4,
    /// `AF_INET6`.
    V6,
}

/// Supported INET socket kind and protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InetKind {
    /// TCP stream socket.
    Tcp,
    /// UDP datagram socket restricted to the DNS relay.
    DnsUdp,
}

/// Immutable socket metadata captured before ADDFD-SEND.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketMetadata {
    /// Address family.
    pub family: InetFamily,
    /// Socket kind/protocol.
    pub kind: InetKind,
    /// Whether the injected descriptor must be close-on-exec.
    pub close_on_exec: bool,
    /// Whether the socket's open-file description is nonblocking.
    pub nonblocking: bool,
    /// Task generation that created the socket.
    pub creator_generation: u64,
}

/// Stable state of one socket open-file description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SocketState {
    /// Created but not bound or connected.
    Created,
    /// Explicitly bound by the workload.
    Bound { local: SocketAddr },
    /// Connected through an external supervisor relay.
    Connected { original_peer: SocketAddr },
    /// Connected directly to an allowed workload loopback endpoint.
    Local { peer: SocketAddr },
    /// UDP socket pinned to the exact local DNS relay.
    DnsUdp { relay: SocketAddr },
    /// TCP socket pinned to the exact local DNS relay.
    DnsTcp { relay: SocketAddr },
    /// Workload-owned listening socket.
    Listening { local: SocketAddr },
    /// Stream accepted from a verified local peer.
    AcceptedLocal { peer: SocketAddr },
    /// A committed relay failed after connection.
    Failed { errno: i32 },
}

/// One committed registry entry.
#[derive(Debug)]
pub struct SocketEntry {
    identity: SocketIdentity,
    metadata: SocketMetadata,
    state: SocketState,
    retained_preconnect: Option<OwnedFd>,
}

impl SocketEntry {
    /// Stable socket identity.
    #[must_use]
    pub fn identity(&self) -> SocketIdentity {
        self.identity
    }

    /// Immutable creation metadata.
    #[must_use]
    pub fn metadata(&self) -> SocketMetadata {
        self.metadata
    }

    /// Current stable state.
    #[must_use]
    pub fn state(&self) -> &SocketState {
        &self.state
    }

    /// Retained source descriptor used to perform pre-connect operations on
    /// the exact injected open-file description.
    pub fn retained_preconnect(&self) -> io::Result<&OwnedFd> {
        self.retained_preconnect.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "socket no longer has a retained pre-connect descriptor",
            )
        })
    }

    /// Replace the stable state. Callers perform policy and notification
    /// revalidation before invoking this commit primitive.
    pub fn set_state(&mut self, state: SocketState) {
        self.state = state;
    }

    /// Close the temporary source descriptor after a connection commits.
    pub fn release_preconnect(&mut self) {
        self.retained_preconnect = None;
    }

    /// Verify that the retained source still has the registered cookie and
    /// inode.
    pub fn validate_retained_identity(&self) -> io::Result<()> {
        let retained = self.retained_preconnect()?;
        let identity = socket_identity(retained.as_raw_fd(), self.identity.listener_generation)?;
        if identity == self.identity {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retained socket identity changed",
            ))
        }
    }
}

/// Tentative socket metadata that is invisible until ADDFD-SEND succeeds.
#[derive(Debug)]
pub struct TentativeSocket {
    identity: SocketIdentity,
    metadata: SocketMetadata,
    source: OwnedFd,
}

impl TentativeSocket {
    /// Stable identity used to correlate the ADDFD transaction.
    #[must_use]
    pub fn identity(&self) -> SocketIdentity {
        self.identity
    }

    /// Source descriptor passed to ADDFD-SEND.
    #[must_use]
    pub fn source_fd(&self) -> RawFd {
        self.source.as_raw_fd()
    }
}

/// Bounded committed socket registry.
pub struct SocketRegistry {
    listener_generation: u64,
    capacity: usize,
    entries: BTreeMap<u64, SocketEntry>,
}

impl SocketRegistry {
    /// Create an empty registry for one nonzero listener generation.
    pub fn new(listener_generation: u64, capacity: usize) -> io::Result<Self> {
        if listener_generation == 0 || capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listener generation and registry capacity must be nonzero",
            ));
        }
        Ok(Self {
            listener_generation,
            capacity,
            entries: BTreeMap::new(),
        })
    }

    /// Number of committed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no sockets are committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stage a newly created source descriptor without publishing it.
    pub fn stage(&self, source: OwnedFd, metadata: SocketMetadata) -> io::Result<TentativeSocket> {
        if self.entries.len() >= self.capacity {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        let identity = socket_identity(source.as_raw_fd(), self.listener_generation)?;
        if self.entries.contains_key(&identity.inode) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket inode is already registered",
            ));
        }
        Ok(TentativeSocket {
            identity,
            metadata,
            source,
        })
    }

    /// Publish a tentative socket only after ADDFD-SEND has succeeded.
    pub fn commit(&mut self, tentative: TentativeSocket) -> io::Result<SocketIdentity> {
        if self.entries.len() >= self.capacity {
            return Err(io::Error::from_raw_os_error(libc::EMFILE));
        }
        if tentative.identity.listener_generation != self.listener_generation
            || self.entries.contains_key(&tentative.identity.inode)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "socket identity cannot be committed to this registry",
            ));
        }
        let identity = tentative.identity;
        self.entries.insert(
            identity.inode,
            SocketEntry {
                identity,
                metadata: tentative.metadata,
                state: SocketState::Created,
                retained_preconnect: Some(tentative.source),
            },
        );
        Ok(identity)
    }

    /// Resolve a notifying task's installed descriptor to a committed entry.
    pub fn resolve(&self, tid: u32, fd: RawFd) -> io::Result<&SocketEntry> {
        let inode = proc_fd::socket_inode(tid, fd)?;
        let entry = self.entries.get(&inode).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket inode is not registered for this sandbox",
            )
        })?;
        if entry.retained_preconnect.is_some() {
            entry.validate_retained_identity()?;
        }
        Ok(entry)
    }

    /// Mutable form of [`Self::resolve`].
    pub fn resolve_mut(&mut self, tid: u32, fd: RawFd) -> io::Result<&mut SocketEntry> {
        let inode = proc_fd::socket_inode(tid, fd)?;
        let entry = self.entries.get_mut(&inode).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket inode is not registered for this sandbox",
            )
        })?;
        if entry.retained_preconnect.is_some() {
            entry.validate_retained_identity()?;
        }
        Ok(entry)
    }

    /// Remove metadata after descendant-FD collection proves no installed
    /// alias remains.
    pub fn remove_inode(&mut self, inode: u64) -> bool {
        self.entries.remove(&inode).is_some()
    }
}

fn socket_identity(fd: RawFd, listener_generation: u64) -> io::Result<SocketIdentity> {
    // SAFETY: `fd` remains open for this function; the borrow never escapes.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let stat = fstat(borrowed)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "registry source descriptor is not a socket",
        ));
    }
    let mut cookie = 0_u64;
    let mut length =
        libc::socklen_t::try_from(size_of::<u64>()).expect("SO_COOKIE length fits socklen_t");
    // SAFETY: getsockopt writes at most the supplied u64 and socklen_t.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_COOKIE,
            std::ptr::addr_of_mut!(cookie).cast(),
            std::ptr::addr_of_mut!(length),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(length).ok() != Some(size_of::<u64>()) || cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "kernel returned an invalid SO_COOKIE",
        ));
    }
    Ok(SocketIdentity {
        listener_generation,
        inode: stat.st_ino,
        cookie,
    })
}

#[cfg(test)]
mod tests {
    use std::os::fd::FromRawFd;

    use super::*;

    fn tcp_socket() -> OwnedFd {
        // SAFETY: socket returns one newly owned descriptor on success.
        let fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                libc::IPPROTO_TCP,
            )
        };
        assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
        // SAFETY: successful socket returned one owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn metadata() -> SocketMetadata {
        SocketMetadata {
            family: InetFamily::V4,
            kind: InetKind::Tcp,
            close_on_exec: true,
            nonblocking: false,
            creator_generation: 11,
        }
    }

    #[test]
    fn tentative_entry_is_invisible_until_commit() {
        let mut registry = SocketRegistry::new(7, 1).unwrap();
        let socket = tcp_socket();
        let fd = socket.as_raw_fd();
        let tentative = registry.stage(socket, metadata()).unwrap();
        assert!(registry.is_empty());
        assert_eq!(
            registry
                .resolve(std::process::id(), fd)
                .expect_err("tentative socket must be invisible")
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let identity = registry.commit(tentative).unwrap();
        let entry = registry.resolve(std::process::id(), fd).unwrap();
        assert_eq!(entry.identity(), identity);
        assert_eq!(entry.metadata(), metadata());
        assert_eq!(entry.state(), &SocketState::Created);
        assert_eq!(registry.len(), 1);

        assert_eq!(
            registry
                .stage(tcp_socket(), metadata())
                .expect_err("quota must fail before injection")
                .raw_os_error(),
            Some(libc::EMFILE)
        );
    }

    #[test]
    fn dup_alias_resolves_to_same_open_file_description() {
        let mut registry = SocketRegistry::new(9, 4).unwrap();
        let socket = tcp_socket();
        let original_fd = socket.as_raw_fd();
        // SAFETY: dup returns a new descriptor for the same open-file
        // description or a negative error.
        let alias_fd = unsafe { libc::dup(original_fd) };
        assert!(alias_fd >= 0, "dup: {}", io::Error::last_os_error());
        // SAFETY: successful dup returned one owned descriptor.
        let alias = unsafe { OwnedFd::from_raw_fd(alias_fd) };

        let tentative = registry.stage(socket, metadata()).unwrap();
        let identity = registry.commit(tentative).unwrap();
        assert_eq!(
            registry
                .resolve(std::process::id(), alias.as_raw_fd())
                .unwrap()
                .identity(),
            identity
        );
    }
}
