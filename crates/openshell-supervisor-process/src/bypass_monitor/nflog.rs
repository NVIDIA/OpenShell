// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal `nfnetlink_log` (NFLOG) client for bypass detection.
//!
//! Receives nftables `log group <N>` entries over an `AF_NETLINK` /
//! `NETLINK_NETFILTER` socket instead of the kernel ring buffer. NFLOG
//! delivery is scoped to the network namespace the socket was created in and
//! requires only `CAP_NET_ADMIN` over that namespace's owning user namespace,
//! so it works in user-namespaced pods (`hostUsers: false`) where reading the
//! ring buffer via `syslog(2)` would need `CAP_SYSLOG` in the initial user
//! namespace.
//!
//! The wire protocol is stable kernel ABI (`linux/netfilter/nfnetlink_log.h`).
//! Only the small subset needed here is implemented: group bind, copy-mode
//! config, and packet-message parsing. Message construction and parsing are
//! pure functions with unit tests; only the socket syscalls are unsafe FFI.

use super::BypassEvent;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use tracing::debug;

/// NFLOG group used for sandbox bypass log rules.
///
/// Arbitrary but must match between the nftables `log group <N>` rules and
/// the listener socket. The group namespace is per-netns, so collisions with
/// other tools cannot occur inside the dedicated sandbox namespace.
pub const BYPASS_NFLOG_GROUP: u16 = 1;

/// Bytes of each logged packet copied to userspace. Large enough for any
/// IPv4/IPv6 header plus L4 ports; the monitor only reads addresses, ports,
/// and protocol.
const COPY_RANGE_BYTES: u32 = 256;

/// Receive buffer for netlink datagrams. The kernel's default per-instance
/// buffer (`NFULNL_NLBUFSIZ_DEFAULT`) is 4096; double it so batched messages
/// are never truncated.
pub const RECV_BUFFER_LEN: usize = 8192;

/// Timeout for config-request acks during socket setup. Prevents a hang when
/// talking to a kernel that accepts the message but never acks.
const CONFIG_ACK_TIMEOUT_SECS: u64 = 2;

// --- Netlink / nfnetlink constants (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nfnetlink_log.h). Stable kernel ABI. ---

const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;

const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;

const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;

const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_UID: u16 = 11;

const NFNETLINK_V0: u8 = 0;
/// `nfgenmsg` family for group config messages (`AF_UNSPEC`).
const NFGEN_FAMILY_UNSPEC: u8 = 0;

/// Mask for the attribute type field (`NLA_TYPE_MASK`): strips the
/// `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flag bits.
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_HDR_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const NLATTR_HDR_LEN: usize = 4;
/// Netlink message and attribute payloads align to 4 bytes (`NLMSG_ALIGNTO`).
const NL_ALIGN: usize = 4;

/// `NLMSG_ERROR` message type: carries acks (code 0) and errors (-errno).
const NLMSG_TYPE_ERROR: u16 = 2;
/// `NLM_F_REQUEST` header flag.
const NLM_F_REQUEST: u16 = 1;
/// `NLM_F_ACK` header flag: ask the kernel to confirm the request.
const NLM_F_ACK: u16 = 4;

/// `nlmsg_type` for NFLOG packet messages: subsystem in the high byte.
const NFLOG_PACKET_MSG_TYPE: u16 = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET;
const NFLOG_CONFIG_MSG_TYPE: u16 = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;

const IPV4_MIN_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const L4_PORTS_LEN: usize = 4;
const IPPROTO_TCP_NUM: u8 = 6;
const IPPROTO_UDP_NUM: u8 = 17;

/// An NFLOG listener socket bound to a group inside a network namespace.
///
/// The netns association is fixed at `socket(2)` time, so the socket keeps
/// receiving from the sandbox namespace regardless of which namespace the
/// reading thread is in.
#[derive(Debug)]
pub struct NflogSocket {
    fd: OwnedFd,
    group: u16,
}

impl NflogSocket {
    /// Open and configure an NFLOG socket inside the network namespace
    /// referred to by `ns_fd`.
    ///
    /// Spawns a short-lived thread that enters the namespace via `setns`,
    /// creates the socket, binds the group, and sets packet copy mode. The
    /// thread exits immediately after; using a dedicated thread avoids
    /// changing the namespace of any long-lived thread.
    ///
    /// # Errors
    ///
    /// Returns an error when `setns` fails, the socket cannot be created
    /// (e.g. seccomp or missing `nfnetlink_log`), or the kernel rejects the
    /// group bind (e.g. missing `CAP_NET_ADMIN` over the netns owner).
    pub fn open_in_netns(ns_fd: RawFd, group: u16) -> io::Result<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> io::Result<Self> {
                // SAFETY: setns on a dedicated thread that exits right after;
                // no thread-pool namespace contamination.
                // libc/syscall FFI requires unsafe
                #[allow(unsafe_code)]
                let rc = unsafe { libc::setns(ns_fd, libc::CLONE_NEWNET) };
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }
                Self::open_in_current_netns(group)
            })();
            let _ = tx.send(result);
        });
        rx.recv()
            .map_err(|_| io::Error::other("nflog netns setup thread panicked"))?
    }

    /// Open and configure an NFLOG socket in the current network namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when socket creation, bind, or group configuration
    /// fails.
    // sa_family_t / socklen_t narrowing casts of fixed libc constants.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn open_in_current_netns(group: u16) -> io::Result<Self> {
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_NETFILTER,
            )
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw_fd was just returned by socket() and is owned here.
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        // SAFETY: sockaddr_nl is plain-old-data; zeroed then initialized.
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        unsafe {
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            let rc = libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let socket = Self { fd, group };
        socket.set_recv_timeout(CONFIG_ACK_TIMEOUT_SECS)?;

        // Bind the group first, then set copy mode. Sent as two acked
        // requests, mirroring libnetfilter_log. Group-targeted `log group N`
        // rules deliver without a protocol-family bind, so PF_BIND is not
        // needed.
        let mut seq: u32 = 0;
        seq += 1;
        socket.config_request(seq, &build_bind_group_msg(seq, group))?;
        seq += 1;
        socket.config_request(seq, &build_copy_mode_msg(seq, group, COPY_RANGE_BYTES))?;

        // Back to fully blocking reads for the monitor loop.
        socket.set_recv_timeout(0)?;
        debug!(group, "NFLOG socket configured");
        Ok(socket)
    }

    /// The NFLOG group this socket is bound to.
    #[must_use]
    pub const fn group(&self) -> u16 {
        self.group
    }

    /// Receive one netlink datagram. Blocks until data arrives.
    ///
    /// # Errors
    ///
    /// Returns the underlying socket error; `ENOBUFS` indicates the kernel
    /// dropped messages under load and reading may continue.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // n is non-negative here, so the cast cannot lose the sign.
        #[allow(clippy::cast_sign_loss)]
        let received = n as usize;
        Ok(received)
    }

    /// Send a config request and wait for its netlink ack.
    fn config_request(&self, seq: u32, msg: &[u8]) -> io::Result<()> {
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast::<libc::c_void>(),
                msg.len(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut buf = [0u8; RECV_BUFFER_LEN];
        let received = self.recv(&mut buf)?;
        parse_config_ack(&buf[..received], seq)
    }

    /// Set `SO_RCVTIMEO`; zero seconds means blocking (no timeout).
    // timeval / socklen_t narrowing casts of small fixed values.
    #[allow(clippy::cast_possible_truncation)]
    fn set_recv_timeout(&self, secs: u64) -> io::Result<()> {
        #[allow(clippy::cast_possible_wrap)]
        let tv = libc::timeval {
            tv_sec: secs as libc::time_t,
            tv_usec: 0,
        };
        // libc/syscall FFI requires unsafe
        #[allow(unsafe_code)]
        let rc = unsafe {
            libc::setsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

const fn align_nl(len: usize) -> usize {
    len.div_ceil(NL_ALIGN) * NL_ALIGN
}

/// Append one netlink attribute (header + payload + alignment padding).
// Attribute payloads here are a handful of bytes; the u16 length cannot truncate.
#[allow(clippy::cast_possible_truncation)]
fn push_attr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
    let attr_len = (NLATTR_HDR_LEN + payload.len()) as u16;
    buf.extend_from_slice(&attr_len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf.resize(align_nl(buf.len()), 0);
}

/// Build an `NFULNL_MSG_CONFIG` request: nlmsghdr + nfgenmsg + attributes.
// Config messages are tens of bytes; the u32 length cannot truncate.
#[allow(clippy::cast_possible_truncation)]
fn build_config_msg(seq: u32, group: u16, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    // nlmsghdr; nlmsg_len patched at the end.
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&NFLOG_CONFIG_MSG_TYPE.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid: kernel fills sender

    // nfgenmsg { family, version, res_id (big-endian group) }
    buf.push(NFGEN_FAMILY_UNSPEC);
    buf.push(NFNETLINK_V0);
    buf.extend_from_slice(&group.to_be_bytes());

    for (attr_type, payload) in attrs {
        push_attr(&mut buf, *attr_type, payload);
    }

    let total = buf.len() as u32;
    buf[..4].copy_from_slice(&total.to_ne_bytes());
    buf
}

/// Config message binding this socket to an NFLOG group.
fn build_bind_group_msg(seq: u32, group: u16) -> Vec<u8> {
    // struct nfulnl_msg_config_cmd { __u8 command; }
    build_config_msg(seq, group, &[(NFULA_CFG_CMD, vec![NFULNL_CFG_CMD_BIND])])
}

/// Config message setting packet copy mode and range for the group.
fn build_copy_mode_msg(seq: u32, group: u16, copy_range: u32) -> Vec<u8> {
    // struct nfulnl_msg_config_mode { __be32 copy_range; __u8 copy_mode; __u8 _pad; }
    let mut mode = Vec::with_capacity(6);
    mode.extend_from_slice(&copy_range.to_be_bytes());
    mode.push(NFULNL_COPY_PACKET);
    mode.push(0);
    build_config_msg(seq, group, &[(NFULA_CFG_MODE, mode)])
}

/// Parse the netlink ack for a config request with sequence `expected_seq`.
///
/// An `NLMSG_ERROR` message with error code 0 is a positive ack; a negative
/// code is `-errno` from the kernel.
fn parse_config_ack(datagram: &[u8], expected_seq: u32) -> io::Result<()> {
    for (header, payload) in NetlinkMessages::new(datagram) {
        if header.msg_type != NLMSG_TYPE_ERROR || header.seq != expected_seq {
            continue;
        }
        if payload.len() < 4 {
            return Err(io::Error::other("truncated netlink ack"));
        }
        let code = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if code == 0 {
            return Ok(());
        }
        return Err(io::Error::from_raw_os_error(-code));
    }
    Err(io::Error::other(
        "no netlink ack received for NFLOG config request",
    ))
}

/// Parsed netlink message header fields used by this module.
struct NlMsgHeader {
    msg_type: u16,
    seq: u32,
}

/// Iterator over the netlink messages in one datagram.
struct NetlinkMessages<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkMessages<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = (NlMsgHeader, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = &self.data[self.offset.min(self.data.len())..];
        if remaining.len() < NLMSG_HDR_LEN {
            return None;
        }
        let msg_len =
            u32::from_ne_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as usize;
        if msg_len < NLMSG_HDR_LEN || msg_len > remaining.len() {
            return None;
        }
        let header = NlMsgHeader {
            msg_type: u16::from_ne_bytes([remaining[4], remaining[5]]),
            seq: u32::from_ne_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]),
        };
        let payload = &remaining[NLMSG_HDR_LEN..msg_len];
        self.offset += align_nl(msg_len);
        Some((header, payload))
    }
}

/// Iterator over netlink attributes in a message payload.
struct NlAttrs<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> NlAttrs<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for NlAttrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = &self.data[self.offset.min(self.data.len())..];
        if remaining.len() < NLATTR_HDR_LEN {
            return None;
        }
        let attr_len = u16::from_ne_bytes([remaining[0], remaining[1]]) as usize;
        if attr_len < NLATTR_HDR_LEN || attr_len > remaining.len() {
            return None;
        }
        let attr_type = u16::from_ne_bytes([remaining[2], remaining[3]]) & NLA_TYPE_MASK;
        let payload = &remaining[NLATTR_HDR_LEN..attr_len];
        self.offset += align_nl(attr_len);
        Some((attr_type, payload))
    }
}

/// Parse every NFLOG packet message in a datagram into bypass events.
///
/// Filters on the NFLOG `group` (nfgenmsg `res_id`) and on the log rule prefix
/// so entries from unrelated rules are ignored, mirroring the namespace
/// prefix check in the ring-buffer path. Malformed messages are skipped, not
/// errors: the socket only receives from rules the supervisor installed.
#[must_use]
pub fn parse_datagram(datagram: &[u8], group: u16, expected_prefix: &str) -> Vec<BypassEvent> {
    let mut events = Vec::new();
    for (header, payload) in NetlinkMessages::new(datagram) {
        if header.msg_type != NFLOG_PACKET_MSG_TYPE || payload.len() < NFGENMSG_LEN {
            continue;
        }
        let res_id = u16::from_be_bytes([payload[2], payload[3]]);
        if res_id != group {
            continue;
        }
        if let Some(event) = parse_packet_attrs(&payload[NFGENMSG_LEN..], expected_prefix) {
            events.push(event);
        }
    }
    events
}

/// Extract a bypass event from one packet message's attributes.
fn parse_packet_attrs(attrs: &[u8], expected_prefix: &str) -> Option<BypassEvent> {
    let mut prefix: Option<&str> = None;
    let mut uid: Option<u32> = None;
    let mut ip_payload: Option<&[u8]> = None;

    for (attr_type, payload) in NlAttrs::new(attrs) {
        match attr_type {
            NFULA_PREFIX => {
                let trimmed = payload.strip_suffix(&[0]).unwrap_or(payload);
                prefix = std::str::from_utf8(trimmed).ok();
            }
            NFULA_UID if payload.len() >= 4 => {
                uid = Some(u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]));
            }
            NFULA_PAYLOAD => ip_payload = Some(payload),
            _ => {}
        }
    }

    if prefix != Some(expected_prefix) {
        return None;
    }
    let (dst_addr, dst_port, src_port, proto) = parse_ip_packet(ip_payload?)?;
    Some(BypassEvent {
        dst_addr,
        dst_port,
        src_port,
        proto,
        uid,
    })
}

/// Parse destination address, ports, and protocol from a raw IP packet.
///
/// Handles IPv4 (any header length) and IPv6 (fixed header; the bypass rules
/// only log plain TCP SYN and UDP, so extension-header chains are not
/// expected). Returns `None` for anything else rather than guessing.
fn parse_ip_packet(packet: &[u8]) -> Option<(String, u16, u16, String)> {
    let version = packet.first()? >> 4;
    match version {
        4 => {
            if packet.len() < IPV4_MIN_HDR_LEN {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < IPV4_MIN_HDR_LEN || packet.len() < header_len + L4_PORTS_LEN {
                return None;
            }
            let proto = l4_proto_name(packet[9])?;
            let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            let (src_port, dst_port) = parse_l4_ports(&packet[header_len..]);
            Some((dst.to_string(), dst_port, src_port, proto))
        }
        6 => {
            if packet.len() < IPV6_HDR_LEN + L4_PORTS_LEN {
                return None;
            }
            let proto = l4_proto_name(packet[6])?;
            let dst_octets: [u8; 16] = packet[24..40].try_into().ok()?;
            let dst = Ipv6Addr::from(dst_octets);
            let (src_port, dst_port) = parse_l4_ports(&packet[IPV6_HDR_LEN..]);
            Some((dst.to_string(), dst_port, src_port, proto))
        }
        _ => None,
    }
}

fn l4_proto_name(proto: u8) -> Option<String> {
    match proto {
        IPPROTO_TCP_NUM => Some("tcp".to_string()),
        IPPROTO_UDP_NUM => Some("udp".to_string()),
        _ => None,
    }
}

/// Source and destination ports share the same offsets in TCP and UDP.
fn parse_l4_ports(l4: &[u8]) -> (u16, u16) {
    (
        u16::from_be_bytes([l4[0], l4[1]]),
        u16::from_be_bytes([l4[2], l4[3]]),
    )
}

#[cfg(test)]
// Test fixtures cast fixed libc constants and small buffer lengths.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
mod tests {
    use super::*;

    const TEST_PREFIX: &str = "openshell:bypass:sandbox-abcd1234:";

    /// Build a synthetic NFLOG packet message datagram like the kernel emits.
    fn build_packet_msg(
        group: u16,
        family: u8,
        prefix: &str,
        uid: Option<u32>,
        ip_payload: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&NFLOG_PACKET_MSG_TYPE.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.push(family);
        buf.push(NFNETLINK_V0);
        buf.extend_from_slice(&group.to_be_bytes());

        let mut prefix_z = prefix.as_bytes().to_vec();
        prefix_z.push(0);
        push_attr(&mut buf, NFULA_PREFIX, &prefix_z);
        if let Some(uid) = uid {
            push_attr(&mut buf, NFULA_UID, &uid.to_be_bytes());
        }
        push_attr(&mut buf, NFULA_PAYLOAD, ip_payload);

        let total = buf.len() as u32;
        buf[..4].copy_from_slice(&total.to_ne_bytes());
        buf
    }

    /// Minimal IPv4 packet: src 10.200.0.2 -> dst, with TCP/UDP ports.
    fn build_ipv4_packet(proto: u8, dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV4_MIN_HDR_LEN + 8];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[9] = proto;
        pkt[12..16].copy_from_slice(&[10, 200, 0, 2]);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn build_ipv6_packet(proto: u8, dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; IPV6_HDR_LEN + 8];
        pkt[0] = 0x60; // version 6
        pkt[6] = proto;
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn parses_ipv4_tcp_bypass_event() {
        let pkt = build_ipv4_packet(IPPROTO_TCP_NUM, [93, 184, 216, 34], 48012, 443);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            Some(1000),
            &pkt,
        );

        let events = parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_addr, "93.184.216.34");
        assert_eq!(events[0].dst_port, 443);
        assert_eq!(events[0].src_port, 48012);
        assert_eq!(events[0].proto, "tcp");
        assert_eq!(events[0].uid, Some(1000));
    }

    #[test]
    fn parses_ipv4_udp_dns_bypass_event() {
        let pkt = build_ipv4_packet(IPPROTO_UDP_NUM, [8, 8, 8, 8], 53421, 53);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            Some(1000),
            &pkt,
        );

        let events = parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_addr, "8.8.8.8");
        assert_eq!(events[0].dst_port, 53);
        assert_eq!(events[0].proto, "udp");
    }

    #[test]
    fn parses_ipv6_tcp_bypass_event() {
        let dst = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        let pkt = build_ipv6_packet(IPPROTO_TCP_NUM, dst, 55555, 443);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET6 as u8,
            TEST_PREFIX,
            None,
            &pkt,
        );

        let events = parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].dst_addr, "2001:4860:4860::8888");
        assert_eq!(events[0].dst_port, 443);
        assert_eq!(events[0].uid, None);
    }

    #[test]
    fn wrong_prefix_is_ignored() {
        let pkt = build_ipv4_packet(IPPROTO_TCP_NUM, [1, 2, 3, 4], 1111, 80);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            "openshell:bypass:sandbox-other:",
            None,
            &pkt,
        );
        assert!(parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX).is_empty());
    }

    #[test]
    fn wrong_group_is_ignored() {
        let pkt = build_ipv4_packet(IPPROTO_TCP_NUM, [1, 2, 3, 4], 1111, 80);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP + 1,
            libc::AF_INET as u8,
            TEST_PREFIX,
            None,
            &pkt,
        );
        assert!(parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX).is_empty());
    }

    #[test]
    fn multiple_messages_in_one_datagram() {
        let tcp = build_ipv4_packet(IPPROTO_TCP_NUM, [1, 1, 1, 1], 1000, 443);
        let udp = build_ipv4_packet(IPPROTO_UDP_NUM, [8, 8, 4, 4], 2000, 53);
        let mut datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            None,
            &tcp,
        );
        datagram.extend(build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            None,
            &udp,
        ));

        let events = parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].proto, "tcp");
        assert_eq!(events[1].proto, "udp");
    }

    #[test]
    fn truncated_datagram_does_not_panic() {
        let pkt = build_ipv4_packet(IPPROTO_TCP_NUM, [1, 2, 3, 4], 1111, 80);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            None,
            &pkt,
        );
        for len in 0..datagram.len() {
            let _ = parse_datagram(&datagram[..len], BYPASS_NFLOG_GROUP, TEST_PREFIX);
        }
    }

    #[test]
    fn non_tcp_udp_protocol_is_skipped() {
        // ICMP (protocol 1) should not produce an event.
        let pkt = build_ipv4_packet(1, [1, 2, 3, 4], 0, 0);
        let datagram = build_packet_msg(
            BYPASS_NFLOG_GROUP,
            libc::AF_INET as u8,
            TEST_PREFIX,
            None,
            &pkt,
        );
        assert!(parse_datagram(&datagram, BYPASS_NFLOG_GROUP, TEST_PREFIX).is_empty());
    }

    #[test]
    fn bind_group_msg_layout() {
        let msg = build_bind_group_msg(7, 1);
        // nlmsg_len covers the whole message.
        assert_eq!(
            u32::from_ne_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize,
            msg.len()
        );
        assert_eq!(u16::from_ne_bytes([msg[4], msg[5]]), NFLOG_CONFIG_MSG_TYPE);
        assert_eq!(
            u16::from_ne_bytes([msg[6], msg[7]]),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(u32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]), 7);
        // nfgenmsg res_id is the group in big-endian.
        assert_eq!(u16::from_be_bytes([msg[18], msg[19]]), 1);
        // First attribute is NFULA_CFG_CMD with the BIND command byte.
        assert_eq!(u16::from_ne_bytes([msg[22], msg[23]]), NFULA_CFG_CMD);
        assert_eq!(msg[24], NFULNL_CFG_CMD_BIND);
    }

    #[test]
    fn copy_mode_msg_layout() {
        let msg = build_copy_mode_msg(8, 1, COPY_RANGE_BYTES);
        assert_eq!(u16::from_ne_bytes([msg[22], msg[23]]), NFULA_CFG_MODE);
        // copy_range is big-endian, followed by the copy mode byte.
        assert_eq!(
            u32::from_be_bytes([msg[24], msg[25], msg[26], msg[27]]),
            COPY_RANGE_BYTES
        );
        assert_eq!(msg[28], NFULNL_COPY_PACKET);
    }

    #[test]
    fn config_ack_success() {
        let ack = build_error_msg(9, 0);
        assert!(parse_config_ack(&ack, 9).is_ok());
    }

    #[test]
    fn config_ack_eperm() {
        let ack = build_error_msg(9, -libc::EPERM);
        let err = parse_config_ack(&ack, 9).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn config_ack_missing() {
        assert!(parse_config_ack(&[], 9).is_err());
    }

    fn build_error_msg(seq: u32, code: i32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&NLMSG_TYPE_ERROR.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&code.to_ne_bytes());
        let total = buf.len() as u32;
        buf[..4].copy_from_slice(&total.to_ne_bytes());
        buf
    }
}
