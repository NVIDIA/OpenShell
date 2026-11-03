// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded DNS exchange with an explicitly configured trusted resolver.
//!
//! This module never reads sandbox resolver state or `/etc/hosts`. The caller
//! supplies an already-parsed resolver socket address, and Hickory owns all DNS
//! wire encoding and decoding.

use super::name::NormalizedName;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use openshell_core::net::connect_tcp_nodelay_best_effort;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::timeout;

pub(crate) const DEFAULT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const MAX_DNS_MESSAGE_BYTES: usize = 8 * 1024;
pub(crate) const MAX_RETAINED_ADDRESSES: usize = 16;
pub(crate) const MAX_CNAME_HOPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    pub(crate) fn record_type(self) -> RecordType {
        match self {
            Self::Ipv4 => RecordType::A,
            Self::Ipv6 => RecordType::AAAA,
        }
    }

    pub(crate) fn accepts(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedAnswer {
    pub(crate) addresses: Vec<IpAddr>,
    pub(crate) ttl: Duration,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ResolveError {
    #[error("trusted DNS exchange timed out")]
    Timeout,
    #[error("trusted DNS I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("trusted DNS response exceeded the configured size bound")]
    Oversized,
    #[error("trusted DNS response was malformed or did not match the query")]
    Malformed,
    #[error("trusted DNS returned NXDOMAIN")]
    NxDomain,
    #[error("trusted DNS returned response code {0:?}")]
    Response(ResponseCode),
    #[error("trusted DNS returned no usable address records")]
    NoData,
    #[error("trusted DNS CNAME chain looped or exceeded the hop limit")]
    CnameLimit,
}

#[allow(async_fn_in_trait)]
pub(crate) trait TrustedResolver: Send + Sync {
    async fn resolve(
        &self,
        name: &NormalizedName,
        family: AddressFamily,
    ) -> Result<TrustedAnswer, ResolveError>;
}

/// A DNS client for operator-supplied upstream servers.
///
/// With a resolver configuration path, the server list is reread for every
/// exchange so a host network or VPN change takes effect without a restart.
pub(crate) struct SocketTrustedResolver {
    servers: Mutex<Vec<SocketAddr>>,
    conf_path: Option<PathBuf>,
    preferred: Mutex<Option<SocketAddr>>,
    exchange_timeout: Duration,
}

impl SocketTrustedResolver {
    #[cfg(test)]
    pub(crate) fn new(server: SocketAddr) -> Self {
        Self::with_timeout(server, DEFAULT_EXCHANGE_TIMEOUT)
    }

    #[cfg(test)]
    pub(crate) fn with_timeout(server: SocketAddr, exchange_timeout: Duration) -> Self {
        Self {
            servers: Mutex::new(vec![server]),
            conf_path: None,
            preferred: Mutex::new(None),
            exchange_timeout,
        }
    }

    /// Track the literal `nameserver` entries of a resolv.conf style file.
    /// Fails when the file has none, so a misconfigured host is caught at start.
    pub(crate) fn from_resolv_conf(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        let contents = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let servers = parse_resolv_conf(&contents);
        if servers.is_empty() {
            return Err(format!(
                "no literal nameserver is configured in {}",
                path.display()
            ));
        }
        tracing::info!(?servers, "policy DNS upstream servers");
        Ok(Self {
            servers: Mutex::new(servers),
            conf_path: Some(path),
            preferred: Mutex::new(None),
            exchange_timeout: DEFAULT_EXCHANGE_TIMEOUT,
        })
    }

    /// Current servers, preferred (last answering) first. An unreadable or
    /// empty configuration keeps the last good list.
    fn current_servers(&self) -> Vec<SocketAddr> {
        let mut servers = self
            .servers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(path) = &self.conf_path
            && let Ok(contents) = std::fs::read_to_string(path)
        {
            let fresh = parse_resolv_conf(&contents);
            if !fresh.is_empty() && fresh != *servers {
                tracing::info!(servers = ?fresh, "policy DNS upstream servers changed");
                *servers = fresh;
            }
        }
        let mut list = servers.clone();
        drop(servers);
        let preferred = *self
            .preferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(index) = preferred.and_then(|p| list.iter().position(|s| *s == p)) {
            list[..=index].rotate_right(1);
        }
        list
    }

    async fn exchange(&self, name: Name, record_type: RecordType) -> Result<Message, ResolveError> {
        let query = Query::query(name, record_type);
        let mut request = Message::query();
        let id = request.metadata.id;
        request.metadata.recursion_desired = true;
        request.queries.push(query.clone());
        let wire = request.to_vec().map_err(|_| ResolveError::Malformed)?;

        let mut failure = ResolveError::Timeout;
        for server in self.current_servers() {
            match self.exchange_with(server, &wire, id, &query).await {
                Ok(response) => {
                    *self
                        .preferred
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(server);
                    return Ok(response);
                }
                Err(error @ (ResolveError::Timeout | ResolveError::Io(_))) => failure = error,
                Err(error) => return Err(error),
            }
        }
        Err(failure)
    }

    async fn exchange_with(
        &self,
        server: SocketAddr,
        wire: &[u8],
        id: u16,
        query: &Query,
    ) -> Result<Message, ResolveError> {
        let udp_response = self.udp_exchange(server, wire).await?;
        let response = parse_response(&udp_response, id, query)?;
        if response.metadata.truncation {
            let tcp_response = self.tcp_exchange(server, wire).await?;
            parse_response(&tcp_response, id, query)
        } else {
            Ok(response)
        }
    }

    async fn udp_exchange(
        &self,
        server: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(server).await?;

        timeout(self.exchange_timeout, socket.send(request))
            .await
            .map_err(|_| ResolveError::Timeout)??;
        let mut response = vec![0_u8; MAX_DNS_MESSAGE_BYTES + 1];
        let received = timeout(self.exchange_timeout, socket.recv(&mut response))
            .await
            .map_err(|_| ResolveError::Timeout)??;
        if received > MAX_DNS_MESSAGE_BYTES {
            return Err(ResolveError::Oversized);
        }
        response.truncate(received);
        Ok(response)
    }

    async fn tcp_exchange(
        &self,
        server: SocketAddr,
        request: &[u8],
    ) -> Result<Vec<u8>, ResolveError> {
        let mut stream = timeout(
            self.exchange_timeout,
            connect_tcp_nodelay_best_effort(&[server]),
        )
        .await
        .map_err(|_| ResolveError::Timeout)??;

        let request_len = u16::try_from(request.len()).map_err(|_| ResolveError::Oversized)?;
        timeout(self.exchange_timeout, stream.write_u16(request_len))
            .await
            .map_err(|_| ResolveError::Timeout)??;
        timeout(self.exchange_timeout, stream.write_all(request))
            .await
            .map_err(|_| ResolveError::Timeout)??;

        let response_len = timeout(self.exchange_timeout, stream.read_u16())
            .await
            .map_err(|_| ResolveError::Timeout)?? as usize;
        if response_len > MAX_DNS_MESSAGE_BYTES {
            return Err(ResolveError::Oversized);
        }
        let mut response = vec![0_u8; response_len];
        timeout(self.exchange_timeout, stream.read_exact(&mut response))
            .await
            .map_err(|_| ResolveError::Timeout)??;
        Ok(response)
    }
}

impl TrustedResolver for SocketTrustedResolver {
    async fn resolve(
        &self,
        name: &NormalizedName,
        family: AddressFamily,
    ) -> Result<TrustedAnswer, ResolveError> {
        let mut current = name.as_absolute_name();
        let mut visited = BTreeSet::new();
        let mut chain_ttl = u32::MAX;
        let mut cname_hops = 0;
        visited.insert(canonical_name(&current));

        for _ in 0..=MAX_CNAME_HOPS {
            let current_key = canonical_name(&current);
            let response = self.exchange(current.clone(), family.record_type()).await?;
            let parsed = parse_answer_records(&response, family);
            let mut cursor = current_key;

            loop {
                if let Some(records) = parsed.addresses.get(&cursor) {
                    let mut addresses = records
                        .iter()
                        .map(|(address, _)| *address)
                        .collect::<Vec<_>>();
                    retain_first_addresses(&mut addresses);
                    addresses.truncate(MAX_RETAINED_ADDRESSES);
                    let address_ttl = records.iter().map(|(_, ttl)| *ttl).min().unwrap_or(1);
                    return Ok(TrustedAnswer {
                        addresses,
                        ttl: Duration::from_secs(u64::from(chain_ttl.min(address_ttl))),
                    });
                }

                let Some((target, ttl)) = parsed.cnames.get(&cursor) else {
                    return Err(ResolveError::NoData);
                };
                cname_hops += 1;
                if cname_hops > MAX_CNAME_HOPS {
                    return Err(ResolveError::CnameLimit);
                }
                chain_ttl = chain_ttl.min(*ttl);
                let target_key = canonical_name(target);
                if !visited.insert(target_key.clone()) {
                    return Err(ResolveError::CnameLimit);
                }
                cursor = target_key;

                if !parsed.addresses.contains_key(&cursor) && !parsed.cnames.contains_key(&cursor) {
                    current = target.clone();
                    break;
                }
            }
        }

        Err(ResolveError::CnameLimit)
    }
}

fn retain_first_addresses(addresses: &mut Vec<IpAddr>) {
    let mut seen = HashSet::new();
    addresses.retain(|address| seen.insert(*address));
}

fn parse_response(wire: &[u8], id: u16, query: &Query) -> Result<Message, ResolveError> {
    if wire.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(ResolveError::Oversized);
    }
    let response = Message::from_vec(wire).map_err(|_| ResolveError::Malformed)?;
    if response.metadata.id != id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.queries.len() != 1
        || response.queries.first() != Some(query)
    {
        return Err(ResolveError::Malformed);
    }
    match response.metadata.response_code {
        ResponseCode::NoError => Ok(response),
        ResponseCode::NXDomain => Err(ResolveError::NxDomain),
        code => Err(ResolveError::Response(code)),
    }
}

struct ParsedRecords {
    addresses: BTreeMap<String, Vec<(IpAddr, u32)>>,
    cnames: BTreeMap<String, (Name, u32)>,
}

fn parse_answer_records(message: &Message, family: AddressFamily) -> ParsedRecords {
    let mut parsed = ParsedRecords {
        addresses: BTreeMap::new(),
        cnames: BTreeMap::new(),
    };

    for record in &message.answers {
        let owner = canonical_name(&record.name);
        match &record.data {
            RData::A(value) if family == AddressFamily::Ipv4 => {
                parsed
                    .addresses
                    .entry(owner)
                    .or_default()
                    .push((IpAddr::V4(value.0), record.ttl));
            }
            RData::AAAA(value) if family == AddressFamily::Ipv6 => {
                parsed
                    .addresses
                    .entry(owner)
                    .or_default()
                    .push((IpAddr::V6(value.0), record.ttl));
            }
            RData::CNAME(target) => {
                parsed
                    .cnames
                    .entry(owner)
                    .or_insert_with(|| (target.0.clone(), record.ttl));
            }
            _ => {}
        }
    }
    parsed
}

fn canonical_name(name: &Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

/// Literal `nameserver` addresses of a resolv.conf style file, in order.
fn parse_resolv_conf(contents: &str) -> Vec<SocketAddr> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('#').next()?.split_whitespace();
            if fields.next() != Some("nameserver") {
                return None;
            }
            fields.next()?.parse::<IpAddr>().ok()
        })
        .map(|ip| SocketAddr::new(ip, 53))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Record;
    use hickory_proto::rr::rdata::{A, CNAME};
    use openshell_core::net::set_tcp_nodelay_best_effort;
    use tokio::net::TcpListener;

    async fn bind_dns_test_server() -> (UdpSocket, TcpListener, SocketAddr) {
        const MAX_BIND_ATTEMPTS: usize = 100;

        for _ in 0..MAX_BIND_ATTEMPTS {
            // Port zero only guarantees availability for the protocol being bound.
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server = tcp.local_addr().unwrap();
            match UdpSocket::bind(server).await {
                Ok(udp) => return (udp, tcp, server),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("failed to bind DNS test UDP socket: {error}"),
            }
        }

        panic!("failed to bind DNS test TCP and UDP sockets to the same port");
    }

    #[test]
    fn resolver_address_deduplication_preserves_answer_order() {
        let mut addresses = vec![
            "203.0.113.20".parse().unwrap(),
            "203.0.113.10".parse().unwrap(),
            "203.0.113.20".parse().unwrap(),
        ];

        retain_first_addresses(&mut addresses);

        assert_eq!(
            addresses,
            vec![
                "203.0.113.20".parse::<IpAddr>().unwrap(),
                "203.0.113.10".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn answer_parser_keeps_only_requested_family_and_bounds_are_constants() {
        let owner = Name::from_ascii("db.example.").unwrap();
        let mut message = Message::response(1, OpCode::Query);
        message.add_answer(Record::from_rdata(
            owner.clone(),
            120,
            RData::A(A::new(203, 0, 113, 10)),
        ));
        message.add_answer(Record::from_rdata(
            owner,
            120,
            RData::AAAA("2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap().into()),
        ));

        let parsed = parse_answer_records(&message, AddressFamily::Ipv4);
        assert_eq!(parsed.addresses["db.example"].len(), 1);
        assert_eq!(MAX_RETAINED_ADDRESSES, 16);
        assert_eq!(MAX_DNS_MESSAGE_BYTES, 8192);
    }

    #[test]
    fn parser_retains_cname_owner_target_and_ttl() {
        let owner = Name::from_ascii("db.example.").unwrap();
        let target = Name::from_ascii("target.example.").unwrap();
        let mut message = Message::response(1, OpCode::Query);
        message.add_answer(Record::from_rdata(
            owner,
            17,
            RData::CNAME(CNAME(target.clone())),
        ));
        let parsed = parse_answer_records(&message, AddressFamily::Ipv4);
        assert_eq!(parsed.cnames["db.example"], (target, 17));
    }

    #[test]
    fn response_validation_rejects_wrong_transaction_or_question() {
        let query = Query::query(Name::from_ascii("db.example.").unwrap(), RecordType::A);
        let mut response = Message::response(9, OpCode::Query);
        response.queries.push(query.clone());
        let wire = response.to_vec().unwrap();
        assert!(matches!(
            parse_response(&wire, 10, &query),
            Err(ResolveError::Malformed)
        ));
    }

    #[tokio::test]
    async fn truncated_udp_retries_over_tcp_and_follows_cname() {
        let (udp, tcp, server) = bind_dns_test_server().await;

        let udp_task = tokio::spawn(async move {
            let mut wire = [0_u8; MAX_DNS_MESSAGE_BYTES];
            let (length, peer) = udp.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..length]).unwrap();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.metadata.truncation = true;
            response.queries = request.queries;
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            set_tcp_nodelay_best_effort(&stream);
            let length = stream.read_u16().await.unwrap() as usize;
            let mut wire = vec![0_u8; length];
            stream.read_exact(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire).unwrap();
            let requested = request.queries[0].name.clone();
            let canonical = Name::from_ascii("canonical.example.").unwrap();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.queries = request.queries;
            response.add_answer(Record::from_rdata(
                requested,
                12,
                RData::CNAME(CNAME(canonical.clone())),
            ));
            response.add_answer(Record::from_rdata(
                canonical,
                20,
                RData::A(A::new(8, 8, 8, 8)),
            ));
            let wire = response.to_vec().unwrap();
            stream
                .write_u16(u16::try_from(wire.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&wire).await.unwrap();
        });

        let resolver = SocketTrustedResolver::new(server);
        let answer = resolver
            .resolve(
                &NormalizedName::parse("db.example").unwrap(),
                AddressFamily::Ipv4,
            )
            .await
            .unwrap();
        assert_eq!(answer.addresses, ["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert_eq!(answer.ttl, Duration::from_secs(12));
        udp_task.await.unwrap();
        tcp_task.await.unwrap();
    }

    #[tokio::test]
    async fn cname_hop_overflow_fails_closed() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server = udp.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut wire = [0_u8; MAX_DNS_MESSAGE_BYTES];
            let (length, peer) = udp.recv_from(&mut wire).await.unwrap();
            let request = Message::from_vec(&wire[..length]).unwrap();
            let mut response = Message::response(request.metadata.id, OpCode::Query);
            response.queries = request.queries.clone();
            let mut owner = request.queries[0].name.clone();
            for index in 0..=MAX_CNAME_HOPS {
                let target = Name::from_ascii(format!("hop{index}.example.")).unwrap();
                response.add_answer(Record::from_rdata(
                    owner,
                    10,
                    RData::CNAME(CNAME(target.clone())),
                ));
                owner = target;
            }
            response.add_answer(Record::from_rdata(owner, 10, RData::A(A::new(8, 8, 8, 8))));
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        let resolver = SocketTrustedResolver::new(server);
        assert!(matches!(
            resolver
                .resolve(
                    &NormalizedName::parse("db.example").unwrap(),
                    AddressFamily::Ipv4
                )
                .await,
            Err(ResolveError::CnameLimit)
        ));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn trusted_exchange_timeout_is_bounded() {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = SocketTrustedResolver::with_timeout(
            udp.local_addr().unwrap(),
            Duration::from_millis(10),
        );
        assert!(matches!(
            resolver
                .resolve(
                    &NormalizedName::parse("db.example").unwrap(),
                    AddressFamily::Ipv4
                )
                .await,
            Err(ResolveError::Timeout)
        ));
        drop(udp);
    }

    #[test]
    fn resolv_conf_lists_literal_nameservers_in_order() {
        let conf = "# c\nsearch example\nnameserver 192.0.2.10 # x\nnameserver bogus\nnameserver 2001:db8::1\n";
        assert_eq!(
            parse_resolv_conf(conf),
            [
                "192.0.2.10:53".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn resolv_conf_changes_are_picked_up_and_bad_reads_keep_last_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 192.0.2.10\n").unwrap();
        let resolver = SocketTrustedResolver::from_resolv_conf(&path).unwrap();
        assert_eq!(
            resolver.current_servers(),
            ["192.0.2.10:53".parse::<SocketAddr>().unwrap()]
        );

        std::fs::write(&path, "nameserver 198.51.100.53\n").unwrap();
        assert_eq!(
            resolver.current_servers(),
            ["198.51.100.53:53".parse::<SocketAddr>().unwrap()]
        );

        std::fs::write(&path, "").unwrap();
        assert_eq!(resolver.current_servers().len(), 1);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(resolver.current_servers().len(), 1);
    }

    #[test]
    fn resolv_conf_without_nameserver_is_rejected_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "search example\n").unwrap();
        assert!(SocketTrustedResolver::from_resolv_conf(&path).is_err());
    }

    #[tokio::test]
    async fn unresponsive_server_falls_through_to_next_and_is_remembered() {
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut wire = [0_u8; MAX_DNS_MESSAGE_BYTES];
            for _ in 0..2 {
                let (length, peer) = live.recv_from(&mut wire).await.unwrap();
                let request = Message::from_vec(&wire[..length]).unwrap();
                let mut response = Message::response(request.metadata.id, OpCode::Query);
                response.queries = request.queries.clone();
                response.add_answer(Record::from_rdata(
                    request.queries[0].name.clone(),
                    10,
                    RData::A(A::new(8, 8, 8, 8)),
                ));
                live.send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        let resolver = SocketTrustedResolver::with_timeout(
            dead.local_addr().unwrap(),
            Duration::from_millis(50),
        );
        resolver.servers.lock().unwrap().push(live_addr);
        let name = NormalizedName::parse("db.example").unwrap();
        for _ in 0..2 {
            let answer = resolver.resolve(&name, AddressFamily::Ipv4).await.unwrap();
            assert_eq!(answer.addresses, ["8.8.8.8".parse::<IpAddr>().unwrap()]);
        }
        assert_eq!(resolver.current_servers()[0], live_addr);
        task.await.unwrap();
        drop(dead);
    }

    #[test]
    fn oversized_response_is_rejected_before_decode() {
        let query = Query::query(Name::from_ascii("db.example.").unwrap(), RecordType::A);
        assert!(matches!(
            parse_response(&vec![0; MAX_DNS_MESSAGE_BYTES + 1], 1, &query),
            Err(ResolveError::Oversized)
        ));
    }
}
