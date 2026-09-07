// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! DNS request and response wire handling.

use super::resolver::{AddressFamily, MAX_DNS_MESSAGE_BYTES, ResolveError, TrustedResolver};
use super::{PolicyDnsError, PolicyDnsService};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub(crate) enum WireError {
    #[error("DNS response encoding failed")]
    Encode,
    #[error("DNS-over-TCP frame is invalid")]
    InvalidTcpFrame,
}

/// Handle one DNS datagram without binding a runtime listener.
pub(crate) async fn handle_udp_query<R: TrustedResolver>(
    service: &PolicyDnsService<R>,
    wire: &[u8],
) -> Result<Vec<u8>, WireError> {
    handle_udp_query_with_ipv6(service, wire, true).await
}

pub(crate) async fn handle_udp_query_with_ipv6<R: TrustedResolver>(
    service: &PolicyDnsService<R>,
    wire: &[u8],
    ipv6_egress: bool,
) -> Result<Vec<u8>, WireError> {
    let fallback_id = wire
        .get(..2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .unwrap_or_default();
    if wire.len() > MAX_DNS_MESSAGE_BYTES {
        return encode_message(Message::error_msg(
            fallback_id,
            OpCode::Query,
            ResponseCode::FormErr,
        ));
    }
    let Ok(request) = Message::from_vec(wire) else {
        return encode_message(Message::error_msg(
            fallback_id,
            OpCode::Query,
            ResponseCode::FormErr,
        ));
    };
    let Some((query, family)) = validate_request(&request) else {
        let code = if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
            || request.queries.len() != 1
        {
            ResponseCode::FormErr
        } else {
            ResponseCode::NotImp
        };
        return encode_message(response_with_code(&request, code));
    };

    let raw_name = query.name.to_ascii();
    if family == AddressFamily::Ipv6 && !ipv6_egress {
        return encode_message(response_with_code(&request, ResponseCode::NoError));
    }
    match service
        .answer_query(&raw_name, family, Instant::now())
        .await
    {
        Ok(answer) => {
            let rdata = match answer.address {
                IpAddr::V4(address) if family == AddressFamily::Ipv4 => RData::A(A(address)),
                IpAddr::V6(address) if family == AddressFamily::Ipv6 => RData::AAAA(AAAA(address)),
                _ => return encode_message(response_with_code(&request, ResponseCode::ServFail)),
            };
            let mut response = response_with_code(&request, ResponseCode::NoError);
            response.answers.push(Record::from_rdata(
                query.name.clone(),
                u32::try_from(answer.ttl.as_secs()).unwrap_or(u32::MAX),
                rdata,
            ));
            encode_message(response)
        }
        Err(PolicyDnsError::Ineligible | PolicyDnsError::TrustedGatewayUnavailable) => {
            encode_message(response_with_code(&request, ResponseCode::Refused))
        }
        Err(PolicyDnsError::Resolver(ResolveError::NxDomain)) => {
            encode_message(response_with_code(&request, ResponseCode::NXDomain))
        }
        Err(PolicyDnsError::Resolver(ResolveError::NoData)) => {
            encode_message(response_with_code(&request, ResponseCode::NoError))
        }
        Err(PolicyDnsError::InvalidName) => {
            encode_message(response_with_code(&request, ResponseCode::FormErr))
        }
        Err(
            PolicyDnsError::Resolver(_)
            | PolicyDnsError::NoValidAddress
            | PolicyDnsError::StalePolicy
            | PolicyDnsError::Publish(_)
            | PolicyDnsError::Policy(_),
        ) => encode_message(response_with_code(&request, ResponseCode::ServFail)),
    }
}

/// Handle exactly one length-prefixed DNS-over-TCP message.
pub(crate) async fn handle_tcp_query<R: TrustedResolver>(
    service: &PolicyDnsService<R>,
    frame: &[u8],
) -> Result<Vec<u8>, WireError> {
    handle_tcp_query_with_ipv6(service, frame, true).await
}

pub(crate) async fn handle_tcp_query_with_ipv6<R: TrustedResolver>(
    service: &PolicyDnsService<R>,
    frame: &[u8],
    ipv6_egress: bool,
) -> Result<Vec<u8>, WireError> {
    let declared = frame
        .get(..2)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
        .ok_or(WireError::InvalidTcpFrame)?;
    if declared > MAX_DNS_MESSAGE_BYTES || frame.len() != declared + 2 {
        return Err(WireError::InvalidTcpFrame);
    }
    let response = handle_udp_query_with_ipv6(service, &frame[2..], ipv6_egress).await?;
    let length = u16::try_from(response.len()).map_err(|_| WireError::Encode)?;
    let mut framed = Vec::with_capacity(response.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(&response);
    Ok(framed)
}

fn validate_request(request: &Message) -> Option<(&hickory_proto::op::Query, AddressFamily)> {
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
        || request.queries.len() != 1
    {
        return None;
    }
    let query = request.queries.first()?;
    if query.query_class != DNSClass::IN {
        return None;
    }
    let family = match query.query_type {
        RecordType::A => AddressFamily::Ipv4,
        RecordType::AAAA => AddressFamily::Ipv6,
        _ => return None,
    };
    Some((query, family))
}

fn response_with_code(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = code;
    response.queries.clone_from(&request.queries);
    response
}

fn encode_message(message: Message) -> Result<Vec<u8>, WireError> {
    message.to_vec().map_err(|_| WireError::Encode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opa::OpaEngine;
    use crate::policy_dns::name::NormalizedName;
    use crate::policy_dns::resolver::TrustedAnswer;
    use crate::policy_dns::store::{ResolvedEndpointStore, StoreConfig, SyntheticPools};
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct FakeResolver {
        calls: AtomicUsize,
    }

    struct NoDataResolver;

    impl TrustedResolver for NoDataResolver {
        async fn resolve(
            &self,
            _name: &NormalizedName,
            _family: AddressFamily,
        ) -> Result<TrustedAnswer, ResolveError> {
            Err(ResolveError::NoData)
        }
    }

    impl TrustedResolver for FakeResolver {
        async fn resolve(
            &self,
            _name: &NormalizedName,
            family: AddressFamily,
        ) -> Result<TrustedAnswer, ResolveError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(TrustedAnswer {
                addresses: match family {
                    AddressFamily::Ipv4 => vec!["8.8.8.8".parse().unwrap()],
                    AddressFamily::Ipv6 => vec!["2001:4860:4860::8888".parse().unwrap()],
                },
                ttl: Duration::from_secs(10),
            })
        }
    }

    fn service_with_resolver<R: TrustedResolver>(resolver: R) -> PolicyDnsService<R> {
        let yaml = r"
network_policies:
  database:
    name: database
    endpoints: [{ host: db.example, port: 5432, protocol: tcp }]
    binaries: [{ path: /usr/bin/psql }]
filesystem_policy: { include_workdir: true, read_only: [], read_write: [] }
landlock: { compatibility: best_effort }
process: { run_as_user: sandbox, run_as_group: sandbox }
";
        let policy = Arc::new(
            OpaEngine::from_strings(include_str!("../../data/sandbox-policy.rego"), yaml).unwrap(),
        );
        let pools = SyntheticPools::new(
            Ipv4Addr::new(198, 18, 0, 1)..=Ipv4Addr::new(198, 18, 0, 4),
            "fd00:1::1".parse::<Ipv6Addr>().unwrap()..="fd00:1::4".parse::<Ipv6Addr>().unwrap(),
        )
        .unwrap();
        PolicyDnsService::new(
            policy,
            resolver,
            Arc::new(ResolvedEndpointStore::new(
                StoreConfig::new(pools, 8).unwrap(),
            )),
            None,
        )
    }

    fn service() -> PolicyDnsService<FakeResolver> {
        service_with_resolver(FakeResolver {
            calls: AtomicUsize::new(0),
        })
    }

    fn request(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = Message::new(42, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message
            .queries
            .push(Query::query(Name::from_ascii(name).unwrap(), record_type));
        message.to_vec().unwrap()
    }

    #[tokio::test]
    async fn udp_and_tcp_queries_return_synthetic_answers() {
        let service = service();
        let udp = handle_udp_query(&service, &request("DB.EXAMPLE.", RecordType::A))
            .await
            .unwrap();
        let udp_message = Message::from_vec(&udp).unwrap();
        assert_eq!(udp_message.metadata.response_code, ResponseCode::NoError);
        assert!(matches!(udp_message.answers[0].data, RData::A(_)));

        let query = request("db.example.", RecordType::A);
        let mut frame = Vec::with_capacity(query.len() + 2);
        frame.extend_from_slice(&u16::try_from(query.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&query);
        let tcp = handle_tcp_query(&service, &frame).await.unwrap();
        let declared = usize::from(u16::from_be_bytes([tcp[0], tcp[1]]));
        assert_eq!(declared, tcp.len() - 2);
        assert_eq!(
            Message::from_vec(&tcp[2..]).unwrap().metadata.response_code,
            ResponseCode::NoError
        );

        let ipv6 = handle_udp_query(&service, &request("db.example.", RecordType::AAAA))
            .await
            .unwrap();
        assert!(matches!(
            Message::from_vec(&ipv6).unwrap().answers[0].data,
            RData::AAAA(_)
        ));
    }

    #[tokio::test]
    async fn ineligible_query_is_refused_without_upstream_call() {
        let service = service();
        let wire = handle_udp_query(&service, &request("other.example.", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&wire).unwrap().metadata.response_code,
            ResponseCode::Refused
        );
        assert_eq!(service.resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn eligible_family_without_records_returns_empty_success() {
        let service = service_with_resolver(NoDataResolver);
        let wire = handle_udp_query(&service, &request("db.example.", RecordType::AAAA))
            .await
            .unwrap();
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    #[tokio::test]
    async fn runtime_without_ipv6_egress_suppresses_aaaa_without_resolving() {
        let service = service();
        let wire =
            handle_udp_query_with_ipv6(&service, &request("db.example.", RecordType::AAAA), false)
                .await
                .unwrap();
        let response = Message::from_vec(&wire).unwrap();
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert_eq!(service.resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unsupported_type_is_not_implemented_and_malformed_tcp_is_rejected() {
        let service = service();
        let wire = handle_udp_query(&service, &request("db.example.", RecordType::TXT))
            .await
            .unwrap();
        assert_eq!(
            Message::from_vec(&wire).unwrap().metadata.response_code,
            ResponseCode::NotImp
        );
        assert!(matches!(
            handle_tcp_query(&service, &[0, 10, 1, 2]).await,
            Err(WireError::InvalidTcpFrame)
        ));
    }
}
