// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private adapter for Rust `AsyncRead`/`AsyncWrite` handles.
//!
//! Length/channel markers exist only on these in-process pipes; gRPC carries
//! typed `ExchangeFrame` or `MediateFrame` values.
//! Both directions check the operation's expected frame kind before forwarding.
use crate::{
    boundary_protocol as w, mediation as m,
    proto::{self as p, exchange_frame::Payload},
    protobuf::{self, WireMessage},
};
use prost::Message as _;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const MAX_MESSAGE_BYTES: usize = w::MAX_CONTROL_FRAME_BYTES + 4096;
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Request,
    Response,
    Input,
    Output,
    Decision,
    Relay,
    DnsQueries,
    DnsResponses,
    Done,
}
fn bad(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}
fn chunk(payload: Payload) -> p::ExchangeFrame {
    p::ExchangeFrame {
        payload: Some(payload),
    }
}
fn request_mode(v: &w::Request) -> Mode {
    match v {
        w::Request::Exec { .. } | w::Request::AttachProcess { .. } => Mode::Input,
        w::Request::AcceptNetwork => Mode::Decision,
        w::Request::LoopbackConnect { .. } => Mode::Relay,
        w::Request::OpenMediation => Mode::DnsResponses,
        _ => Mode::Done,
    }
}
fn response_mode(v: &w::Response) -> Mode {
    match v {
        w::Response::ProcessAttached { .. } | w::Response::ExecStarted { .. } => Mode::Output,
        w::Response::NetworkConnected { .. } | w::Response::LoopbackConnected => Mode::Relay,
        w::Response::MediationReady => Mode::DnsQueries,
        _ => Mode::Done,
    }
}
fn stream_bytes(channel: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > w::MAX_STREAM_FRAME_BYTES {
        return Err(bad("stream payload exceeds limit"));
    }
    let mut bytes = vec![channel];
    bytes.extend_from_slice(&u32::try_from(payload.len()).map_err(bad)?.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
fn dns_bytes(kind: m::MediationFrameKind, id: u64, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() > 256 * 1024 {
        return Err(bad("DNS metadata exceeds limit"));
    }
    let mut bytes = vec![kind as u8];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&u32::try_from(payload.len()).map_err(bad)?.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
/// Convert a checked typed frame to the local stream interface.
pub fn receive(mode: &mut Mode, value: p::ExchangeFrame) -> io::Result<Vec<u8>> {
    use prost::Message;
    if value.encoded_len() > MAX_MESSAGE_BYTES {
        return Err(bad("protocol message exceeds limit"));
    }
    let payload = value.payload.ok_or_else(|| bad("frame payload missing"))?;
    match (*mode, payload) {
        (Mode::Request, Payload::Request(v)) => {
            let v = w::RequestEnvelope::from_proto(v).map_err(bad)?;
            *mode = request_mode(&v.request);
            w::encode_frame(&v).map_err(bad)
        }
        (Mode::Response, Payload::Response(v)) => {
            let v = w::ResponseEnvelope::from_proto(v).map_err(bad)?;
            *mode = response_mode(&v.response);
            w::encode_frame(&v).map_err(bad)
        }
        (Mode::Input, Payload::Stdin(v)) => stream_bytes(w::STREAM_STDIN, &v),
        (Mode::Input, Payload::StdinClosed(_)) => {
            *mode = Mode::Done;
            stream_bytes(w::STREAM_STDIN_CLOSED, &[])
        }
        (Mode::Output, Payload::Stdout(v)) => stream_bytes(w::STREAM_STDOUT, &v),
        (Mode::Output, Payload::Stderr(v)) => stream_bytes(w::STREAM_STDERR, &v),
        (Mode::Output, Payload::Exit(v)) => {
            *mode = Mode::Done;
            let v = w::ExitStatusWire::from_proto(v).map_err(bad)?;
            stream_bytes(w::STREAM_EXIT, &protobuf::encode(&v).map_err(bad)?)
        }
        (Mode::Decision, Payload::TcpOpenDecision(v)) => {
            let v = openshell_isolation_interface::contract::TcpOpenDecision::from_proto(v)
                .map_err(bad)?;
            *mode = if matches!(
                v,
                openshell_isolation_interface::contract::TcpOpenDecision::RelayReady
            ) {
                Mode::Relay
            } else {
                Mode::Done
            };
            stream_bytes(
                w::STREAM_NETWORK_DECISION,
                &protobuf::encode(&v).map_err(bad)?,
            )
        }
        (Mode::Relay, Payload::RelayData(v)) if v.len() <= w::MAX_STREAM_FRAME_BYTES => Ok(v),
        _ => Err(bad(
            "frame kind does not match stream operation or direction",
        )),
    }
}
async fn control<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let first = match reader.read_u8().await {
        Ok(v) => v,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut header = [first, 0, 0, 0];
    reader.read_exact(&mut header[1..]).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len > w::MAX_CONTROL_FRAME_BYTES {
        return Err(bad("control message exceeds limit"));
    }
    let mut bytes = header.to_vec();
    bytes.resize(4 + len, 0);
    reader.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
/// Read a local handle and emit its next typed public protocol frame.
pub async fn send<R: AsyncRead + Unpin>(
    reader: &mut R,
    mode: &mut Mode,
) -> io::Result<Option<p::ExchangeFrame>> {
    let payload = match *mode {
        Mode::Request => {
            let Some(bytes) = control(reader).await? else {
                return Ok(None);
            };
            let v = w::decode_frame::<w::RequestEnvelope>(&bytes).map_err(bad)?;
            *mode = request_mode(&v.request);
            Payload::Request(v.to_proto().map_err(bad)?)
        }
        Mode::Response => {
            let Some(bytes) = control(reader).await? else {
                return Ok(None);
            };
            let v = w::decode_frame::<w::ResponseEnvelope>(&bytes).map_err(bad)?;
            *mode = response_mode(&v.response);
            Payload::Response(v.to_proto().map_err(bad)?)
        }
        Mode::Input | Mode::Output | Mode::Decision => {
            let Some((channel, bytes)) = w::read_stream_frame(reader).await? else {
                return Ok(None);
            };
            match (*mode, channel) {
                (Mode::Input, w::STREAM_STDIN) => Payload::Stdin(bytes),
                (Mode::Input, w::STREAM_STDIN_CLOSED) if bytes.is_empty() => {
                    *mode = Mode::Done;
                    Payload::StdinClosed(p::StdinClosed {})
                }
                (Mode::Output, w::STREAM_STDOUT) => Payload::Stdout(bytes),
                (Mode::Output, w::STREAM_STDERR) => Payload::Stderr(bytes),
                (Mode::Output, w::STREAM_EXIT) => {
                    *mode = Mode::Done;
                    Payload::Exit(
                        protobuf::decode::<w::ExitStatusWire>(&bytes)
                            .map_err(bad)?
                            .to_proto()
                            .map_err(bad)?,
                    )
                }
                (Mode::Decision, w::STREAM_NETWORK_DECISION) => {
                    let v = protobuf::decode::<
                        openshell_isolation_interface::contract::TcpOpenDecision,
                    >(&bytes)
                    .map_err(bad)?;
                    *mode = if matches!(
                        v,
                        openshell_isolation_interface::contract::TcpOpenDecision::RelayReady
                    ) {
                        Mode::Relay
                    } else {
                        Mode::Done
                    };
                    Payload::TcpOpenDecision(v.to_proto().map_err(bad)?)
                }
                _ => return Err(bad("invalid local stream channel")),
            }
        }
        Mode::Relay => {
            let mut bytes = vec![0; 16 * 1024];
            let len = reader.read(&mut bytes).await?;
            if len == 0 {
                return Ok(None);
            }
            bytes.truncate(len);
            Payload::RelayData(bytes)
        }
        Mode::DnsQueries | Mode::DnsResponses => return Err(bad("DNS requires Mediate")),
        Mode::Done => {
            let mut byte = [0];
            if reader.read(&mut byte).await? != 0 {
                return Err(bad("unexpected bytes after completed operation"));
            }
            return Ok(None);
        }
    };
    Ok(Some(chunk(payload)))
}

/// Shared local byte adapter for the two distinct RPC stream types.
/// The public schema limits payload kinds; this adapter also checks ordering.
pub trait ProtocolFrame: prost::Message + Default + Send + 'static {
    fn bind(boundary_id: &str) -> Self;
    fn boundary_id(&self) -> Option<&str>;
    fn receive(self, mode: &mut Mode) -> io::Result<Vec<u8>>;
    fn send<R: AsyncRead + Unpin + Send>(
        reader: &mut R,
        mode: &mut Mode,
    ) -> impl Future<Output = io::Result<Option<Self>>> + Send;
}
impl ProtocolFrame for p::ExchangeFrame {
    fn bind(id: &str) -> Self {
        chunk(Payload::BoundaryId(id.into()))
    }
    fn boundary_id(&self) -> Option<&str> {
        match self.payload.as_ref() {
            Some(Payload::BoundaryId(id)) => Some(id),
            _ => None,
        }
    }
    fn receive(self, mode: &mut Mode) -> io::Result<Vec<u8>> {
        receive(mode, self)
    }
    async fn send<R: AsyncRead + Unpin + Send>(
        reader: &mut R,
        mode: &mut Mode,
    ) -> io::Result<Option<Self>> {
        send(reader, mode).await
    }
}
impl ProtocolFrame for p::MediateFrame {
    fn bind(id: &str) -> Self {
        Self {
            payload: Some(p::mediate_frame::Payload::BoundaryId(id.into())),
        }
    }
    fn boundary_id(&self) -> Option<&str> {
        match self.payload.as_ref() {
            Some(p::mediate_frame::Payload::BoundaryId(id)) => Some(id),
            _ => None,
        }
    }
    fn receive(self, mode: &mut Mode) -> io::Result<Vec<u8>> {
        use p::mediate_frame::Payload as M;
        if self.encoded_len() > MAX_MESSAGE_BYTES {
            return Err(bad("protocol message exceeds limit"));
        }
        match (
            *mode,
            self.payload.ok_or_else(|| bad("frame payload missing"))?,
        ) {
            (Mode::Request, M::Request(v))
                if matches!(
                    v.request,
                    Some(p::request_envelope::Request::OpenMediation(_))
                ) =>
            {
                receive(mode, chunk(Payload::Request(v)))
            }
            (Mode::Response, M::Response(v))
                if matches!(
                    v.response,
                    Some(
                        p::response_envelope::Response::MediationReady(_)
                            | p::response_envelope::Response::Error(_)
                    )
                ) =>
            {
                receive(mode, chunk(Payload::Response(v)))
            }
            (Mode::DnsQueries, M::DnsQuery(v)) => {
                let id = v.stream_id;
                let v = m::DnsQueryWire::from_proto(v).map_err(bad)?;
                dns_bytes(
                    m::MediationFrameKind::DnsQuery,
                    id,
                    &protobuf::encode(&v).map_err(bad)?,
                )
            }
            (Mode::DnsResponses, M::DnsResponse(v)) => {
                let id = v.stream_id;
                let v = w::DnsQueryResultWire::from_proto(v).map_err(bad)?;
                dns_bytes(
                    m::MediationFrameKind::DnsResponse,
                    id,
                    &protobuf::encode(&v).map_err(bad)?,
                )
            }

            _ => Err(bad(
                "frame kind does not match mediation operation or direction",
            )),
        }
    }
    async fn send<R: AsyncRead + Unpin + Send>(
        reader: &mut R,
        mode: &mut Mode,
    ) -> io::Result<Option<Self>> {
        use p::mediate_frame::Payload as M;
        let payload = match *mode {
            Mode::DnsQueries | Mode::DnsResponses => {
                let Some(frame) = m::read_frame(reader).await? else {
                    return Ok(None);
                };
                match (*mode, frame.kind) {
                    (Mode::DnsQueries, m::MediationFrameKind::DnsQuery) => {
                        let mut v = protobuf::decode::<m::DnsQueryWire>(&frame.payload)
                            .map_err(bad)?
                            .to_proto()
                            .map_err(bad)?;
                        v.stream_id = frame.stream_id;
                        M::DnsQuery(v)
                    }
                    (Mode::DnsResponses, m::MediationFrameKind::DnsResponse) => {
                        let mut v = protobuf::decode::<w::DnsQueryResultWire>(&frame.payload)
                            .map_err(bad)?
                            .to_proto()
                            .map_err(bad)?;
                        v.stream_id = frame.stream_id;
                        M::DnsResponse(v)
                    }
                    _ => return Err(bad("wrong DNS stream direction")),
                }
            }

            Mode::Request | Mode::Response | Mode::Done => {
                let Some(frame) = send(reader, mode).await? else {
                    return Ok(None);
                };
                match frame.payload {
                    Some(Payload::Request(v))
                        if matches!(
                            v.request,
                            Some(p::request_envelope::Request::OpenMediation(_))
                        ) =>
                    {
                        M::Request(v)
                    }
                    Some(Payload::Response(v))
                        if matches!(
                            v.response,
                            Some(
                                p::response_envelope::Response::MediationReady(_)
                                    | p::response_envelope::Response::Error(_)
                            )
                        ) =>
                    {
                        M::Response(v)
                    }
                    _ => return Err(bad("only OpenMediation is allowed on Mediate")),
                }
            }
            _ => return Err(bad("process and relay I/O require Exchange")),
        };
        Ok(Some(Self {
            payload: Some(payload),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_direction_and_limits_are_enforced_before_forwarding() {
        assert!(receive(&mut Mode::Request, chunk(Payload::RelayData(vec![1]))).is_err());
        assert!(receive(&mut Mode::Input, chunk(Payload::Stdout(vec![1]))).is_err());
        assert!(
            receive(
                &mut Mode::Relay,
                chunk(Payload::RelayData(vec![0; w::MAX_STREAM_FRAME_BYTES + 1]))
            )
            .is_err()
        );
        assert!(receive(&mut Mode::Done, chunk(Payload::Stdin(vec![1]))).is_err());
    }

    #[tokio::test]
    async fn mediation_requires_its_control_handshake_before_dns() {
        let request = w::RequestEnvelope::new(w::Request::OpenMediation).unwrap();
        let bytes = w::encode_frame(&request).unwrap();
        let mut outgoing = Mode::Request;
        let frame = p::MediateFrame::send(&mut bytes.as_slice(), &mut outgoing)
            .await
            .unwrap()
            .unwrap();
        let mut incoming = Mode::Request;
        let decoded = frame.receive(&mut incoming).unwrap();
        assert_eq!(
            w::decode_frame::<w::RequestEnvelope>(&decoded).unwrap(),
            request
        );
        assert!(matches!(outgoing, Mode::DnsResponses));
        assert!(matches!(incoming, Mode::DnsResponses));

        let other = w::RequestEnvelope::new(w::Request::DiscoverPolicy).unwrap();
        let wrong = p::MediateFrame {
            payload: Some(p::mediate_frame::Payload::Request(
                other.to_proto().unwrap(),
            )),
        };
        assert!(wrong.receive(&mut Mode::Request).is_err());
        let dns = p::MediateFrame {
            payload: Some(p::mediate_frame::Payload::DnsResponse(p::DnsResponse {
                stream_id: 1,
                result: Some(p::dns_response::Result::Response(vec![])),
            })),
        };
        assert!(dns.receive(&mut Mode::Request).is_err());
        assert!(
            p::ExchangeFrame::send(&mut &[][..], &mut Mode::DnsResponses)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn typed_dns_preserves_correlation_and_failure() {
        let frame = p::MediateFrame {
            payload: Some(p::mediate_frame::Payload::DnsResponse(p::DnsResponse {
                stream_id: 9_007_199_254_740_993,
                result: Some(p::dns_response::Result::Error(
                    "resolver unavailable".into(),
                )),
            })),
        };
        let bytes = frame.clone().receive(&mut Mode::DnsResponses).unwrap();
        let mut reader = bytes.as_slice();
        assert_eq!(
            p::MediateFrame::send(&mut reader, &mut Mode::DnsResponses)
                .await
                .unwrap(),
            Some(frame)
        );
    }
}
