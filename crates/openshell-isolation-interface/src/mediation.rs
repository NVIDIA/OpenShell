// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Framing for the persistent sandbox-to-supervisor DNS data plane.
//!
//! TCP connections use independent streams on the authenticated HTTP/2
//! transport so one busy connection cannot head-of-line block another.

use std::io;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::boundary_protocol::{BinaryIdentityWire, MediationTimingWire};
use crate::contract::DnsTransport;

const HEADER_BYTES: usize = 13;
const MAX_METADATA_BYTES: usize = 256 * 1024;
const MAX_FRAME_BYTES: usize = MAX_METADATA_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MediationFrameKind {
    DnsQuery = 5,
    DnsResponse = 6,
}

impl TryFrom<u8> for MediationFrameKind {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            5 => Ok(Self::DnsQuery),
            6 => Ok(Self::DnsResponse),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown mediation frame kind {value}"),
            )),
        }
    }
}

#[derive(Debug)]
pub struct MediationFrame {
    pub kind: MediationFrameKind,
    pub stream_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsQueryWire {
    pub request: Vec<u8>,
    pub transport: DnsTransport,
    pub identity: BinaryIdentityWire,
    pub timing: MediationTimingWire,
}

pub fn encode_json<T: Serialize>(value: &T) -> io::Result<Vec<u8>> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_METADATA_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediation metadata frame exceeds limit",
        ));
    }
    Ok(payload)
}

pub fn decode_json<T: DeserializeOwned>(payload: &[u8]) -> io::Result<T> {
    serde_json::from_slice(payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: MediationFrameKind,
    stream_id: u64,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_FRAME_BYTES.max(MAX_METADATA_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediation frame exceeds limit",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mediation frame too large"))?;
    let mut header = [0_u8; HEADER_BYTES];
    header[0] = kind as u8;
    header[1..9].copy_from_slice(&stream_id.to_be_bytes());
    header[9..13].copy_from_slice(&length.to_be_bytes());
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<MediationFrame>> {
    let mut header = [0_u8; HEADER_BYTES];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let kind = MediationFrameKind::try_from(header[0])?;
    let stream_id = u64::from_be_bytes(
        header[1..9]
            .try_into()
            .map_err(|_| io::Error::other("invalid stream ID header"))?,
    );
    let length = u32::from_be_bytes(
        header[9..13]
            .try_into()
            .map_err(|_| io::Error::other("invalid payload length header"))?,
    ) as usize;
    if length > MAX_FRAME_BYTES.max(MAX_METADATA_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mediation frame exceeds limit",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some(MediationFrame {
        kind,
        stream_id,
        payload,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip_preserves_binary_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let send = tokio::spawn(async move {
            write_frame(
                &mut writer,
                MediationFrameKind::DnsResponse,
                42,
                &[0, 1, 2, 255],
            )
            .await
            .unwrap();
        });
        let frame = read_frame(&mut reader).await.unwrap().unwrap();
        assert_eq!(frame.kind, MediationFrameKind::DnsResponse);
        assert_eq!(frame.stream_id, 42);
        assert_eq!(frame.payload, vec![0, 1, 2, 255]);
        send.await.unwrap();
    }
}
