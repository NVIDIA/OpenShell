// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Internal streaming-upload protocol shared by the CLI and SSH supervisor.
//!
//! SSH receive credit is replenished before application consumption. This
//! subsystem supplies its own bounded credit: an ACK means boundary stdin has
//! accepted bytes, while RESULT means extraction completed successfully.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::forward::shell_escape;

pub const SUBSYSTEM: &str = "openshell-upload-v1";
pub const WINDOW_BYTES: u32 = 1024 * 1024;
pub const MAX_DATA_BYTES: usize = 64 * 1024;
pub const MAX_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_DIAGNOSTIC_BYTES: usize = 16 * 1024;
pub const DESTINATION_CHANGED_EXIT_CODE: i32 = 73;
const HEADER_BYTES: usize = 12;
const MAGIC: &[u8; 4] = b"OSUP";
// JSON can expand one control character into six bytes (a Unicode escape).
const MAX_ERROR_BYTES: usize = MAX_DIAGNOSTIC_BYTES * 6 + 512;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("upload transport: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid upload protocol: {0}")]
    Invalid(&'static str),
    #[error("invalid upload metadata: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Directory,
    File,
    Missing,
}

impl DestinationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDestination {
    pub path: String,
    pub kind: DestinationKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadPlan {
    pub destination_directory: String,
    pub expected_destination: Option<ExpectedDestination>,
}

impl UploadPlan {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        validate_path(&self.destination_directory)?;
        if let Some(expected) = &self.expected_destination {
            validate_path(&expected.path)?;
        }
        Ok(())
    }
}

fn validate_path(path: &str) -> Result<(), ProtocolError> {
    if path.is_empty() || path.len() > MAX_METADATA_BYTES || path.contains('\0') {
        return Err(ProtocolError::Invalid("invalid destination path"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UploadSummary {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Protocol,
    DestinationChanged,
    Extract,
    InputWrite,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadFailure {
    pub code: FailureCode,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    Hello {
        window_bytes: u32,
        max_data_bytes: u32,
    },
    Begin(UploadPlan),
    Ready,
    Data(Vec<u8>),
    Ack(u64),
    End(UploadSummary),
    Result(UploadSummary),
    Error(UploadFailure),
    Cancel,
}

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let (kind, payload) = match self {
            Self::Hello {
                window_bytes,
                max_data_bytes,
            } => {
                validate_limits(*window_bytes, *max_data_bytes)?;
                let mut bytes = window_bytes.to_be_bytes().to_vec();
                bytes.extend_from_slice(&max_data_bytes.to_be_bytes());
                (1, bytes)
            }
            Self::Begin(plan) => {
                plan.validate()?;
                (2, serde_json::to_vec(plan)?)
            }
            Self::Ready => (3, Vec::new()),
            Self::Data(bytes) => (4, bytes.clone()),
            Self::Ack(bytes) => (5, bytes.to_be_bytes().to_vec()),
            Self::End(summary) => (6, encode_summary(*summary)),
            Self::Result(summary) => (7, encode_summary(*summary)),
            Self::Error(failure) => {
                if failure.message.len() > MAX_DIAGNOSTIC_BYTES {
                    return Err(ProtocolError::Invalid("diagnostic exceeds limit"));
                }
                (8, serde_json::to_vec(failure)?)
            }
            Self::Cancel => (9, Vec::new()),
        };
        validate_length(kind, payload.len())?;
        let length = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::Invalid("frame exceeds limit"))?;
        let mut encoded = Vec::with_capacity(HEADER_BYTES + payload.len());
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&[kind, 0, 0, 0]);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(&payload);
        Ok(encoded)
    }
}

fn validate_limits(window: u32, chunk: u32) -> Result<(), ProtocolError> {
    if window == 0
        || window > WINDOW_BYTES
        || chunk == 0
        || chunk as usize > MAX_DATA_BYTES
        || chunk > window
    {
        return Err(ProtocolError::Invalid("invalid credit limits"));
    }
    Ok(())
}

fn encode_summary(summary: UploadSummary) -> Vec<u8> {
    let mut encoded = summary.bytes.to_be_bytes().to_vec();
    encoded.extend_from_slice(&summary.sha256);
    encoded
}

fn validate_length(kind: u8, length: usize) -> Result<(), ProtocolError> {
    let valid = match kind {
        1 | 5 => length == 8,
        2 => length > 0 && length <= MAX_METADATA_BYTES,
        3 | 9 => length == 0,
        4 => length > 0 && length <= MAX_DATA_BYTES,
        6 | 7 => length == 40,
        8 => length > 0 && length <= MAX_ERROR_BYTES,
        _ => return Err(ProtocolError::Invalid("unknown frame type")),
    };
    if !valid {
        return Err(ProtocolError::Invalid("invalid frame length"));
    }
    Ok(())
}

fn parse_header(header: &[u8; HEADER_BYTES]) -> Result<(u8, usize), ProtocolError> {
    if &header[..4] != MAGIC || header[5..8] != [0, 0, 0] {
        return Err(ProtocolError::Invalid("invalid frame header"));
    }
    let kind = header[4];
    let length = u32::from_be_bytes(header[8..12].try_into().expect("fixed length")) as usize;
    validate_length(kind, length)?;
    Ok((kind, length))
}

fn decode_payload(kind: u8, payload: Vec<u8>) -> Result<Frame, ProtocolError> {
    Ok(match kind {
        1 => {
            let window_bytes = u32::from_be_bytes(payload[..4].try_into().expect("fixed length"));
            let max_data_bytes =
                u32::from_be_bytes(payload[4..8].try_into().expect("fixed length"));
            validate_limits(window_bytes, max_data_bytes)?;
            Frame::Hello {
                window_bytes,
                max_data_bytes,
            }
        }
        2 => {
            let plan: UploadPlan = serde_json::from_slice(&payload)?;
            plan.validate()?;
            Frame::Begin(plan)
        }
        3 => Frame::Ready,
        4 => Frame::Data(payload),
        5 => Frame::Ack(u64::from_be_bytes(
            payload[..8].try_into().expect("fixed length"),
        )),
        6 | 7 => {
            let summary = UploadSummary {
                bytes: u64::from_be_bytes(payload[..8].try_into().expect("fixed length")),
                sha256: payload[8..40].try_into().expect("fixed length"),
            };
            if kind == 6 {
                Frame::End(summary)
            } else {
                Frame::Result(summary)
            }
        }
        8 => {
            let failure: UploadFailure = serde_json::from_slice(&payload)?;
            if failure.message.len() > MAX_DIAGNOSTIC_BYTES {
                return Err(ProtocolError::Invalid("diagnostic exceeds limit"));
            }
            Frame::Error(failure)
        }
        9 => Frame::Cancel,
        _ => return Err(ProtocolError::Invalid("unknown frame type")),
    })
}

/// Incremental decoder holding at most one bounded payload. The caller keeps
/// processing the remaining slice, so coalesced packets do not grow a queue.
#[derive(Default)]
pub struct Decoder {
    header: [u8; HEADER_BYTES],
    header_used: usize,
    payload: Vec<u8>,
    expected: Option<(u8, usize)>,
}

impl Decoder {
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<Frame>, ProtocolError> {
        if self.header_used < HEADER_BYTES {
            let size = input.len().min(HEADER_BYTES - self.header_used);
            self.header[self.header_used..self.header_used + size].copy_from_slice(&input[..size]);
            self.header_used += size;
            *input = &input[size..];
            if self.header_used < HEADER_BYTES {
                return Ok(None);
            }
            let expected = parse_header(&self.header).inspect_err(|_| {
                self.header_used = 0;
            })?;
            self.payload.reserve(expected.1);
            self.expected = Some(expected);
        }
        let (kind, length) = self.expected.expect("validated header");
        let size = input.len().min(length - self.payload.len());
        self.payload.extend_from_slice(&input[..size]);
        *input = &input[size..];
        if self.payload.len() < length {
            return Ok(None);
        }
        self.header_used = 0;
        self.expected = None;
        decode_payload(kind, std::mem::take(&mut self.payload)).map(Some)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.header_used == 0
    }
}

pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame, ProtocolError> {
    let mut header = [0_u8; HEADER_BYTES];
    reader.read_exact(&mut header).await?;
    let (kind, length) = parse_header(&header)?;
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    decode_payload(kind, payload)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &Frame,
) -> Result<(), ProtocolError> {
    writer.write_all(&frame.encode()?).await?;
    Ok(())
}

// This is the existing CLI destination probe, now shared with the receiving
// supervisor. Check existing parents before treating failed existence as absence.
const DESTINATION_KIND_SH: &str = r#"upload_destination_kind() {
    upload_path=$1
    upload_parent=$2
    while :; do
        if [ -d "$upload_parent" ]; then
            if [ ! -x "$upload_parent" ]; then
                printf 'cannot inspect upload destination parent: %s\n' "$upload_parent" >&2
                return 1
            fi
        elif [ -e "$upload_parent" ] || [ -L "$upload_parent" ]; then
            printf 'upload destination parent is not a directory: %s\n' "$upload_parent" >&2
            return 1
        fi
        case "$upload_parent" in
            /|.) break ;;
            */*) upload_parent=${upload_parent%/*}; [ -n "$upload_parent" ] || upload_parent=/ ;;
            *) upload_parent=. ;;
        esac
    done
    if [ -d "$upload_path" ]; then
        printf directory
    elif [ -e "$upload_path" ] || [ -L "$upload_path" ]; then
        printf file
    else
        printf missing
    fi
}"#;

fn destination_invocation(path: &str) -> String {
    let parent = match path.rfind('/') {
        Some(0) => "/",
        Some(position) => &path[..position],
        None => ".",
    };
    format!(
        "upload_destination_kind {} {}",
        shell_escape(path),
        shell_escape(parent)
    )
}

#[must_use]
pub fn build_destination_probe(path: &str) -> String {
    format!("{DESTINATION_KIND_SH}\n{}", destination_invocation(path))
}

pub fn build_extract_command(plan: &UploadPlan) -> Result<String, ProtocolError> {
    plan.validate()?;
    let dest = shell_escape(&plan.destination_directory);
    let extract = format!("mkdir -p -- {dest} && cat | tar xf - -C {dest}");
    let Some(expected) = &plan.expected_destination else {
        return Ok(extract);
    };
    Ok(format!(
        "{DESTINATION_KIND_SH}\n\
         upload_kind=$({probe}) || exit 1\n\
         if [ \"$upload_kind\" != {kind} ]; then\n\
             printf 'upload destination changed type before extraction: %s\\n' {path} >&2\n\
             exit {status}\n\
         fi\n\
         {extract}",
        probe = destination_invocation(&expected.path),
        kind = expected.kind.as_str(),
        path = shell_escape(&expected.path),
        status = DESTINATION_CHANGED_EXIT_CODE,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames() -> Vec<Frame> {
        let summary = UploadSummary {
            bytes: u64::MAX,
            sha256: [7; 32],
        };
        vec![
            Frame::Hello {
                window_bytes: WINDOW_BYTES,
                max_data_bytes: u32::try_from(MAX_DATA_BYTES).unwrap(),
            },
            Frame::Begin(UploadPlan {
                destination_directory: "/tmp/with 'quotes'".into(),
                expected_destination: Some(ExpectedDestination {
                    path: "/tmp/file".into(),
                    kind: DestinationKind::Missing,
                }),
            }),
            Frame::Ready,
            Frame::Data(vec![42; MAX_DATA_BYTES]),
            Frame::Ack(u64::MAX),
            Frame::End(summary),
            Frame::Result(summary),
            Frame::Error(UploadFailure {
                code: FailureCode::InputWrite,
                message: "stdin closed".into(),
            }),
            Frame::Cancel,
        ]
    }

    #[test]
    fn fragmented_and_coalesced_frames_round_trip() {
        let frames = frames();
        let encoded = frames
            .iter()
            .flat_map(|f| f.encode().unwrap())
            .collect::<Vec<_>>();
        for size in [1, 7, 12, 4096, encoded.len()] {
            let mut decoder = Decoder::default();
            let mut output = Vec::new();
            for chunk in encoded.chunks(size) {
                let mut input = chunk;
                while !input.is_empty() {
                    if let Some(frame) = decoder.decode(&mut input).unwrap() {
                        output.push(frame);
                    }
                }
            }
            assert!(decoder.is_empty());
            assert_eq!(output, frames);
        }
    }

    #[test]
    fn malformed_headers_fail_before_payload_allocation() {
        let good = Frame::Ready.encode().unwrap();
        for offset in [0, 4, 5, 6, 7, 8, 9, 10, 11] {
            let mut bad = good.clone();
            bad[offset] = 255;
            let mut decoder = Decoder::default();
            assert!(decoder.decode(&mut bad.as_slice()).is_err());
            assert_eq!(decoder.payload.capacity(), 0);
        }
        assert!(Frame::Data(vec![0; MAX_DATA_BYTES + 1]).encode().is_err());
        assert!(
            Frame::Hello {
                window_bytes: WINDOW_BYTES + 1,
                max_data_bytes: 1
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn metadata_rejects_unknown_fields_and_nul_paths() {
        let bad = br#"{"destination_directory":"/tmp","expected_destination":null,"command":"id"}"#
            .to_vec();
        assert!(decode_payload(2, bad).is_err());
        assert!(
            UploadPlan {
                destination_directory: "/tmp\0bad".into(),
                expected_destination: None
            }
            .validate()
            .is_err()
        );
        assert!(
            Frame::Error(UploadFailure {
                code: FailureCode::Protocol,
                message: "a".repeat(MAX_DIAGNOSTIC_BYTES + 1)
            })
            .encode()
            .is_err()
        );
    }

    #[tokio::test]
    async fn async_codec_rejects_truncation() {
        let encoded = Frame::Data(vec![7; 32]).encode().unwrap();
        let mut input = &encoded[..encoded.len() - 1];
        assert!(matches!(
            read_frame(&mut input).await,
            Err(ProtocolError::Io(_))
        ));
        let mut output = Vec::new();
        write_frame(&mut output, &Frame::Ack(12)).await.unwrap();
        assert_eq!(
            read_frame(&mut output.as_slice()).await.unwrap(),
            Frame::Ack(12)
        );
    }
}
