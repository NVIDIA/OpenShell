// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use testkit::{Poll, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::http::read_request;
use crate::{MAX_REQUEST, READ_TIMEOUT, Server, WAIT_INTERVAL, WAIT_TIMEOUT, header};

/// A WebSocket server that completes the handshake, then reads frames until
/// the connection closes. It records whether any was a binary frame, records
/// each text frame, and answers each text frame with [`TEXT_REPLY`].
pub struct WebSocketRecorder {
    pub port: u16,
    state: Arc<WebSocketState>,
    _server: Server,
}

/// The text frame a [`WebSocketRecorder`] sends after each text frame.
pub const TEXT_REPLY: &str = "received";

#[derive(Default)]
struct WebSocketState {
    handshake_seen: AtomicBool,
    binary_seen: AtomicBool,
    finished: AtomicBool,
    texts: Mutex<Vec<String>>,
}

impl WebSocketRecorder {
    pub async fn start() -> Result<Self> {
        let state = Arc::new(WebSocketState::default());
        let task_state = Arc::clone(&state);
        let server =
            Server::start(move |stream| accept_websocket(stream, Arc::clone(&task_state))).await?;
        Ok(Self {
            port: server.port,
            state,
            _server: server,
        })
    }

    /// Wait until a client completed the handshake.
    pub async fn wait_for_handshake(&self) -> Result {
        testkit::poll_until(
            &format!(
                "a WebSocket handshake at the host server on port {}",
                self.port
            ),
            WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                Ok(if self.state.handshake_seen.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending("no handshake".to_string())
                })
            },
        )
        .await
    }

    /// Wait until a connection that completed the handshake has ended, by a
    /// close frame, the client closing it, or [`READ_TIMEOUT`] passing, and
    /// return whether a binary frame arrived on it.
    pub async fn wait_until_finished(&self) -> Result<bool> {
        testkit::poll_until(
            &format!(
                "the WebSocket connection at the host server on port {} to end",
                self.port
            ),
            READ_TIMEOUT + WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                Ok(if self.state.finished.load(Ordering::Acquire) {
                    Poll::Ready(self.state.binary_seen.load(Ordering::Acquire))
                } else {
                    Poll::Pending("the connection is open".to_string())
                })
            },
        )
        .await
    }

    /// The text frames the server has read so far.
    pub fn texts(&self) -> Vec<String> {
        self.state
            .texts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

async fn accept_websocket(mut stream: TcpStream, state: Arc<WebSocketState>) {
    let _ = stream.set_nodelay(true);
    let Some(request) = read_request(&mut stream, &mut Vec::new()).await else {
        return;
    };
    let Some(key) = header(&request.head, "sec-websocket-key") else {
        return;
    };
    // The supervisor checks Sec-WebSocket-Accept, so compute it properly.
    let accept = tungstenite::handshake::derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    state.handshake_seen.store(true, Ordering::Release);

    let _ = tokio::time::timeout(READ_TIMEOUT, read_frames(&mut stream, &state)).await;
    state.finished.store(true, Ordering::Release);
}

/// Read frames until a close frame or the end of the stream, record a
/// binary frame and each text frame, and answer each text frame.
async fn read_frames(stream: &mut TcpStream, state: &WebSocketState) -> std::io::Result<()> {
    loop {
        let mut frame_header = [0_u8; 2];
        stream.read_exact(&mut frame_header).await?;
        let opcode = frame_header[0] & 0x0f;
        let length = match frame_header[1] & 0x7f {
            126 => u64::from(stream.read_u16().await?),
            127 => stream.read_u64().await?,
            length => u64::from(length),
        };
        match opcode {
            0x01 => {
                let text = read_payload(stream, frame_header[1], length).await?;
                state
                    .texts
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(String::from_utf8_lossy(&text).into_owned());
                stream.write_all(&server_text_frame(TEXT_REPLY)).await?;
                continue;
            }
            0x02 => state.binary_seen.store(true, Ordering::Release),
            _ => {}
        }
        let mask = if frame_header[1] & 0x80 == 0 { 0 } else { 4 };
        // Read a close frame's payload too, since closing with unread bytes
        // resets the connection.
        let skipped = tokio::io::copy(
            &mut (&mut *stream).take(mask + length),
            &mut tokio::io::sink(),
        )
        .await?;
        if opcode == 0x08 || skipped < mask + length {
            return Ok(());
        }
    }
}

/// Read a text frame's payload, unmasked, up to [`MAX_REQUEST`] bytes.
async fn read_payload(
    stream: &mut TcpStream,
    second_byte: u8,
    length: u64,
) -> std::io::Result<Vec<u8>> {
    let length = usize::try_from(length)
        .ok()
        .filter(|length| *length <= MAX_REQUEST)
        .ok_or_else(|| std::io::Error::other("text frame too large"))?;
    let mut mask = [0_u8; 4];
    if second_byte & 0x80 != 0 {
        stream.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok(payload)
}

/// A final, unmasked server text frame.
fn server_text_frame(text: &str) -> Vec<u8> {
    let mut frame = vec![0x81];
    match text.len() {
        length @ 0..=125 => frame.push(u8::try_from(length).unwrap_or_default()),
        length => {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
        }
    }
    frame.extend_from_slice(text.as_bytes());
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::find;

    /// Complete a handshake with `recorder`, send `frames`, and close.
    async fn send_frames(recorder: &WebSocketRecorder, frames: &[(u8, Vec<u8>)]) -> TcpStream {
        #[allow(
            clippy::disallowed_methods,
            reason = "standalone test support has no openshell-core dependency and enables TCP_NODELAY below"
        )]
        let mut stream = TcpStream::connect(("127.0.0.1", recorder.port))
            .await
            .unwrap();
        stream.set_nodelay(true).unwrap();
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        while find(&response, b"\r\n\r\n").is_none() {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "closed during the handshake");
            response.extend_from_slice(&buffer[..read]);
        }
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 101"), "{response}");
        // The RFC 6455 sample key's accept value.
        assert!(
            response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "{response}"
        );
        for (opcode, payload) in frames {
            stream.write_all(&frame(*opcode, payload)).await.unwrap();
        }
        stream.write_all(&frame(0x08, &[])).await.unwrap();
        stream
    }

    /// A final, masked client frame.
    fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [1_u8, 2, 3, 4];
        let mut frame = vec![0x80 | opcode];
        match payload.len() {
            length @ 0..=125 => frame.push(0x80 | u8::try_from(length).unwrap()),
            length => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        frame
    }

    #[tokio::test]
    async fn websocket_recorder_sees_a_binary_frame_after_a_long_text_frame() {
        let recorder = WebSocketRecorder::start().await.unwrap();
        // Hold the connection so the replies to text frames don't reset it.
        let _stream = send_frames(
            &recorder,
            &[(0x01, vec![b'x'; 300]), (0x02, b"binary".to_vec())],
        )
        .await;
        assert!(recorder.wait_until_finished().await.unwrap());
        assert_eq!(recorder.texts(), ["x".repeat(300)]);
    }

    #[tokio::test]
    async fn websocket_recorder_sees_no_binary_frame_in_text_frames() {
        let recorder = WebSocketRecorder::start().await.unwrap();
        // Hold the connection so the replies to text frames don't reset it.
        let _stream = send_frames(
            &recorder,
            &[(0x01, vec![b'x'; 300]), (0x01, b"text".to_vec())],
        )
        .await;
        assert!(!recorder.wait_until_finished().await.unwrap());
    }

    #[tokio::test]
    async fn websocket_recorder_answers_each_text_frame() {
        let recorder = WebSocketRecorder::start().await.unwrap();
        let mut stream = send_frames(
            &recorder,
            &[(0x01, b"one".to_vec()), (0x01, b"two".to_vec())],
        )
        .await;
        let mut replies = Vec::new();
        stream.read_to_end(&mut replies).await.unwrap();
        assert_eq!(
            replies,
            [server_text_frame(TEXT_REPLY), server_text_frame(TEXT_REPLY)].concat()
        );
        recorder.wait_until_finished().await.unwrap();
        assert_eq!(recorder.texts(), ["one", "two"]);
    }
}
