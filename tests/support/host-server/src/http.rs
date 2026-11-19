// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex, PoisonError};

use testkit::{Poll, Result};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::{MAX_REQUEST, READ_TIMEOUT, WAIT_INTERVAL, WAIT_TIMEOUT, bind, find, header};

/// A request an [`HttpRecorder`] read.
#[derive(Clone, Debug)]
pub struct Request {
    /// The request line and headers.
    pub head: String,
    pub body: String,
}

/// An HTTP server that answers every request with `200` and a fixed body,
/// and records each request it read. It reads a body by `Content-Length`
/// only, not a chunked one.
pub struct HttpRecorder {
    pub port: u16,
    requests: Arc<Mutex<Vec<Request>>>,
    task: JoinHandle<()>,
}

impl HttpRecorder {
    pub async fn start(body: impl Into<String>) -> Result<Self> {
        let (listener, port) = bind().await?;
        let body: Arc<str> = body.into().into();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(respond(
                    stream,
                    Arc::clone(&body),
                    Arc::clone(&task_requests),
                ));
            }
        });
        Ok(Self {
            port,
            requests,
            task,
        })
    }

    /// The requests the server has read, once there are at least `count`.
    pub async fn wait_for_requests(&self, count: usize) -> Result<Vec<Request>> {
        testkit::poll_until(
            &format!(
                "{count} request(s) at the host server on port {}",
                self.port
            ),
            WAIT_TIMEOUT,
            WAIT_INTERVAL,
            async || {
                let requests = self
                    .requests
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                Ok(if requests.len() >= count {
                    Poll::Ready(requests)
                } else {
                    Poll::Pending(format!("{} request(s)", requests.len()))
                })
            },
        )
        .await
    }
}

impl Drop for HttpRecorder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Read one request, headers and `Content-Length` body, record it, and
/// answer with `body`.
async fn respond(mut stream: TcpStream, body: Arc<str>, requests: Arc<Mutex<Vec<Request>>>) {
    let _ = stream.set_nodelay(true);
    let Some(request) = read_request(&mut stream).await else {
        return;
    };
    requests
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(request);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

pub(crate) async fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        if let Some(end) = find(&request, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).into_owned();
            let length = header(&head, "content-length")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                let body =
                    String::from_utf8_lossy(&request[end + 4..end + 4 + length]).into_owned();
                return Some(Request { head, body });
            }
        }
        match tokio::time::timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
            Ok(Ok(read)) if read > 0 && request.len() < MAX_REQUEST => {
                request.extend_from_slice(&buffer[..read]);
            }
            _ => return None,
        }
    }
}
