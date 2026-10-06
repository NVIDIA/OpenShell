// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only TCP fixture for real MXC ingress E2E; not a shipped runtime binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    if arguments.len() != 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: mxc-forwarding-agent READY_FILE NONCE",
        ));
    }
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let ready_file = std::path::Path::new(&arguments[1]);
    let staged_ready = ready_file.with_extension("tmp");
    std::fs::write(&staged_ready, listener.local_addr()?.port().to_string())?;
    std::fs::rename(staged_ready, ready_file)?;
    for connection in listener.incoming() {
        let mut socket = connection?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut request = String::new();
        BufReader::new((&socket).take(4096)).read_line(&mut request)?;
        if !request.ends_with('\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request must be a bounded newline-terminated string",
            ));
        }
        write!(socket, "{}:{request}", arguments[2])?;
    }
    Ok(())
}
