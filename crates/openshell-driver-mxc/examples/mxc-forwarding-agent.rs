// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only TCP/HTTP fixture for real MXC E2E; not a shipped runtime binary.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str) {
        // The MXC exec test uses this mode to exchange data with a real child
        // process and check its arguments, output streams, and nonzero status.
        Some("--exec-probe") => {
            probe_exec_io(&arguments[2..])?;
            std::process::exit(7); // arbitrary non-zero status
        }
        Some("--print-arg") if arguments.len() == 3 => {
            println!("{}", arguments[2]);
            return Ok(());
        }
        Some("--print-cwd") if arguments.len() == 2 => {
            println!("{}", std::env::current_dir()?.display());
            return Ok(());
        }
        Some("--print-env") if arguments.len() == 3 => {
            // `<unset>` is not a valid value for the checks that use this, so it cannot
            // be confused with a set variable.
            println!(
                "{}",
                std::env::var(&arguments[2]).unwrap_or_else(|_| "<unset>".to_string())
            );
            return Ok(());
        }
        Some("--exit-on-file") if arguments.len() == 4 => {
            let mut launches = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&arguments[2])?;
            writeln!(launches, "launched")?;
            drop(launches);
            let exit_file = std::path::Path::new(&arguments[3]);
            while !exit_file.try_exists()? {
                std::thread::sleep(Duration::from_millis(100));
            }
            return Ok(());
        }
        _ => {}
    }
    if !(arguments.len() == 3 || (matches!(arguments.len(), 4 | 5) && arguments[3] == "http")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "usage: mxc-forwarding-agent READY_FILE NONCE [http [REQUEST_LOG]]",
        ));
    }
    let http_mode = arguments.len() >= 4;
    let request_log = arguments.get(4);
    if let Some(path) = request_log {
        std::fs::write(path, "")?;
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
        let mut reader = BufReader::new((&socket).take(8192));
        reader.read_line(&mut request)?;
        if !request.ends_with('\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request must be a bounded newline-terminated string",
            ));
        }
        if http_mode {
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header)? == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP headers must be bounded and complete",
                    ));
                }
                if header == "\r\n" {
                    break;
                }
            }
            drop(reader);
            let mut fields = request.split_whitespace();
            if fields.next() != Some("GET") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP fixture accepts GET only",
                ));
            }
            let target = fields.next().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing HTTP target")
            })?;
            if let Some(path) = request_log {
                let mut log = std::fs::OpenOptions::new().append(true).open(path)?;
                writeln!(log, "{target}")?;
            }
            let body = format!("{}:{target}", arguments[2]);
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
        } else {
            drop(reader);
            write!(socket, "{}:{request}", arguments[2])?;
        }
    }
    Ok(())
}

fn probe_exec_io(arguments: &[String]) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(b"ready\n")?;
    stdout.flush()?;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    writeln!(stdout, "argv: {}", serde_json::json!(arguments))?;
    write!(stdout, "stdin: {}", serde_json::json!(input))?;
    stdout.flush()?;

    let mut stderr = std::io::stderr().lock();
    stderr.write_all(b"stderr line\nstderr tail")?;
    stderr.flush()
}
