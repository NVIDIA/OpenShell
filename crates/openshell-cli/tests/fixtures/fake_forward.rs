// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    if std::env::args_os().next().as_deref() != Some(std::ffi::OsStr::new("ssh")) {
        reexec_as_ssh();
    }

    match std::env::var("OPENSHELL_FAKE_FORWARD_MODE").as_deref() {
        Ok("listen") => run_listener(),
        Ok("sleep") => loop {
            thread::sleep(Duration::from_secs(60));
        },
        _ => std::process::exit(2),
    }
}

fn reexec_as_ssh() -> ! {
    use std::os::unix::process::CommandExt;

    let executable = std::env::current_exe().expect("fake forward must resolve its executable");
    let error = Command::new(executable)
        .arg0("ssh")
        .args(std::env::args_os().skip(1))
        .exec();
    panic!("fake forward failed to re-execute as ssh: {error}");
}

fn run_listener() {
    let port = forward_port().expect("fake forward must receive an SSH -L argument");
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("fake forward must bind");
    for stream in listener.incoming() {
        let _ = stream;
    }
}

fn forward_port() -> Option<u16> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-L" {
            return args.get(index + 1).and_then(|value| local_port(value));
        }
        if let Some(value) = arg.strip_prefix("-L").filter(|value| !value.is_empty()) {
            return local_port(value);
        }
        index += 1;
    }
    None
}

fn local_port(forward: &str) -> Option<u16> {
    let (first, rest) = forward.split_once(':')?;
    if first.bytes().all(|byte| byte.is_ascii_digit()) {
        return first.parse().ok();
    }
    rest.split_once(':')?.0.parse().ok()
}
