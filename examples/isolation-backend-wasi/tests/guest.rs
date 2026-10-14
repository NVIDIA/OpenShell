// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_wasi_backend_example::guest::{DEFAULT_FUEL, Guest, GuestStatus, read_module};
use std::{path::Path, sync::Arc, time::Duration};

#[test]
#[cfg(unix)]
fn wasi_reads_only_the_workspace() {
    let temp = tempfile::tempdir().unwrap();
    let workspace = temp.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(workspace.join("allowed.txt"), "workspace content\n").unwrap();
    std::fs::write(temp.path().join("secret.txt"), "outside secret\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(temp.path().join("secret.txt"), workspace.join("escape")).unwrap();
    let bytes = read_module(&Path::new(env!("CARGO_MANIFEST_DIR")).join("guest.wat")).unwrap();
    let result = Guest::new(&bytes)
        .unwrap()
        .run(&workspace, DEFAULT_FUEL)
        .unwrap();
    assert_eq!(result.status, GuestStatus::Exited, "{result:?}");
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(
        result.stdout,
        b"workspace content\nescape denied\nsymlink denied\nwrite denied\n"
    );
    assert!(!workspace.join("new.txt").exists());
}

#[test]
fn guest_limits_fuel_memory_and_imports() {
    let temp = tempfile::tempdir().unwrap();
    for (module, expected) in [
        (
            "(module (func (export \"_start\") (loop $l br $l)))",
            GuestStatus::FuelExhausted,
        ),
        (
            "(module (memory 257) (func (export \"_start\")))",
            GuestStatus::Trapped,
        ),
        (
            "(module (import \"wasi:sockets/tcp\" \"create-socket\" (func)) (func (export \"_start\")))",
            GuestStatus::UnsupportedModule,
        ),
        (
            "(module (func (export \"_start\") unreachable))",
            GuestStatus::Trapped,
        ),
    ] {
        let result = Guest::new(module.as_bytes())
            .unwrap()
            .run(temp.path(), DEFAULT_FUEL)
            .unwrap();
        assert_eq!(result.status, expected, "{result:?}");
    }
}

#[test]
fn termination_interrupts_only_its_owned_engine() {
    let temp = tempfile::tempdir().unwrap();
    let guest =
        Arc::new(Guest::new(b"(module (func (export \"_start\") (loop $l br $l)))").unwrap());
    let worker_guest = guest.clone();
    let workspace = temp.path().to_owned();
    let (ready_send, ready_receive) = std::sync::mpsc::channel();
    let (done_send, done_receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let result = worker_guest.run_when_ready(&workspace, 1_000_000_000_000, || {
            ready_send.send(()).unwrap()
        });
        done_send.send(result).unwrap();
    });
    ready_receive.recv_timeout(Duration::from_secs(5)).unwrap();
    guest.terminate();
    let result = done_receive
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    assert_eq!(result.status, GuestStatus::Terminated);
    worker.join().unwrap();
    let independent = Guest::new(b"(module (func (export \"_start\")))").unwrap();
    assert_eq!(
        independent.run(temp.path(), DEFAULT_FUEL).unwrap().status,
        GuestStatus::Exited
    );
}

#[test]
fn output_capture_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let module = br#"(module
        (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
        (memory (export "memory") 2)
        (data (i32.const 0) "\10\00\00\00\01\00\01\00")
        (func (export "_start")
            i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write drop))"#;
    let result = Guest::new(module)
        .unwrap()
        .run(temp.path(), DEFAULT_FUEL)
        .unwrap();
    assert!(!result.stdout.is_empty(), "{result:?}");
    assert!(result.stdout.len() <= 64 * 1024);
}
