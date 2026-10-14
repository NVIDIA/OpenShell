// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Local guest execution. Deliberately unreachable through the backend service.
use std::{
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};
use wasmtime_wasi::{
    DirPerms, FilePerms, I32Exit, WasiCtxBuilder,
    p1::{self, WasiP1Ctx},
    p2::pipe::MemoryOutputPipe,
};

pub const DEFAULT_FUEL: u64 = 1_000_000;
const MAX_MODULE: u64 = 4 * 1024 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;

pub fn read_module(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_MODULE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_MODULE,
        "module exceeds the 4 MiB prototype limit"
    );
    // Normalize WAT to the actual module bytes before computing its identity.
    let bytes = wat::parse_bytes(&bytes)?.into_owned();
    ensure!(
        bytes.len() as u64 <= MAX_MODULE,
        "compiled module exceeds the 4 MiB prototype limit"
    );
    Ok(bytes)
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestStatus {
    Exited,
    Terminated,
    FuelExhausted,
    Trapped,
    UnsupportedModule,
}

#[derive(Debug, Serialize)]
pub struct GuestResult {
    pub status: GuestStatus,
    pub exit_code: Option<i32>,
    #[serde(skip)]
    pub stdout: Vec<u8>,
    #[serde(skip)]
    pub stderr: Vec<u8>,
    pub module_sha256: String,
}

struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

/// One engine per guest: terminating one guest cannot interrupt another.
pub struct Guest {
    engine: Engine,
    module: Module,
    digest: String,
    cancelled: AtomicBool,
}

impl Guest {
    pub fn new(module: &[u8]) -> Result<Self> {
        let mut config = Config::new();
        config.consume_fuel(true).epoch_interruption(true);
        let engine = Engine::new(&config)?;
        Ok(Self {
            module: Module::new(&engine, module)?,
            engine,
            digest: format!("{:x}", Sha256::digest(module)),
            cancelled: AtomicBool::new(false),
        })
    }

    pub fn terminate(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.engine.increment_epoch();
    }

    pub fn run(&self, workspace: &Path, fuel: u64) -> Result<GuestResult> {
        self.run_when_ready(workspace, fuel, || {})
    }

    /// Calls `ready` once the store's interruption deadline is armed.
    pub fn run_when_ready(
        &self,
        workspace: &Path,
        fuel: u64,
        ready: impl FnOnce(),
    ) -> Result<GuestResult> {
        let stdout = MemoryOutputPipe::new(MAX_OUTPUT);
        let stderr = MemoryOutputPipe::new(MAX_OUTPUT);
        let wasi = WasiCtxBuilder::new()
            .arg("/work/guest.wasm")
            .stdout(stdout.clone())
            .stderr(stderr.clone())
            .preopened_dir(
                workspace.canonicalize()?,
                "/work",
                DirPerms::READ,
                FilePerms::READ,
            )?
            .build_p1();
        let mut store = Store::new(
            &self.engine,
            State {
                wasi,
                limits: StoreLimitsBuilder::new()
                    .memory_size(16 * 1024 * 1024)
                    .table_elements(1024)
                    .instances(1)
                    .tables(1)
                    .memories(1)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store.set_fuel(fuel)?;
        store.set_epoch_deadline(1);
        let mut linker = Linker::new(&self.engine);
        p1::add_to_linker_sync(&mut linker, |state: &mut State| &mut state.wasi)?;
        let pre = linker.instantiate_pre(&self.module);
        ready();
        let (status, exit_code) = if self.cancelled.load(Ordering::SeqCst) {
            (GuestStatus::Terminated, None)
        } else if let Ok(pre) = pre {
            // Instantiation may execute a start function; it happens only here.
            let result = pre.instantiate(&mut store).and_then(|instance| {
                instance
                    .get_typed_func::<(), ()>(&mut store, "_start")?
                    .call(&mut store, ())
            });
            match result {
                Ok(()) => (GuestStatus::Exited, Some(0)),
                Err(error) => {
                    if let Some(exit) = error.downcast_ref::<I32Exit>() {
                        (GuestStatus::Exited, Some(exit.0))
                    } else {
                        let status = match error.downcast_ref::<Trap>() {
                            Some(Trap::Interrupt) => GuestStatus::Terminated,
                            Some(Trap::OutOfFuel) => GuestStatus::FuelExhausted,
                            _ => GuestStatus::Trapped,
                        };
                        (status, None)
                    }
                }
            }
        } else {
            (GuestStatus::UnsupportedModule, None)
        };
        Ok(GuestResult {
            status,
            exit_code,
            stdout: stdout.contents().to_vec(),
            stderr: stderr.contents().to_vec(),
            module_sha256: self.digest.clone(),
        })
    }
}
