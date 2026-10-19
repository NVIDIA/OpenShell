// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! One V8 isolate with bounded console output and no guest I/O.
use std::{
    ffi::c_void,
    fs::File,
    io::Read,
    path::Path,
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_SCRIPT: usize = 256 * 1024;
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_HEAP: usize = 32 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);

pub fn read_script(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((MAX_SCRIPT + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_SCRIPT, "script exceeds 256 KiB");
    std::str::from_utf8(&bytes)?;
    Ok(bytes)
}

#[derive(Clone, Default)]
pub struct Output(Arc<Mutex<Vec<u8>>>);

impl Output {
    pub fn contents(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }

    fn append(&self, text: &str) -> bool {
        let mut bytes = self.0.lock().unwrap();
        if text.len() + bytes.len() > MAX_OUTPUT {
            return false;
        }
        bytes.extend_from_slice(text.as_bytes());
        true
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuestStatus {
    Exited,
    Terminated,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct GuestResult {
    pub status: GuestStatus,
    pub exit_code: Option<i32>,
    #[serde(skip)]
    pub stdout: Vec<u8>,
    #[serde(skip)]
    pub stderr: Vec<u8>,
    pub script_sha256: String,
}

struct State {
    stdout: Output,
    stderr: Output,
    rejections: Vec<v8::Global<v8::Promise>>,
}

pub struct Guest {
    source: String,
    digest: String,
    cancelled: AtomicBool,
    isolate: Mutex<Option<v8::IsolateHandle>>,
}

impl Guest {
    pub fn new(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_SCRIPT, "script exceeds 256 KiB");
        Ok(Self {
            source: std::str::from_utf8(bytes)?.to_owned(),
            digest: format!("{:x}", Sha256::digest(bytes)),
            cancelled: AtomicBool::new(false),
            isolate: Mutex::new(None),
        })
    }

    pub fn terminate(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        if let Some(handle) = self.isolate.lock().unwrap().as_ref() {
            handle.terminate_execution();
        }
    }

    pub fn run(&self, ready: impl FnOnce(Output, Output)) -> Result<GuestResult> {
        static INITIALIZE: Once = Once::new();
        INITIALIZE.call_once(|| {
            v8::V8::initialize_platform(v8::new_default_platform(0, false).make_shared());
            v8::V8::initialize();
        });
        let stdout = Output::default();
        let stderr = Output::default();
        ready(stdout.clone(), stderr.clone());
        // Dropping `done` also releases the watchdog if execution returns early.
        let (done, finished) = std::sync::mpsc::channel::<()>();
        let outcome = std::thread::scope(|threads| {
            threads.spawn(move || {
                if matches!(
                    finished.recv_timeout(DEADLINE),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    self.terminate();
                }
            });
            let outcome = self.execute(stdout.clone(), &stderr);
            drop(done);
            outcome
        })?;
        *self.isolate.lock().unwrap() = None;
        Ok(GuestResult {
            exit_code: match outcome {
                GuestStatus::Exited => Some(0),
                GuestStatus::Failed => Some(1),
                GuestStatus::Terminated => None,
            },
            status: outcome,
            stdout: stdout.contents(),
            stderr: stderr.contents(),
            script_sha256: self.digest.clone(),
        })
    }

    fn execute(&self, stdout: Output, stderr: &Output) -> Result<GuestStatus> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default().heap_limits(0, MAX_HEAP));
        *self.isolate.lock().unwrap() = Some(isolate.thread_safe_handle());
        if self.cancelled.load(Ordering::SeqCst) {
            return Ok(GuestStatus::Terminated);
        }
        isolate.set_slot(State {
            stdout,
            stderr: stderr.clone(),
            rejections: Vec::new(),
        });
        isolate.set_promise_reject_callback(promise_rejected);
        // The callback borrows this Guest only while execute() owns the isolate.
        isolate
            .add_near_heap_limit_callback(heap_limit, std::ptr::from_ref(self).cast_mut().cast());
        let result = (|| {
            v8::scope!(let scope, &mut isolate);
            let global = v8::ObjectTemplate::new(scope);
            global.set(
                v8::String::new(scope, "fetch").unwrap().into(),
                v8::FunctionTemplate::new(scope, deny_network).into(),
            );
            let context = v8::Context::new(
                scope,
                v8::ContextOptions {
                    global_template: Some(global),
                    ..Default::default()
                },
            );
            let scope = &mut v8::ContextScope::new(scope, context);
            // V8 installs a console while creating the context; replace it only
            // after that step so every log goes through our bounded capture.
            let console = v8::Object::new(scope);
            let logger = v8::Function::new(scope, log).unwrap();
            let log_key = v8::String::new(scope, "log").unwrap();
            console.set(scope, log_key.into(), logger.into());
            let error_logger = v8::Function::new(scope, log_error).unwrap();
            let error_key = v8::String::new(scope, "error").unwrap();
            console.set(scope, error_key.into(), error_logger.into());
            let console_key = v8::String::new(scope, "console").unwrap();
            context
                .global(scope)
                .set(scope, console_key.into(), console.into());
            v8::tc_scope!(let scope, scope);
            let source = v8::String::new(scope, &self.source)
                .ok_or_else(|| anyhow::anyhow!("source allocation failed"))?;
            let result =
                v8::Script::compile(scope, source, None).and_then(|script| script.run(scope));
            // Drain ordinary JS microtasks, but install no timers, loaders, or I/O.
            if result.is_some() {
                scope.perform_microtask_checkpoint();
            }
            let rejections = std::mem::take(&mut scope.get_slot_mut::<State>().unwrap().rejections);
            let rejection = rejections
                .iter()
                .map(|promise| v8::Local::new(scope, promise))
                .find(|promise| !promise.has_handler())
                .map(|promise| promise.result(scope));
            if scope.has_terminated() {
                Ok(GuestStatus::Terminated)
            } else if result.is_some() && rejection.is_none() {
                Ok(GuestStatus::Exited)
            } else {
                let message = scope
                    .exception()
                    .or(rejection)
                    .and_then(|value| value.to_string(scope))
                    .map(|value| {
                        if value.length() > MAX_OUTPUT {
                            "JavaScript exception exceeds output limit".into()
                        } else {
                            value.to_rust_string_lossy(scope)
                        }
                    })
                    .unwrap_or_else(|| "JavaScript execution failed".into());
                stderr.append(&message);
                stderr.append("\n");
                Ok(GuestStatus::Failed)
            }
        })();
        isolate.remove_near_heap_limit_callback(heap_limit, 0);
        isolate.remove_slot::<State>();
        result
    }
}

extern "C" fn promise_rejected(message: v8::PromiseRejectMessage) {
    if message.get_event() != v8::PromiseRejectEvent::PromiseRejectWithNoHandler {
        return;
    }
    // SAFETY: V8 invokes this callback with a live promise on the current isolate.
    v8::callback_scope!(unsafe scope, &message);
    let promise = v8::Global::new(scope, message.get_promise());
    scope
        .get_slot_mut::<State>()
        .unwrap()
        .rejections
        .push(promise);
}

unsafe extern "C" fn heap_limit(data: *mut c_void, current: usize, _initial: usize) -> usize {
    // SAFETY: execute() registers its borrowed Guest and removes the callback
    // before disposing the isolate; the Guest remains alive for that whole call.
    let guest = unsafe { &*data.cast::<Guest>() };
    guest.terminate();
    // Give V8 room to unwind after termination instead of aborting on heap OOM.
    current.saturating_add(8 * 1024 * 1024)
}

fn log(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, _result: v8::ReturnValue) {
    write_output(scope, args, false);
}

fn log_error(
    scope: &mut v8::PinScope,
    args: v8::FunctionCallbackArguments,
    _result: v8::ReturnValue,
) {
    write_output(scope, args, true);
}

fn write_output(scope: &mut v8::PinScope, args: v8::FunctionCallbackArguments, error: bool) {
    let Some(text) = args.get(0).to_string(scope) else {
        return;
    };
    if text.length() > MAX_OUTPUT {
        scope.terminate_execution();
        return;
    }
    let message = text.to_rust_string_lossy(scope);
    let state = scope.get_slot::<State>().unwrap();
    let output = if error { &state.stderr } else { &state.stdout };
    if !output.append(&message) || !output.append("\n") {
        scope.terminate_execution();
    }
}

fn deny_network(
    scope: &mut v8::PinScope,
    _args: v8::FunctionCallbackArguments,
    _result: v8::ReturnValue,
) {
    let message = v8::String::new(scope, "Network access is disabled").unwrap();
    let error = v8::Exception::error(scope, message);
    scope.throw_exception(error);
}
