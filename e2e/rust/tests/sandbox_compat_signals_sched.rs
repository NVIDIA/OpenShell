// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end compatibility for scheduling, priority, resource-limit, and
//! self-directed signal calls inside a sandbox.
//!
//! The static child filter used to deny these syscalls whatever their target,
//! so `pthread_setaffinity_np`, `taskset -p`, `prlimit(getpid())`, and `nice`
//! failed with EPERM. The broker now mediates them: the caller's own thread
//! group is allowed and every other target stays denied.

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

const SUCCESS_MARKER: &str = "sandbox_compat_signals_sched=ok";

/// Reconfigure the workload's own thread group through each mediated syscall.
///
/// The affinity mask is read back first and re-applied, which still exercises
/// the mediated syscall while avoiding EINVAL and EPERM on cpuset-restricted
/// runners. The self-directed signal handler records a plain flag that the main
/// thread polls instead of using a synchronization primitive: the handler runs
/// in the main thread at a bytecode boundary, so signalling an `Event` whose
/// lock that same thread is holding would deadlock.
fn compat_script() -> &'static str {
    r#"
import ctypes, os, resource, signal, sys, threading, time

failures = []

def report(name, error=None):
    if error is None:
        print(f"{name}=ok", flush=True)
        return
    print(f"{name}=fail:{error}", flush=True)
    failures.append(name)

def affinity_probe():
    tid = threading.get_native_id()
    try:
        os.sched_setaffinity(tid, os.sched_getaffinity(0))
        report("affinity")
    except OSError as error:
        report("affinity", error)

thread = threading.Thread(target=affinity_probe)
thread.start()
thread.join()

received = False

def on_sigusr1(_signo, _frame):
    global received
    received = True

signal.signal(signal.SIGUSR1, on_sigusr1)
try:
    os.kill(os.getpid(), signal.SIGUSR1)
    report("signal")
except OSError as error:
    report("signal", error)
deadline = time.monotonic() + 10
while not received and time.monotonic() < deadline:
    time.sleep(0.01)
if received:
    report("handler")
else:
    report("handler", "timed out waiting for the handler")

try:
    os.nice(1)
    report("nice")
except OSError as error:
    report("nice", error)

class Rlimit(ctypes.Structure):
    _fields_ = [("current", ctypes.c_ulonglong), ("maximum", ctypes.c_ulonglong)]

libc = ctypes.CDLL(None, use_errno=True)
prlimit64 = getattr(libc, "prlimit64", None)
limits = Rlimit()
if prlimit64 is None:
    report("prlimit64", "libc does not export prlimit64")
elif prlimit64(0, resource.RLIMIT_CORE, None, ctypes.byref(limits)) != 0:
    report("prlimit64", os.strerror(ctypes.get_errno()))
elif prlimit64(0, resource.RLIMIT_CORE, ctypes.byref(limits), None) != 0:
    report("prlimit64", os.strerror(ctypes.get_errno()))
else:
    report("prlimit64")

print("sandbox_compat_signals_sched=" + ("ok" if not failures else "fail"), flush=True)
sys.exit(0 if not failures else 1)
"#
}

#[tokio::test]
async fn sandbox_allows_own_group_scheduling_priority_and_limits() {
    let mut sandbox = SandboxGuard::create(&["--", "python3", "-c", compat_script()])
        .await
        .expect("sandbox create");

    assert!(
        sandbox.create_output.contains(SUCCESS_MARKER),
        "expected own-group scheduling, signal, and limit probes to pass:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
}
