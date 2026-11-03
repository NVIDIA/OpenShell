// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end compatibility for scheduling, priority, resource-limit, and
//! signal calls inside a sandbox.
//!
//! The static child filter used to deny these syscalls whatever their target,
//! so `pthread_setaffinity_np`, `taskset -p`, `prlimit(getpid())`, and `nice`
//! failed with EPERM. The broker now mediates them: the caller's own thread
//! group is allowed and every other target stays denied.

#![cfg(feature = "e2e")]

use openshell_e2e::harness::sandbox::SandboxGuard;

const SUCCESS_MARKER: &str = "sandbox_compat_signals_sched=ok";

/// Exercise each mediated syscall from inside the workload.
///
/// Own-group calls must succeed. Calls that name a target re-apply an affinity
/// mask or nice value read back first, which still exercises the mediated
/// syscall while avoiding EINVAL and EPERM on cpuset-restricted runners. For
/// the same reason every denied call would succeed natively: it re-applies
/// current settings to a same-UID process, so only the sandbox can refuse it,
/// and it must do so with EPERM. `os.nice` targets pid 0, the path that never
/// leaves the kernel.
///
/// The signal handler records a plain counter that the main thread polls
/// instead of using a synchronization primitive: the handler runs in the main
/// thread at a bytecode boundary, so signalling an `Event` whose lock that same
/// thread is holding would deadlock.
///
/// The queued signal goes to another process, the only path the broker
/// emulates, and its payload carries a different `si_signo` than the syscall
/// argument, which native `rt_sigqueueinfo` overwrites.
fn compat_script() -> &'static str {
    r#"
import ctypes, errno, os, platform, resource, signal, struct, subprocess, sys, threading, time

failures = []
libc = ctypes.CDLL(None, use_errno=True)

def report(name, error=None):
    if error is None:
        print(f"{name}=ok", flush=True)
        return
    print(f"{name}=fail:{error}", flush=True)
    failures.append(name)

def expect_denied(name, call):
    try:
        call()
        report(name, "call was not denied")
    except OSError as error:
        report(name, None if error.errno == errno.EPERM else error)

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

received = 0

def on_sigusr1(_signo, _frame):
    global received
    received += 1

def signal_probe(name, target):
    seen = received
    try:
        os.kill(target, signal.SIGUSR1)
    except OSError as error:
        report(name, error)
        return
    deadline = time.monotonic() + 10
    while received == seen and time.monotonic() < deadline:
        time.sleep(0.01)
    report(name, None if received > seen else "timed out waiting for the handler")

signal.signal(signal.SIGUSR1, on_sigusr1)
signal_probe("signal", os.getpid())

# kill() resolves a sibling thread's TID to this process, so it is self-directed too.
release = threading.Event()
sibling = threading.Thread(target=release.wait)
sibling.start()
signal_probe("sibling_signal", sibling.native_id)
release.set()
sibling.join()

mask = os.sched_getaffinity(0)
bystander = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
expect_denied("foreign_affinity", lambda: os.sched_setaffinity(bystander.pid, mask))
expect_denied(
    "foreign_nice",
    lambda: os.setpriority(
        os.PRIO_PROCESS, bystander.pid, os.getpriority(os.PRIO_PROCESS, bystander.pid)
    ),
)
bystander.kill()
bystander.wait()
expect_denied("parent_affinity", lambda: os.sched_setaffinity(os.getppid(), mask))

queue_child = "\n".join([
    "import signal, sys",
    "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})",
    "print('ready', flush=True)",
    "info = signal.sigtimedwait({signal.SIGUSR2}, 10)",
    "queued = info is not None and info.si_signo == signal.SIGUSR2 and info.si_code == -1",
    "sys.exit(0 if queued else 3)",
])
rt_sigqueueinfo = {"x86_64": 129, "aarch64": 138}.get(platform.machine())
if rt_sigqueueinfo is None:
    report("queued_signal", "no rt_sigqueueinfo number for " + platform.machine())
else:
    child = subprocess.Popen([sys.executable, "-c", queue_child], stdout=subprocess.PIPE, text=True)
    child.stdout.readline()
    # si_signo is SIGUSR1 on purpose; si_code -1 is SI_QUEUE.
    info = ctypes.create_string_buffer(struct.pack("iii", signal.SIGUSR1, 0, -1), 128)
    queued = libc.syscall(
        ctypes.c_long(rt_sigqueueinfo),
        ctypes.c_long(child.pid),
        ctypes.c_long(signal.SIGUSR2),
        info,
    )
    if queued != 0:
        report("queued_signal", os.strerror(ctypes.get_errno()))
        child.kill()
        child.wait()
    else:
        try:
            status = child.wait(timeout=15)
            report("queued_signal", None if status == 0 else f"receiver exited {status}")
        except subprocess.TimeoutExpired:
            report("queued_signal", "receiver timed out")
            child.kill()
            child.wait()

try:
    own = os.getpid()
    os.setpriority(os.PRIO_PROCESS, own, os.getpriority(os.PRIO_PROCESS, own))
    report("own_nice")
except OSError as error:
    report("own_nice", error)

try:
    os.nice(1)
    report("nice")
except OSError as error:
    report("nice", error)

class Rlimit(ctypes.Structure):
    _fields_ = [("current", ctypes.c_ulonglong), ("maximum", ctypes.c_ulonglong)]

prlimit64 = getattr(libc, "prlimit64", None)
limits = Rlimit()
if prlimit64 is None:
    report("prlimit64", "libc does not export prlimit64")
elif prlimit64(os.getpid(), resource.RLIMIT_CORE, None, ctypes.byref(limits)) != 0:
    report("prlimit64", os.strerror(ctypes.get_errno()))
elif prlimit64(os.getpid(), resource.RLIMIT_CORE, ctypes.byref(limits), None) != 0:
    report("prlimit64", os.strerror(ctypes.get_errno()))
else:
    report("prlimit64")

print("sandbox_compat_signals_sched=" + ("ok" if not failures else "fail"), flush=True)
sys.exit(0 if not failures else 1)
"#
}

#[tokio::test]
async fn sandbox_allows_own_group_and_denies_foreign_scheduling_and_signals() {
    let mut sandbox = SandboxGuard::create(&["--", "python3", "-c", compat_script()])
        .await
        .expect("sandbox create");

    assert!(
        sandbox.create_output.contains(SUCCESS_MARKER),
        "expected own-group probes to pass and foreign-target probes to be denied:\n{}",
        sandbox.create_output
    );

    sandbox.cleanup().await;
}
