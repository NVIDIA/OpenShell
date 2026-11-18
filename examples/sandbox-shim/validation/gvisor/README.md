# Stock gVisor ptrace mediation: validation

This directory qualifies native socket mediation on stock gVisor without
patches. The current recommendation is
[Candidate D](#current-recommendation-candidate-d). Earlier rounds remain below as
evidence:

- the [first proposal and its NO-GO](#first-proposal-verdict-no-go-on-arm64)
- the [follow-up spike](#follow-up-spike-alternatives-to-reading-arg0) on
  Candidates A and C

The probes are small C programs. They test mechanisms only. No production
mediator, supervisor policy path, or shim integration was built.

## Current recommendation: Candidate D

**Spike GO: implement a native gVisor backend that uses ptrace plus a raw
SecCheck adapter in the supervisor.** This is a GO to build the backend. It
is not a claim of production parity. Every decisive gate below passed on stock
runsc release-20261109.0 (arm64, systrap). It needs no Sentry or kernel patch.
The shim stays inside the sandbox, and the supervisor and gateway stay
outside.

### Mechanism

1. The trusted tracer (the shim) seizes the workload. A seccomp filter
   returns `SECCOMP_RET_TRACE` for `connect`. Workload `ERRNO`, `TRAP`, and
   `KILL` filters outrank `TRACE`, so they decide first.
2. At the TRACE stop, x0 reads -38 on arm64 gVisor. The tracer does not run
   `connect`. It first opens a `PIDFD_THREAD` pidfd for the task. It then
   changes x8 to `gettid` (178) and x4/x5 to a fresh 128-bit `getrandom`
   nonce, leaving x0 and every other argument untouched.
3. gVisor runs the substituted call with the hidden `OrigR0` as `args[0]`.
   `executeSyscall` emits the raw `syscall/sysno/178/enter` point *before*
   `gettid` runs
   ([task_syscall.go#L84-L111](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/task_syscall.go#L84-L111)).
   The point carries `Arg1` (the original fd), `Arg5`/`Arg6` (the nonce),
   and the root-namespace `thread_id`
   ([seccheck.go#L64](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/seccheck.go#L64)).
4. The tracer requires exactly a `gettid` entry stop and then a `gettid` exit
   stop. Any other stop kills the tracee. Restoring `connect` at any stop
   before the exit stop would run the original call, which `unsafe_entry_restore`
   reproduces.
5. With the tracee held at the exit stop, the tracer asks the host collector
   for the unused event that matches `{tid, nonce}`. Only a FOUND reply to
   that exact query, before the deadline, yields an fd. The tracer then uses
   `pidfd_getfd` on the held pidfd and applies policy (deny or relay).
   Finally it restores all original registers with the result and resumes.
   With no match, the original `connect` has not run, so the caller is
   denied.

The collector (`host/collector.c`) models an adapter inside the existing
supervisor:

- runsc connects the remote sink to a helper-private `SOCK_SEQPACKET` path
  during setup
  ([remote.go#L80-L133](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/seccheck/sinks/remote/remote.go#L80-L133)).
  That one connection is the event source for this sandbox generation.
- The collector reaches the tracer through a guest listener created with
  `--host-uds=create`. The tracer accepts one peer, then removes the
  listener and its path before any workload exists.
- The workload never holds the channel or the sink. The collector never
  takes an fd or claim from the workload.

### Results (`probes/rawevent.c`, `run.py raw`)

| Gate | gVisor |
|---|---|
| Readiness: the tracer's own `gettid(0x5eed, nonce)` round-trips Sentry → collector → tracer | PASS |
| fd 77: ptrace x0 = -38, raw `Arg1` = 77; caller gets `EACCES`, socket unconnected, pending SIGUSR1 delivered once | PASS, PASS |
| fd 70000: raw `Arg1` = 70000 (no 16-bit limit) | PASS, PASS |
| Decoy socket at fd 78 and alias at fd 79 in single-connect variants; matched fd exact | PASS |
| Relay: 50 bidirectional connects through the event's fd | PASS |
| Relay: peer EOF on all 50 closes; no fd leak on either side | PASS |
| Workload `ERRNO(EPERM)` and `ERRNO(ENOSYS)` on `connect` win; no stop or substitution | PASS, PASS |
| Workload stacked `TRACE \| 12`: data ignored | PASS, PASS |
| 100 explicit workload `gettid` calls with chosen x4/x5, plus ambient calls from the same tid, never match | PASS (3 checks) |
| Matching event dropped by the collector: denied, socket unconnected | PASS |
| Reply after the deadline: denied; stale reply discarded by sequence number; next call matched | PASS |
| Replayed query for a used `{tid, nonce}`: nothing found | PASS |
| Nonce off by one bit: nothing found, denied | PASS |
| After `execve` (new image) | PASS, PASS |
| Child in a nested PID namespace (Sentry root tid = tracer `waitpid` tid) | PASS, PASS |
| uid 10001, non-dumpable | PASS, PASS |
| No freeze: sibling private-memory writer plus 12,800 accepted classic AIO requests, 200/200 exact (completion overlap not measured) | PASS |
| Fault hook at the exit stop: tracee killed, loopback listener accepted 0 | PASS |
| Real `PTRACE_INTERRUPT` between entry and exit: exit stop still arrives, denied, accepted 0 | PASS |
| **Hazard reproduced:** restoring `connect` at the entry stop runs it (listener accepted 1) | PASS |
| Collector parser: valid packet, plus 9 malformed or foreign headers and protobufs rejected | 10/0/0 |

Counts: `rawevent` 28/0/0 and collector selftest 10/0/0 under `run.py raw`.
In `linux` and `direct` modes, `rawevent` is SKIP because no SecCheck sink is
configured there.

The independent final rerun is recorded in
`.cache/gvisor-spike/logs/final-review/`. Its writer fixture requires 64
accepted AIO requests per iteration and reports 12,800 accepted requests.

D removes C's scratch and freeze requirement for descriptor recovery: its
descriptor metadata comes from Sentry rather than workload-writable memory.
This does not qualify every AIO schedule. A production mediator must still
copy and validate application buffers, such as destination addresses, and
use the same captured bytes for policy and the actual operation.

### Production gates before parity

1. **Transport authentication and generation.**
   - What the spike shows: the event source is the single connection runsc
     makes during setup, and the guest channel accepts a single peer.
   - Still needed: bind the adapter to the supervisor's existing shim
     channel; per-sandbox generation and container id checks; and a policy
     for collector restarts. A tracer nonce authenticates nothing outside
     this private channel.
   - The Sentry only warns on a bad trace session
     ([loader.go#L1017-L1021](https://github.com/google/gvisor/blob/release-20261109.0/runsc/boot/loader.go#L1017-L1021)), so keep
     the readiness round trip as a hard startup gate.
2. **Event loss.**
   - The sink drops events when its socket stays full
     ([remote.go#L209-L240](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/seccheck/sinks/remote/remote.go#L209-L240)).
     A drop is an availability failure only, so it must surface as a deny
     and as an alert.
   - Still needed: sizing and load tests under a hostile `gettid` flood.
3. **Task lifecycle.**
   - `start_ns` is reported but not validated.
   - Unexpected stops currently kill the tracee. Production must instead
     queue and preserve signals and group stops, and handle sibling exec,
     exit, and kill mid-transaction.
   - Exec, tid reuse, and `PIDFD_THREAD` races need full qualification.
4. **Syscall surface.** Only `connect` was built. Still needed:
   - the complete existing broker syscall set: `socket`, `bind`, `listen`,
     `sendto`, `sendmsg`, `sendmmsg`, and `setsockopt`
   - socket creation and registration without seccomp `ADDFD`
   - UDP and DNS
   - allow-and-run versus relay semantics
   - blocking and non-blocking connect, and `EINTR` and restart
   - workload `TRACE` filters without a tracer (Linux returns `ENOSYS`)
5. **Workload constraints.** Workload debuggers and `strace` cannot attach
   while the shim traces every task. This must be documented or emulated.
6. **End to end.** Still needed:
   - per-netns relay for Docker and Bubblewrap
   - binary identity
   - supervisor policy and OCSF integration
   - conformance against Linux
   - performance (each mediated call adds two stops and a host round trip)
   - x86_64, where the raw sysno and registers differ
   - the production crypto path through `openshell-crypto` for nonces

## First proposal verdict: NO-GO on arm64

**NO-GO for the proposed unrestricted ptrace/`SECCOMP_RET_TRACE` backend on
arm64 stock gVisor release-20261109.0.** The current gVisor shim keeps its
CONNECT proxy. Nothing in this directory changes production crates or the
example's runtime behavior.

Two blockers, both reproduced live in stock runsc:

1. **The tracer cannot read arg0** (the fd for `connect`, `sendto`, `bind`,
   and the others, and the domain for `socket`). At the seccomp stop,
   `NT_PRSTATUS` x0 is `-38`. Real fd 77 is not exposed through
   `PTRACE_PEEKUSER` (EIO), `/proc/<tid>/syscall` (ENOENT), or
   `NT_ARM_SYSTEM_CALL` (refused). In the pinned source, `doSyscall` saves x0
   into the internal `OrigR0` and then sets x0 = `-ENOSYS` before checking
   seccomp. Syscall arguments are taken from `OrigR0`, which no ptrace
   interface exposes. See `pkg/sentry/kernel/task_syscall.go` `doSyscall`,
   `pkg/sentry/arch/syscalls_arm64.go` `SyscallSaveOrig` and `SyscallArgs`, and
   `pkg/sentry/arch/arch_aarch64.go` `PtraceGetRegSet`.
2. **The tested event-data workaround is attacker-controlled.** A filter can
   copy arg0 into `SECCOMP_RET_DATA` (`TRACE | fd`, with fd < 65536 enforced in
   BPF), and that works (`eventmsg=77`). But the workload can stack its own
   filter returning `TRACE | 12`. The newest filter wins a tie between equal
   actions (`evaluateSyscallFilters` in `kernel/seccomp.go`), so the tracer
   sees `eventmsg=12` for a connect on fd 77. Host Linux behaves the same.
   Refusing all seccomp filter installs would also reject the normal filters
   that Docker and runc install.

A design that avoids both would need a decision and its own validation. For
example, the tracer could gate every `seccomp` and `PR_SET_SECCOMP` install and
reject any program that can return `SECCOMP_RET_TRACE`, and accept the
fd < 65536 limit. Such validation would also need to prevent the workload
from changing the filter between validation and installation. Nothing here
implements or tests that. x86_64 exposes arguments in separate registers,
but it was **not tested**. The follow-up spike below tests alternatives.

## First proposal gate results

Run on aarch64 (kernel 6.17.0-1029-nvidia) with gcc 13.3.0, comparing:

- **Linux:** the host kernel, with the invoking user as tracer.
- **gVisor:** stock runsc release-20261109.0 systrap, with sandbox root as
  tracer.

| Gate | Check | Linux | gVisor |
|---|---|---|---|
| 1 | TRACE stop fires for the traced syscall | PASS | PASS |
| 1 | TRACE with no tracer returns `ENOSYS` (fail closed) | PASS | PASS |
| 1 | **arg0 readable at the seccomp stop** | PASS | **FAIL** (x0 = -38) |
| 1 | arg0 via `SECCOMP_RET_DATA` with a benign stacked filter | PASS | PASS |
| 1 | **`SECCOMP_RET_DATA` survives a hostile stacked TRACE filter** | **FAIL** | **FAIL** (12, not 77) |
| 1 | Skip: nr = -1 + result + `PTRACE_CONT`; tracee sees `EACCES`, socket untouched | PASS¹ | PASS |
| 1 | Skip + `PTRACE_SYSCALL`: exactly one following stop (exit) | PASS | PASS² |
| 1 | Blocking/nonblocking connect relay, signals, `EINTR`/restart, exit while stopped | UNTESTED | UNTESTED |
| 2 | Thread, fork, vfork+exec, non-leader exec, user+PID namespace child are stopped and denied | PASS | PASS |
| 2 | Exec identity: tracer reads `exe=/usr/bin/bash` after exec | PASS | PASS |
| 2 | Non-leader exec: `PTRACE_EVENT_EXEC` on the leader tid, former tid in eventmsg | PASS | PASS |
| 2 | **Fork/clone eventmsg tid is in the tracer's PID namespace** | PASS | **FAIL**³ |
| 2 | `/proc/<tid>/status` `NSpid` maps nested pids | PASS | SKIP (no `NSpid`) |
| 2 | Tracer `SIGKILL` kills all 7 live descendants (idle, thread, daemon, nested init and child) | PASS | PASS |
| 2 | No process survives in the sandbox after tracer `SIGKILL` | n/a | PASS |
| 3 | `pidfd_open(non-leader, 0)` refused (ENOENT) | PASS | PASS |
| 3 | `PIDFD_THREAD` reaches a thread's private fd table (`unshare(CLONE_FILES)`) | PASS | PASS |
| 3 | Leader pidfd returns a *different* object for that fd number (hazard confirmed) | PASS | PASS |
| 3 | `/proc/<pid>/task/<tid>/fd/N` names the thread's object | PASS | PASS |
| 3 | dup and `SCM_RIGHTS` aliases share inode; accepted socket differs from listener | PASS | PASS |
| 3 | `O_PATH` pin from the tracer's own `pidfd_getfd` dup keeps inode after close | PASS | PASS |
| 3 | `O_PATH` pin does not delay peer EOF or hold a listener port | PASS | PASS |
| 3 | Control: a retained live dup delays EOF and holds the port (`EADDRINUSE`) | PASS | PASS |
| 3 | 20000 socket create/close cycles: no inode reuse | PASS | PASS (strictly increasing) |
| 3 | Concurrent close/dup2 race, dup kept across exec, fd/registry exhaustion, cross-netns inode uniqueness | UNTESTED | UNTESTED |
| 4 | Benign Docker-style filter stacks; trusted TRACE still fires | PASS | PASS |
| 4 | uid 10001 non-dumpable workload cannot `kill` or `PTRACE_ATTACH` the root tracer | SKIP | PASS |
| 4 | Root tracer can seize, read `exe`, and `pidfd_getfd` a non-dumpable uid 10001 workload | SKIP | PASS |
| 4 | Workload denied `ptrace`, `io_uring`, BPF, and raw/packet sockets; namespace-root workload vs tracer | UNTESTED | UNTESTED |
| 5 | Nested Docker daemon, pull interception, per-netns relay through a `setns` worker, Bubblewrap | UNTESTED | UNTESTED |
| 6 | Latency against an untraced baseline and Firecracker; DNS UDP/TCP mediation | UNTESTED | UNTESTED |
| — | Supervisor auth/policy integration and end-to-end conformance | not built | not built |

¹ Linux arm64 needs `NT_ARM_SYSTEM_CALL` to change the syscall number;
`skip_syscall` in `probes/gv.h` writes both. gVisor refuses that regset and
reads x8.

² At that exit stop, the return register is still `-38`. Return value alone
cannot tell an entry stop from an exit stop, and gVisor has no
`PTRACE_GET_SYSCALL_INFO`. A tracer must track stop phase itself.

³ A fork inside a nested PID namespace reported eventmsg = 2, the
namespace-local pid. Linux reports the tracer-namespace pid. The pinned
`kernel/ptrace.go` `ptraceClone` uses `t.tg.pidns.tids[child]`, the tracee's
namespace. If a tracer used that value, it would name an unrelated process in
its own namespace. A tracer must learn new tids from `waitpid()` instead.
The coverage probe still observed and denied each connecting task using its
`waitpid()` identity.

Counts from the final runs:

| Probe | Linux pass/fail/skip | gVisor pass/fail/skip |
|---|---|---|
| `regs` | 11/0/0 | 9/2/0 |
| `stack` | 3/1/0 | 3/1/0 |
| `tree` | 10/0/0 | 9/1/1 |
| `identity` | 12/0/0 | 12/0/0 |
| `creds` | 0/0/1 | 5/0/0 |

The untested gates were deferred because the gate-1 blockers prevent
qualification of this proposed backend for unrestricted workloads on arm64.
Relay, Docker, DNS, and performance tests using the event-data workaround
would not resolve its trust problem. This is not a proof that every possible
unpatched-gVisor design is impossible.

## Follow-up spike: alternatives to reading arg0

Candidate D, above, supersedes this section's recommendation for C. The
findings still stand: A fails, and C depends on scratch quiescence.

The follow-up spike ran on 2026-11-17 against the same runsc and a clean
rootfs. A rerun of the five probes above reproduced the counts in the table
exactly. It tested two alternatives with live probes: TRAP, and
substitution of `fstat`. A third, dup-and-close injection, was ranked
lower and not built. All runs used stock runsc with no patches.

### Decision

- **Candidate A, `SECCOMP_RET_TRAP` + SIGSYS stop: NO-GO for transparent
  seccomp semantics.** It recovers the true arg0, but TRAP outranks a
  workload's own `ERRNO` filter, and the forced SIGSYS rewrites workload
  signal state.
- **Candidate C, `fstat` substitution at the TRACE stop: selected for the
  next prototype, NOT qualified.** It recovers socket identity without
  reading arg0, keeps workload `ERRNO` filters authoritative, and ignores
  `SECCOMP_RET_DATA`. Its identity read is only authoritative while nothing
  can write the scratch memory. The probes prove that for traced sibling
  threads after an all-task freeze, and for nothing else.
- **Candidate B, dup + close injection:** not built. C reaches the same
  identity without creating a tracee fd or injecting a second syscall.
- **`PTRACE_SYSCALL` and `PTRACE_SYSEMU`:** ruled out. Live, the
  syscall-entry stop shows x0 = -38 on gVisor (`trap` probe). In source,
  `doSyscall` clobbers x0 before `doSyscallEnter` reaches
  `ptraceSyscallEnter`, which handles both modes
  ([task_syscall.go#L213-L288](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/task_syscall.go#L213-L288),
  [ptrace.go#L832-L851](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/ptrace.go#L832-L851)).
  SYSEMU was not probed live.
- **Single-step:** unavailable. `SetSingleStep` is a no-op on arm64
  ([arch_aarch64.go#L120-L135](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/arch/arch_aarch64.go#L120-L135)).

### Candidate A: TRAP (`probes/trap.c`)

The filter returns `SECCOMP_RET_TRAP` for `connect`. The TRAP path restores x0
to arg0 before it queues SIGSYS
([seccomp.go#L106-L123](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/seccomp.go#L106-L123)). The
tracer reads registers at the signal-delivery-stop, emulates the call, and
suppresses the signal.

| Check | Linux | gVisor |
|---|---|---|
| siginfo `SYS_SECCOMP`, arch, nr, `si_errno` data, `call_addr == pc` | PASS | PASS |
| x0 holds the real fd: 77 | PASS | PASS |
| x0 holds the real fd: 70000 | SKIP¹ | PASS |
| `pidfd_getfd` of the observed x0, emulate `EACCES`, suppress SIGSYS | PASS | PASS |
| Relay: tracer connects the dup to a loopback relay; data and reply cross | PASS | PASS |
| **Forgery reproduced:** workload queues `SYS_SECCOMP` SIGSYS to itself | PASS | PASS |
| Partial reject: that forgery fails x8/`call_addr` checks | PASS | PASS |
| **Workload `ERRNO(EPERM)` deny-connect filter preserved** | **FAIL** | **FAIL** |
| **SIGSYS state rewrite reproduced:** blocked mask bit cleared | PASS | PASS |
| **SIGSYS state rewrite reproduced:** `SIG_IGN` reset to `SIG_DFL` | PASS | PASS |
| No tracer: SIGSYS kills the workload (fail closed, but not `ENOSYS`) | PASS | PASS |
| `PTRACE_SYSCALL` entry stop shows arg0 | PASS | **FAIL** (x0 = -38) |

¹ The host user cannot raise `RLIMIT_NOFILE` above the hard limit.

Why A is NO-GO:

- **Precedence.** TRAP ranks above ERRNO
  ([seccomp.go#L194-L222](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/seccomp.go#L194-L222)). When a
  legitimate workload filter denies `connect` with `EPERM`, the tracer still
  gets the stop and would emulate over the deny. The probe recorded this as
  exit 61. A nested Docker or Bubblewrap seccomp profile would silently lose
  its deny.
- **Signal state.** A forced signal that is blocked or ignored resets the
  handler to `SIG_DFL` and unblocks it
  ([task_signals.go#L771-L789](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/task_signals.go#L771-L789)).
  Suppressing the signal does not undo that.
  `PTRACE_SETSIGMASK` could repair the mask
  ([ptrace.go#L1413-L1427](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/ptrace.go#L1413-L1427)),
  but no ptrace request restores a disposition.
- **Authentication.** The workload can queue a `SYS_SECCOMP` SIGSYS to itself
  with `rt_tgsigqueueinfo`. A sibling thread in the same thread group can do
  the same. Register checks rejected the simple forgery. `rt_sigreturn` can load
  attacker-chosen x8 and pc before a pending SIGSYS is delivered, and that was
  not tested. The siginfo and register checks are therefore not
  authentication.

### Candidate C: `fstat` substitution (`probes/snapshot.c`)

At the `connect` TRACE stop, the tracer changes only the syscall number to
`fstat` and x1 to a scratch address 2 KiB below the saved SP. It does not read
or write x0. gVisor runs the substituted call with the hidden `OrigR0` as arg0,
which is still the original fd
([task_syscall.go#L267-L281](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/task_syscall.go#L267-L281),
[syscalls_arm64.go#L54-L64](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/arch/syscalls_arm64.go#L54-L64)).
Under `PTRACE_SYSCALL` it then stops at the entry and the exit. Linux has
`PTRACE_GET_SYSCALL_INFO` and reports the stop type. gVisor does not, so the
probe relies on gVisor's fixed entry-then-exit order and checks x8 = `fstat`
at the entry stop. The rest of the transaction:

1. At the exit stop, with return 0, the tracer reads the 128-byte kernel
   `struct stat` and restores the saved scratch bytes. It requires
   `S_IFSOCK`.
2. It scans `/proc/<tid>/fd` and takes a `pidfd_getfd` dup of each entry
   through a `PIDFD_THREAD` pidfd. It keeps the entries whose `st_dev` and
   `st_ino` match.
3. It restores the original registers with the result and resumes. For the
   relay result, it first connects the matching dup to the relay.

The tracer never learns the fd from the workload, creates no tracee fd, and
writes no executable memory. The scratch range must lie in one `rw-p` mapping
in `/proc/<tid>/maps`. Otherwise the tracer fails closed with `EACCES`.

Each run has a decoy socket at fd 78 and an alias `dup` of the target at fd 79.

| Check | Linux | gVisor |
|---|---|---|
| fd 77: identity resolved without reading arg0, no decoy match | PASS | PASS |
| fd 77: caller sees `EACCES`, socket unconnected, pending SIGUSR1 delivered once, no fd leak | PASS | PASS |
| fd 70000: same two checks | SKIP¹ | PASS, PASS |
| Relay: 50 connects relayed through the discovered object, bidirectional | PASS | PASS |
| No leak: peer EOF on all 50 workload closes; tracee and tracer fd counts unchanged | PASS | PASS |
| Workload `ERRNO(EPERM)` on `connect` wins; no stop | PASS | PASS |
| Workload `ERRNO(ENOSYS)` on `connect` wins; no stop | PASS | PASS |
| Workload stacked `TRACE \| 12`: data ignored, identity still exact (2 checks) | PASS | PASS |
| Workload `fstat`→`ERRNO(ENOSYS)` filter: caller still denied | PASS² | PASS² |
| After `execve` (new image, new stack): both checks | PASS | PASS |
| Child in a new PID namespace (tid from `waitpid`): both checks | PASS | PASS |
| uid 10001, non-dumpable, root tracer: identity, then `EACCES` and no fd leak | SKIP¹ | PASS |
| **Scratch forgery reproduced without a freeze** (sibling thread writes decoy dev/ino) | PASS (200/200) | PASS (200/200) |
| Freeze all traced tasks (`PTRACE_INTERRUPT` + wait for each tid): no forgery | PASS (200/200 exact) | PASS (200/200 exact) |
| Freeze vs file AIO preads onto the scratch | SKIP³ | SKIP³ |

¹ Needs privileges the host run lacks.
² The two kernels differ. Linux re-runs filters after a TRACE stop, so the
substituted `fstat` returned `-ENOSYS` and the tracer failed closed. gVisor
does not re-run filters
([task_syscall.go#L267-L281](https://github.com/google/gvisor/blob/release-20261109.0/pkg/sentry/kernel/task_syscall.go#L267-L281)),
so the substitution succeeded despite the workload's `fstat` deny.
³ Not reproduced (0/200). This variant did not check AIO submission results
or establish completion overlap, so it provides no safety evidence. The
Candidate D stress test uses a separate buffer and checks all 12,800 AIO
submissions; its overlap with metadata capture is still unmeasured.

Counts: `snapshot` Linux 15/0/3, gVisor 19/0/1. `trap` Linux 11/1/1,
gVisor 14/2/0.

### What C does not yet establish

C is a viable engineering direction. It is not unrestricted mediation, and it
does not have parity with Linux seccomp. These invariants are unqualified:

- **All-writer quiescence.** A writable scratch is authoritative only while
  every possible writer is stopped. The freeze covered traced sibling threads
  only. These writers are untested:
  - other workload processes using `process_vm_writev` or `/proc/<pid>/mem`
    (gated by ptrace access mode, not by tracer status)
  - `CLONE_VM` children and vfork
  - inherited `/proc/<pid>/mem` fds
  - AIO and io_uring completions, which need no running task (io_uring is off
    unless runsc gets `--iouring`)
  - blocked readers whose buffers overlap the scratch
  - `MAP_SHARED` or file-backed memory on the stack path

  The `rw-p` check excludes shared mappings at check time only. A real design
  needs a tracer-owned or provably private region. Otherwise it must fail
  closed when it cannot pause every writer.
- **Freeze races.** Clone, fork, exec, and exit can race the freeze. A new
  child is auto-attached and starts stopped, but it was not tested under the
  freeze. Tids must come from `waitpid`, not namespace-local event data.
- **Substitution filter semantics.** On gVisor the substituted `fstat`
  bypasses workload filters. On Linux it is rechecked. Both are acceptable
  for the tracer's own lookup, but a mediator must not reuse substitution to
  run a workload-visible syscall.
- **Policy surface.** Only `connect` was probed. Untested: `sendto`,
  `sendmsg`, `bind`, `listen`, `accept`, and DNS, as well as allowing a call to
  run (as opposed to denying or relaying it), blocking connects, `EINTR`,
  and restart. Workload `TRACE` filters with no workload tracer return
  `ENOSYS` on Linux, but the tracer makes them succeed.
- **ptrace exclusivity.** Every workload task is traced, so workload
  debuggers and `strace` cannot attach. This constrains workloads and must be
  documented, or the tracer must emulate nested ptrace.
- **Scale.** Untested: performance, Docker/Bubblewrap end to end, and x86_64.

### Next step (superseded by Candidate D)

Build a C prototype in which every transaction freezes all traced tasks, and
which fails closed if a task cannot be paused or no private scratch exists.
Before any further work on it, run these falsifiers:

1. A cross-process writer using `process_vm_writev`.
2. A delayed async writer: AIO on a pipe or socket, and io_uring with
   `--iouring`.
3. A `CLONE_VM` child.
4. Clone and exec racing the freeze.
5. Allow-and-run semantics for `sendmsg` and UDP DNS.

If no fully private scratch can be guaranteed, the fallback is the existing
CONNECT proxy.

## Related evidence outside this directory

These `/tmp` paths were lost before the follow-up spike and no longer exist.
The initial mechanism study also ran these through the current shim harness
(nonprivileged gVisor, workload uid 10001 as tracer):

- `/tmp/openshell-gvisor-network-study/ptrace-probe.log` and
  `relay-probe.log`: TRACE stop, `pidfd_getfd`, and a relay redirect. The fd
  was passed over a pipe, so these logs do not show fd recovery from an
  unmodified call.
- `/tmp/openshell-gvisor-network-study/lifetime-gvisor.log` and
  `lifetime-linux.log`: the same `O_PATH` versus live-dup lifetime behavior
  that `identity` checks here, in Python and in the workload's own process.
- `/tmp/shim-gvisor-validation-logs/parent-direct-poison.log`: an independent
  reproduction of the forged `SECCOMP_RET_DATA` result.

## Reproduce

Inputs for the follow-up spike, under `.cache/gvisor-spike/runtime/` at the
repository root (untracked):

- `runsc`: release-20261109.0, extracted from the official release tarball,
  whose published SHA-512 was verified
  (`sha256 5b09965feae8a37465e510986b6c447a36396393f921f395eaf0b893f3c7cd18`)
- `rootfs/`: a clean export of `buildpack-deps:26.04`, bind-mounted read-only
- `source/`: pristine source of tag release-20261109.0, used for the citations;
  links point at the same tag upstream
- helper image `buildpack-deps:26.04`
  (`sha256:cbb13fc2b7fd056bb737e71ba5f8e927e096a987abe10fbef1e1f025ced1f4c9`)

The first proposal's runs used the same runsc and a dev rootfs under `/tmp`
that has since been lost.

```shell
cd examples/sandbox-shim/validation/gvisor
uv run --no-project run.py linux            # host Linux reference
uv run --no-project run.py direct           # stock runsc, root tracer
uv run --no-project run.py direct regs      # one probe
```

The follow-up spike and Candidate D used absolute paths:

```shell
R=$PWD/../../../../.cache/gvisor-spike
export SHIM_RUNSC_DIR=$R/runtime SHIM_ROOTFS_DIR=$R/runtime/rootfs GV_LOG_DIR=$R/logs/final-d
uv run --no-project run.py linux
uv run --no-project run.py direct
uv run --no-project run.py raw      # Candidate D: collector selftest + rawevent
```

`raw` mode runs `host/collector.c` and runsc in one labeled `--network none`
helper:

- runsc gets `--host-uds=create` and `--pod-init-config`, with session
  `Default`, point `syscall/sysno/178/enter`, context fields `thread_id` and
  `task_start_time`, and a `remote` sink with `ignore_setup_error` unset.
- The guest channel is helper-private `/bundle-chan`, bound at `/srv`.

The rootfs is read-only and the runner never modifies it. Bind targets
(`/mnt`, and `/srv` for `raw`) must already exist, and the runner exits with
an error if they do not.

Environment overrides: `SHIM_RUNSC_DIR`, `SHIM_ROOTFS_DIR`,
`SHIM_HELPER_IMAGE`, and `GV_LOG_DIR` (default
`/tmp/shim-gvisor-validation-logs`).

Each probe is compiled statically with
`-std=gnu11 -O2 -g -pthread -Wall -Wextra -Werror -Wshadow -Wformat=2`.

`direct` runs each probe as PID 1 of its own runsc sandbox:

- runsc runs with `--network=none --platform=systrap --overlay2=root:memory
  --in-sandbox-cgroup=v2`.
- runsc runs inside a labeled `--network none` Docker helper with the same
  capabilities as the shim's gVisor guest (`src/guest.rs`).
- The rootfs and probe binaries are read-only binds. No control socket,
  credential, or launch file is mounted.
- Each helper is removed after its probe.

A probe prints `RESULT <check> PASS|FAIL|SKIP` lines. The runner exits
nonzero if any probe fails or times out. With the results above, both modes
exit 1 by design: the `stack` and `trap` FAILs are findings. `raw` exits 0.

## Files

- `run.py`: builds the probes, then runs them on host Linux or in stock
  runsc.
- `probes/gv.h`: register access, skip, the trace filter, and result output.
- `probes/tracer.h`: a minimal multi-task trace loop. It is not a mediator.
- `probes/regs.c`: arg0 visibility, `SECCOMP_RET_DATA`, and both skip
  strategies.
- `probes/stack.c`: a benign stacked filter and a forged `TRACE` data filter.
- `probes/tree.c`: fail-closed behavior, descendant coverage, exec identity,
  event tids, and `EXITKILL`.
- `probes/identity.c`: `PIDFD_THREAD`, aliases, `O_PATH` pin lifetime, and
  inode churn.
- `probes/creds.c`: a root tracer over a uid 10001 non-dumpable workload.
- `probes/trap.c`: Candidate A: TRAP arg0 recovery, relay, forgery, filter
  precedence, SIGSYS state, and the `PTRACE_SYSCALL` entry stop.
- `probes/snapshot.c`: Candidate C: `fstat` substitution, identity scan, relay,
  filter interaction, exec, PID namespace, uid 10001, and scratch races with
  and without a freeze.
- `probes/rawevent.c`: Candidate D: `gettid` substitution tracer, readiness,
  identity, relay, filters, event faults, lifecycle variants, writers, and
  fault injection.
- `probes/rawproto.h`: the spike's tracer and collector query and reply
  structs.
- `host/collector.c`: a spike model of the supervisor's SecCheck adapter: sink
  handshake, bounded parsing, `{tid, nonce}` matching, and test hooks.
