# Supervisor Helpers

Supervisor helpers are privileged processes the sandbox supervisor launches
before the workload. They run in the supervisor's own execution context —
without the per-workload seccomp filter, `PR_SET_NO_NEW_PRIVS`, or Landlock —
with operator-declared ambient capabilities. The workload itself is sandboxed
exactly as before.

This page documents the shipped v0 primitive. A broader design with Landlock
integration, workload rendezvous, lifecycle semantics, and OCSF stdio is
tracked in `architecture/plans/supervisor-helpers.md`.

## Motivation

The supervisor already runs as pid 1 of the sandbox pod with a full permitted
capability set and `NoNewPrivs=0`. Some sandbox deployments need a small,
audited daemon running alongside the workload that holds capabilities the
workload must not — a capability broker, a privileged IPC bridge, or a
pre-seccomp helper. Before this feature, the only options were:

- **File capabilities on a helper binary.** Dead on arrival: workloads are
  spawned with `NoNewPrivs=1`, which causes the kernel to drop file caps at
  `execve`. Even if a helper is launched from an unrelated path, it's hard
  to keep it out of the workload's privilege-drop envelope.
- **Hardcoded special cases in the supervisor.** The DNS proxy at pid ~618
  already runs this way — spawned by the supervisor before seccomp applies —
  but it's baked into the supervisor binary. There's no way for a deployment
  to register its own helper without patching the supervisor.

Supervisor helpers turn the DNS-proxy-shaped pattern into a public, declarative
API: one JSON config, any number of operator-audited daemons.

## Surface

One new flag on `openshell-sandbox`:

```
--helpers-config <path>    [env: OPENSHELL_HELPERS_CONFIG]
```

When absent, behavior is unchanged from previous versions. When present, the
supervisor loads the JSON file, validates it, and spawns every listed helper
before starting the workload.

### Config schema

```json
{
  "helpers": [
    {
      "name": "example-broker",
      "command": ["/opt/example/bin/broker", "--socket", "/var/run/example.sock"],
      "env": {
        "RUST_LOG": "info"
      },
      "ambient_caps": ["CAP_SETUID", "CAP_SETGID", "CAP_NET_ADMIN"]
    }
  ]
}
```

| Field | Required | Meaning |
|---|---|---|
| `name` | yes | Human-readable name used in logs and OCSF events. Must be unique. |
| `command` | yes | Full argv. `command[0]` must be an absolute path — the supervisor does not consult `$PATH`. |
| `env` | no | Environment variables merged on top of the supervisor's environment after `OPENSHELL_SSH_HANDSHAKE_SECRET` is scrubbed. |
| `ambient_caps` | no | Capabilities raised into the helper's ambient set before `execve`. Names accept `CAP_FOO` or `FOO`, case-insensitive. |

Validation rejects: empty `name`, duplicate names, empty `command`, non-absolute
`command[0]`, unknown capability names.

## Runtime semantics

For each helper in declaration order:

1. The supervisor forks.
2. In the child's `pre_exec`, for each declared capability, the supervisor
   calls `capset(2)` to add it to the inheritable set, then
   `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)`. After `execve`
   the ambient set becomes part of the helper's permitted and effective sets.
3. The child `execve`s `command[0]` with the declared argv and merged env.
4. The supervisor emits an OCSF `AppLifecycle` event with `activity=Start`.

Helpers do **not** get:

- the per-workload seccomp filter (from `sandbox::linux::seccomp::apply`),
- `PR_SET_NO_NEW_PRIVS`,
- Landlock (from `sandbox::linux::landlock::apply`),
- `drop_privileges` (the helper keeps the supervisor's uid — typically 0).

This is intentional. A helper's containment is bounded by the pod's
securityContext (bounding set and capabilities granted to the supervisor) and
by whatever restrictions the helper binary applies to itself. The operator
vouches for the helper binary shipped in the image and for the capabilities
declared here.

### Interaction with the supervisor seccomp prelude

The supervisor installs its own seccomp prelude mid-startup via
`apply_supervisor_startup_hardening` (introduced in #891). Helpers are
spawned *before* that prelude is applied, so helpers themselves are not
subject to it. The prelude only blocks long-lived supervisor escape
primitives — `mount`, the new mount API (`fsopen`/`fsconfig`/`fsmount`/
`fspick`/`move_mount`/`open_tree`), `umount2`, `pivot_root`, `bpf`,
`perf_event_open`, `userfaultfd`, and module/kexec loaders. Notably it does
not touch `capset`, `prctl`, `clone`, or `execve`, so the helper spawn path
(`capset` for the inheritable set plus `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ...)`
in the pre-exec child, then `execve`) is unaffected.

Helpers are spawned with `kill_on_drop(true)`. When the supervisor exits
(for any reason), tokio sends `SIGKILL` to the helper. No structured
shutdown in v0.

## Security model

The trust boundary is **the supervisor**, and the same trust boundary that
already exists today. A compromised supervisor was always catastrophic;
giving it the ability to fork a declared set of other root-capable processes
from a config file does not expand that blast radius.

What *does* change:

- The operator is now responsible for auditing each helper binary and each
  capability it receives. The `--helpers-config` path and its contents are
  part of the image's attack surface.
- Helpers and the workload share the pod's filesystem. In v0 there is no
  Landlock isolation between them — any cap-less helper could read
  workload-writable paths, and vice versa. Deployments that need file-level
  isolation should either wait for the RFC's Landlock support or implement
  it inside the helper binary.
- `ambient_caps` is clamped to the supervisor's permitted set, which in turn
  is clamped to the pod's bounding set. Requesting a cap the bounding set
  doesn't include fails at `capset(2)` with `EPERM` and the supervisor exits
  before the workload starts.

The SSH handshake secret (`OPENSHELL_SSH_HANDSHAKE_SECRET`) is scrubbed from
the helper's inherited environment, matching what the workload sees.

## Interactions

- **DNS proxy.** The DNS proxy's existing hardcoded path is unchanged.
  Nothing in this feature removes or modifies it. A future follow-up may
  migrate it onto supervisor helpers.
- **Policy.** Helpers are outside the policy surface: OPA rules, network
  policy, and Landlock config apply to the workload, not to helpers. A
  helper talking through the policy-enforced proxy must do so the same way
  any process does — by speaking HTTP to the proxy.
- **OCSF.** Helper start emits `AppLifecycleBuilder { activity: Start,
  severity: Informational, status: Success }`. Structured helper stdout/stderr
  is deferred; plain tracing is used.

## What the v0 does *not* include

These are explicitly out of scope for this landing and are tracked in
`architecture/plans/supervisor-helpers.md`:

- Per-helper Landlock (`readOnly`, `readWrite`, `readExec`).
- A `shareWithWorkload` rendezvous field that lets the workload `connect()`
  to a helper-owned socket without gaining `unlink()`/replace rights.
- Structured restart policy (`Never`, `OnFailure`, `Always`).
- `readinessFd` convention (fd 3 write-one-byte) for "helper is live" gating.
- Helper stdio routing into the OCSF JSONL log stream.
- Per-helper cgroup resource limits.
- `runAsUser`/`runAsGroup` with the `PR_SET_KEEPCAPS` + `setuid` + ambient
  dance to let helpers drop to non-root while retaining requested caps.

Each of those is additive on the existing schema — no breaking change to
the v0 config format.

## Implementation

| Path | Role |
|---|---|
| `crates/openshell-sandbox/src/helpers.rs` | `HelpersConfig`, `HelperSpec`, `spawn_helpers`, cap-raising `pre_exec` hook. |
| `crates/openshell-sandbox/src/lib.rs` | `run_sandbox` takes `helpers_config: Option<String>` and calls `spawn_helpers` after OCSF init, before policy load. |
| `crates/openshell-sandbox/src/main.rs` | `--helpers-config` clap flag bound to `OPENSHELL_HELPERS_CONFIG`. |

Dependencies: [`caps`](https://crates.io/crates/caps) for the capability
set manipulation — thin wrapper over `capset(2)` + `PR_CAP_AMBIENT`. `serde`
is already a workspace dependency.
