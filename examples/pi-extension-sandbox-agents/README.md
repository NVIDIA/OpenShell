<!-- SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Pi extension: OpenShell sandboxes as sub-agents

A [Pi coding agent](https://pi.dev/) extension that wraps the `@openshell/sdk`
TypeScript binding so a controlling Pi agent can spin up fresh OpenShell
sandboxes, dispatch tasks into them, and tear them down — turning each
sandbox into a disposable sub-agent.

## What this demo shows

The Pi agent stays in your terminal. Long-running, isolated, or
untrusted-input work is dispatched to OpenShell sandboxes, which give you:

- A fresh filesystem and process namespace per task
- Policy-enforced egress (no exfil from a runaway tool)
- Credential placeholders instead of real tokens for upstream calls
- Logs you can audit after the fact

The extension exposes five tools to the Pi model:

| Tool | Purpose |
| --- | --- |
| `openshell_run_task` | One-shot: create → exec → return → delete. The killer feature. |
| `openshell_spawn_sandbox` | Create a long-lived sandbox and wait for ready. |
| `openshell_exec` | Run a follow-up command inside an existing sandbox. |
| `openshell_list_sandboxes` | Observe active sub-agents, optionally label-filtered. |
| `openshell_destroy_sandbox` | Release a long-lived sandbox. |

And one slash command:

| Command | Purpose |
| --- | --- |
| `/openshell-health` | Probe the gateway and print its status. |

## How sub-agent semantics work

`openshell_run_task` is the primary dispatch surface. Each call:

1. Creates a sandbox with `pi.openshell/role=sub-agent` plus a
   `pi.openshell/task=<label>` label so you can see what is in flight.
2. Waits for the sandbox to reach `ready` (timeout: 120s).
3. Runs the requested command — either a shell string (`/bin/sh -c`) or an
   explicit argv array.
4. Buffers stdout/stderr (truncated at 64 KiB; full byte counts are
   reported) and returns them along with the exit code.
5. Deletes the sandbox, unless `keep_sandbox: true` was passed.

The controlling Pi agent treats the return value as the sub-agent's
verdict. If the task needs follow-up dispatch, it can pass
`keep_sandbox: true` and then call `openshell_exec` with the returned
`sandbox` name — or pre-create with `openshell_spawn_sandbox` and exec
multiple times against the same name.

## Prerequisites

- Node.js 18 or newer
- A running OpenShell gateway you can reach from the host
- Bearer token for the gateway, either:
  - **OIDC bearer** — what `openshell login` writes after a browser flow
  - **Cloudflare Access token** — what `cloudflared access token` returns

## Install

You need a working `pi` command — install [`@earendil-works/pi-coding-agent`](https://www.npmjs.com/package/@earendil-works/pi-coding-agent) globally if you don't have one:

```shell
npm install -g @earendil-works/pi-coding-agent
pi --version   # should print 0.76 or newer
```

The extension depends on the local `crates/openshell-sdk-node/` build of `@openshell/sdk`. Build the native binary for your platform:

```shell
cd crates/openshell-sdk-node
npx napi build --platform --release
```

Install the extension's dev/runtime dependencies:

```shell
cd ../../examples/pi-extension-sandbox-agents
npm install
```

Register the extension with Pi (writes the path into `~/.pi/agent/settings.json` under `packages`):

```shell
pi install "$(pwd)"
pi list                 # confirm it shows up
```

If a Pi session is already running, type `/reload` to pick up the new extension.

## Configure

The extension reads its gateway connection from the environment at the
first tool call. Set these in the shell that launches Pi:

```shell
export OPENSHELL_GATEWAY="https://gw.example.com"

# Pick one (omit both against a dev gateway with auth disabled):
export OPENSHELL_OIDC_TOKEN="$(cat ~/.openshell/token)"
# or
export OPENSHELL_EDGE_TOKEN="$(cloudflared access token --app https://gw.example.com)"

# Optional:
export OPENSHELL_CA_CERT=/path/to/ca.pem
export OPENSHELL_DEFAULT_IMAGE=openshell/base:latest
# export OPENSHELL_INSECURE=1   # dev only — skip TLS verify
```

When pointed at a local Skaffold deploy (`mise run helm:k3s:create` +
`mise run helm:skaffold:run` with `allowUnauthenticatedUsers: true`),
the token vars can be left unset and the extension connects without
credentials.

## Try it

Start Pi. Then prompt the controlling agent — something the agent can
reasonably answer only by running code on a clean host:

> Use openshell_run_task to determine what version of `node` ships in the
> default image, and report it back.

A useful chain that exercises multiple tools:

> Spawn a sub-agent named `bench`, run `lscpu` and `free -h` inside it,
> summarise the host shape, then destroy it.

A fan-out pattern:

> Run `openshell_run_task` three times in parallel: each task should
> `curl` a different upstream and report its HTTP status. Then list any
> sandboxes still alive afterward.

## Troubleshooting

- **`OPENSHELL_GATEWAY is not set`** — the extension throws on the first
  tool call when required env vars are missing. Set the env vars in the
  shell that started Pi, then `/reload`.
- **`[connect] ...` errors** — the SDK couldn't reach the gateway. Try
  `/openshell-health`; if that also fails, confirm `curl` from the same
  shell reaches `$OPENSHELL_GATEWAY`.
- **`[auth] ...` errors** — the bearer token was rejected. Refresh it
  (`openshell login` or `cloudflared access token`) and `/reload`.
- **Native module load errors** — the SDK ships a per-platform `.node`
  binary built by `napi build`. Re-run `npx napi build --platform
  --release` inside `crates/openshell-sdk-node` for your current OS/arch.

## Files

- `extension.ts` — the Pi extension. Registers tools, holds a single
  cached `OpenShellClient`, and wires JS-shaped inputs through to the
  SDK.
- `package.json` — declares `@openshell/sdk` as a path dependency on the
  local napi crate.
- `tsconfig.json` — strict TS, ES2022, node types. Used by `npm run
  typecheck` for editor / CI feedback. Pi itself runs the `.ts` file
  directly; no build step is needed for runtime.
