# Providers

## Overview

NemoClaw uses a first-class `Provider` entity to represent external tool credentials and
configuration (for example `claude`, `gitlab`, `github`, `outlook`, `generic`, `nvidia`).

Providers exist as an abstraction layer for configuring tools that rely on third-party
access. Rather than each tool managing its own credentials and service configuration,
providers centralize that concern: a user configures a provider once, and any sandbox that
needs that external service can reference it.

At sandbox creation time, providers are validated and associated with the sandbox. The
sandbox supervisor then fetches credentials at runtime and injects them as environment
variables into every child process it spawns. Access is enforced through the sandbox
policy — the policy decides which outbound requests are allowed or denied based on
the providers attached to that sandbox.

Core goals:

- manage providers directly via CLI,
- discover provider data from the local machine automatically,
- require providers during sandbox creation,
- project provider context into sandbox runtime,
- drive sandbox policy to allow or deny outbound access to third-party services.

## Data Model

Provider is defined in `proto/datamodel.proto`:

- `id`: unique entity id
- `name`: user-managed name
- `type`: canonical provider slug (`claude`, `gitlab`, `github`, etc.)
- `credentials`: `map<string, string>` for secret values
- `config`: `map<string, string>` for non-secret settings

The gRPC surface is defined in `proto/navigator.proto`:

- `CreateProvider`
- `GetProvider`
- `ListProviders`
- `UpdateProvider`
- `DeleteProvider`

## Components

- `crates/navigator-providers`
  - canonical provider type normalization and command detection,
  - provider registry and per-provider discovery plugins,
  - shared discovery engine and context abstraction for testability.
- `crates/navigator-cli`
  - `nemoclaw provider ...` command handlers,
  - sandbox provider requirement resolution in `sandbox create`.
- `crates/navigator-server` (gateway)
  - provider CRUD gRPC handlers,
  - `GetSandboxProviderEnvironment` handler resolves credentials at runtime,
  - persistence using `object_type = "provider"`.
- `crates/navigator-sandbox`
  - sandbox supervisor fetches provider credentials via gRPC at startup,
  - injects credentials as environment variables into entrypoint and SSH child processes.

## Provider Plugins

Each provider has its own module under `crates/navigator-providers/src/providers/`.

### Trait Definition

`ProviderPlugin` (`crates/navigator-providers/src/lib.rs`):

```rust
pub trait ProviderPlugin: Send + Sync {
    fn id(&self) -> &'static str;
    fn discover_existing(&self) -> Result<Option<DiscoveredProvider>, ProviderError>;
    fn apply_to_sandbox(&self, _provider: &Provider) -> Result<(), ProviderError> {
        Ok(())  // default no-op, forward-looking extension point
    }
}
```

`DiscoveredProvider` holds two maps (`credentials` and `config`) returned by discovery.

### Current Modules

| Module | Env Vars Discovered | Config Paths |
|---|---|---|
| `claude.rs` | `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY` | `~/.claude.json`, `~/.claude/credentials.json`, `~/.config/claude/config.json` |
| `codex.rs` | `OPENAI_API_KEY` | `~/.config/codex/config.json`, `~/.codex/config.json`, `~/.config/openai/config.json` |
| `opencode.rs` | `OPENCODE_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY` | `~/.config/opencode/config.json`, `~/.opencode/config.json` |
| `openclaw.rs` | `OPENCLAW_API_KEY`, `OPENAI_API_KEY` | `~/.config/openclaw/config.json`, `~/.openclaw/config.json` |
| `generic.rs` | *(none)* | *(none)* |
| `nvidia.rs` | `NVIDIA_API_KEY` | *(none)* |
| `gitlab.rs` | `GITLAB_TOKEN`, `GLAB_TOKEN`, `CI_JOB_TOKEN` | `~/.config/glab-cli/config.yml` |
| `github.rs` | `GITHUB_TOKEN`, `GH_TOKEN` | `~/.config/gh/hosts.yml` |
| `outlook.rs` | *(none)* | *(none)* |

`generic` and `outlook` are stubs — `discover_existing()` always returns `None`.

Each plugin defines a `ProviderDiscoverySpec` with its `id`, `credential_env_vars`, and
`config_paths`. The registry is assembled in `ProviderRegistry::new()` by registering
each provider module.

### Normalization

`normalize_provider_type()` maps common aliases to canonical slugs: `"glab"` -> `"gitlab"`,
`"gh"` -> `"github"`, and accepts `"generic"` directly as a first-class type.
`detect_provider_from_command()` extracts the file basename from the first command token
and passes it through normalization.

## Discovery Architecture

Discovery behavior is split into three layers:

1. provider module defines static spec (`ProviderDiscoverySpec`),
2. shared engine (`discover_with_spec`) performs env/file scanning,
3. runtime context (`DiscoveryContext`) supplies filesystem/environment reads.

### Discovery Engine

`discover_with_spec(spec, context)` performs two passes:

1. **Environment variable scan**: for each var in `spec.credential_env_vars`, reads from
   the `DiscoveryContext`. Non-empty values are stored in `discovered.credentials`.

2. **Config file scan**: for each path in `spec.config_paths`:
   - expands `~/` via the context,
   - rejects `~/` expansions that contain path-escape components (for example `..`),
   - checks file existence,
   - **only parses `.json` files** (`.yml`/`.yaml` are checked for existence but not read),
   - recursively collects JSON fields whose keys match credential patterns
     (`api_key`, `apikey`, `token`, `secret`, `password`, `auth` — case-insensitive),
   - collected values go into `discovered.credentials` using dotted path keys
     (for example `"oauth.api_key"`).

Config file values always go into `credentials`, not `config`. The `config` map is only
populated via explicit CLI flags.

### Discovery Context

`DiscoveryContext` trait:

```rust
pub trait DiscoveryContext {
    fn env_var(&self, key: &str) -> Option<String>;
    fn expand_home(&self, path: &str) -> Option<PathBuf>;
    fn path_exists(&self, path: &Path) -> bool;
    fn read_to_string(&self, path: &Path) -> Option<String>;
}
```

Implementations:

- `RealDiscoveryContext` for production runtime (reads from `std::env` and filesystem),
- `MockDiscoveryContext` test helper for deterministic tests.

This keeps provider tests isolated from host environment and filesystem.

## CLI Flows

### Provider CRUD

`nemoclaw provider create --type <type> --name <name> [--from-existing] [--credential k=v]... [--config k=v]...`

- `--credential` supports `KEY=VALUE` and `KEY` forms.
  - `KEY=VALUE` sets an explicit credential value.
  - `KEY` reads from the local environment variable with the same key, and fails when
    the local value is missing or empty.
- `--from-existing` and `--credential` are mutually exclusive.
- `--from-existing` merges discovered laptop data into explicit `--config` args.

Also supported:

- `nemoclaw provider get <name>`
- `nemoclaw provider list`
- `nemoclaw provider update <name> ...`
- `nemoclaw provider delete <name> [<name>...]`

### Sandbox Create

`nemoclaw sandbox create --provider gitlab -- claude`

Resolution logic (CLI side, `crates/navigator-cli/src/run.rs`):

1. `detect_provider_from_command()` infers provider from command token after `--`
   (for example `claude`),
2. union with explicit `--provider <type>` flags (normalized),
3. deduplicate,
4. `ensure_required_providers()` checks each required type exists on the gateway,
5. if interactive and missing, auto-create from existing local state
   (uses `ProviderRegistry::discover_existing()`), trying names like `"claude"`,
   `"claude-1"`, etc. up to 5 retries for name conflicts,
6. non-interactive mode fails with a clear missing-provider error,
7. set resolved provider **names** in `SandboxSpec.providers`.

Gateway-side `create_sandbox()` (`crates/navigator-server/src/grpc.rs`):

1. validates all provider names exist by fetching each from the store (fail fast),
2. creates the `Sandbox` object with `spec.providers` set,
3. **does not inject credentials into the pod spec** — credentials are fetched at runtime.

If a requested provider name is not found, sandbox creation fails with a
`FailedPrecondition` error.

> **Note:** Providers can also be configured from within the sandbox itself. This allows
> sandbox users to set up or update provider credentials and configuration at runtime,
> without requiring them to be fully resolved before sandbox creation.

## Sandbox Credential Injection

### Runtime Credential Resolution

`SandboxSpec` includes a `providers` field (`repeated string`) containing provider names.
Credentials are **not** embedded in the pod spec. Instead, the sandbox supervisor fetches
them at runtime via the `GetSandboxProviderEnvironment` gRPC call.

### Gateway-side: `resolve_provider_environment()`

`resolve_provider_environment()` (`crates/navigator-server/src/grpc.rs`) builds the
environment map returned by `GetSandboxProviderEnvironment`:

1. for each provider name in `spec.providers`, fetch the provider from the store,
2. iterate over `provider.credentials` only (not `config`),
3. validate each key matches `^[A-Za-z_][A-Za-z0-9_]*$` (valid env var name),
4. insert into result map using `entry().or_insert()` — first provider's value wins
   when duplicate keys appear across providers,
5. invalid keys are skipped with a warning log.

Key behaviors:

- Only `credentials` are injected, not `config`.
- Invalid env var keys (containing `.`, `-`, spaces, etc.) are skipped.
- Credentials are never persisted in the sandbox spec's environment map.

### Sandbox Supervisor: Fetching Credentials

The sandbox pod runs `navigator-sandbox` (`crates/navigator-sandbox/src/main.rs`). On
startup it receives `NEMOCLAW_SANDBOX_ID` and `NEMOCLAW_ENDPOINT` as environment
variables (injected into the pod spec by the gateway's Kubernetes sandbox creation code).

In `run_sandbox()` (`crates/navigator-sandbox/src/lib.rs`):

1. loads the sandbox policy via gRPC (`GetSandboxPolicy`),
2. fetches provider credentials via gRPC (`GetSandboxProviderEnvironment`),
3. if the fetch fails, continues with an empty map (graceful degradation with a warning).

The returned `provider_env` `HashMap<String, String>` is then threaded to both the
entrypoint process spawner and the SSH server.

### Child Process Environment Variable Injection

Provider credentials are injected into child processes in two places, covering all
process spawning paths inside the sandbox:

**1. Entrypoint process** (`crates/navigator-sandbox/src/process.rs`):

```rust
let mut cmd = Command::new(program);
cmd.args(args)
    .env("NEMOCLAW_SANDBOX", "1");

// Set provider environment variables (credentials fetched at runtime).
for (key, value) in provider_env {
    cmd.env(key, value);
}
```

This uses `tokio::process::Command`. The `.env()` call adds each variable to the child's
inherited environment without clearing it.

After provider env vars, proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, etc.)
are also set when `NetworkMode` is `Proxy`. The child is then launched with namespace
isolation, privilege dropping, seccomp, and Landlock restrictions via `pre_exec`.

**2. SSH shell sessions** (`crates/navigator-sandbox/src/ssh.rs`):

When a user connects via `nemoclaw sandbox connect`, a PTY shell is spawned:

```rust
let mut cmd = Command::new(shell);
cmd.env("NEMOCLAW_SANDBOX", "1")
    .env("HOME", "/sandbox")
    .env("USER", "sandbox")
    .env("TERM", term);

// Set provider environment variables (credentials fetched at runtime).
for (key, value) in provider_env {
    cmd.env(key, value);
}
```

This uses `std::process::Command`. The `SshHandler` holds the `provider_env` map and
passes it to `spawn_pty_shell()` for each new shell or exec request.

### End-to-End Flow

```
CLI: nemoclaw sandbox create -- claude
  |
  +-- detect_provider_from_command(["claude"]) -> "claude"
  +-- ensure_required_providers() -> discovers local ANTHROPIC_API_KEY
  |     +-- Creates provider record "claude" on gateway with credentials
  +-- Sets SandboxSpec.providers = ["claude"]
  +-- Sends CreateSandboxRequest to gateway
        |
        Gateway: create_sandbox()
          +-- Validates provider "claude" exists in store (fail fast)
          +-- Persists Sandbox with spec.providers = ["claude"]
          +-- Creates K8s Sandbox CRD (no credentials in pod spec)
                |
                K8s: pod starts navigator-sandbox binary
                  +-- NEMOCLAW_SANDBOX_ID and NEMOCLAW_ENDPOINT set in pod env
                  |
                  Sandbox supervisor: run_sandbox()
                    +-- Fetches policy via gRPC
                    +-- Fetches provider env via gRPC
                    |     +-- Gateway resolves: "claude" -> credentials -> {ANTHROPIC_API_KEY: "sk-..."}
                    +-- Spawns entrypoint: cmd.env("ANTHROPIC_API_KEY", "sk-...")
                    +-- SSH server holds provider_env
                          +-- Each SSH shell: cmd.env("ANTHROPIC_API_KEY", "sk-...")
```

## Persistence and Validation

The gateway enforces:

- `provider.type` must be non-empty,
- name uniqueness for providers,
- generated `id` on create,
- id preservation on update.

Providers are stored with `object_type = "provider"` in the shared object store.

## Security Notes

- Provider credentials are stored in `credentials` map and treated as sensitive.
- CLI output intentionally avoids printing credential values.
- CLI displays only non-sensitive summaries (counts/key names where relevant).
- Credentials are never persisted in the sandbox spec — they exist only in the
  provider store and are fetched at runtime by the sandbox supervisor.

## Test Strategy

- Per-provider unit tests in each provider module.
- Shared normalization/command-detection tests in `crates/navigator-providers/src/lib.rs`.
- Mocked discovery context tests cover env and path-based behavior.
- CLI and gateway integration tests validate end-to-end RPC compatibility.
- `resolve_provider_environment` unit tests in `crates/navigator-server/src/grpc.rs`.
