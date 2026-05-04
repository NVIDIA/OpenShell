# Providers

## Overview

OpenShell uses a first-class `Provider` entity to represent external tool credentials and
configuration (for example `claude`, `gitlab`, `github`, `outlook`, `generic`, `nvidia`).

Providers exist as an abstraction layer for configuring tools that rely on third-party
access. Rather than each tool managing its own credentials and service configuration,
providers centralize that concern: a user configures a provider once, and any sandbox that
needs that external service can reference it.

At sandbox creation time, providers are validated and associated with the sandbox. The
sandbox supervisor then fetches credentials at runtime, keeps the real secret values in
supervisor-only memory, and injects placeholder environment variables into every child
process it spawns. When outbound traffic is allowed through the sandbox proxy, the
supervisor rewrites those placeholders back to the real secret values before forwarding.
Access is enforced through the sandbox policy — the policy decides which outbound
requests are allowed or denied based on the providers attached to that sandbox.

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

The gRPC surface is defined in `proto/openshell.proto`:

- `CreateProvider`
- `GetProvider`
- `ListProviders`
- `ListProviderProfiles`
- `GetProviderProfile`
- `UpdateProvider`
- `DeleteProvider`

## Provider Type Profiles

Provider type profiles are declarative metadata for provider types. Built-in profiles
live as one YAML document per provider under the top-level `providers/` directory
and are exposed through
`ListProviderProfiles` and `GetProviderProfile`. The profile loader validates the
YAML catalog and materializes the same proto-backed shape that future API imports
will accept. Profiles describe credential names and environment variables, known
network endpoints, expected binaries, category, and whether the provider is
inference-capable. Categories are a proto enum so clients can group and filter
provider types without parsing display strings. Current values are `other`,
`inference`, `agent`, `source_control`, `messaging`, `data`, and `knowledge`.
Agent profiles such as `claude`, `codex`, and `opencode` can still be
inference-capable when their tool talks to an inference API.

Profiles are additive to provider records. A provider record with only `type`,
`credentials`, and `config` can be matched to built-in profile metadata by
`provider.type`. Profile-generated policy is still opt-in: the gateway composes provider
profile rules only when the gateway-global `providers_v2_enabled` setting is true.

This keeps the compatibility boundary at the gateway. A gateway without
`providers_v2_enabled=true` keeps the existing credential-only provider behavior, while a
gateway with the flag enabled routes all attached known provider types through the
profile-backed policy path.

### Provider Policy Composition

Sandbox policy fetch uses just-in-time composition:

```text
effective policy = base/static policy + provider profile rules + user rules
```

The composed policy is derived data. The sandbox still receives one normal
`SandboxPolicy`, but provider-generated entries are not persisted as user-authored
policy revisions. Full policy replacement and incremental policy updates continue to
mutate the user-authored policy layer. Provider-generated rules are re-added during
composition for each attached provider whose type has a built-in profile.

Provider-generated network rules use reserved `_provider_*` names derived from the
provider record name. If a user or global policy already has the same key, composition
keeps the policy entry and adds a numeric suffix to the provider entry. Duplicate
host/port endpoints across policy and provider rules are valid; OPA evaluates all
rules, so allow decisions are the union of matching allows and deny rules continue to
win globally.

Gateway-global policy still overrides sandbox-authored policy. When `providers_v2_enabled`
is true, provider layers compose JIT onto the effective policy source, whether that
source is sandbox-scoped or global. The composed payload is derived data and is not
persisted as a policy revision.

## Components

- `crates/openshell-providers`
  - canonical provider type normalization and command detection,
  - YAML-backed built-in provider profiles,
  - provider registry and per-provider discovery plugins,
  - shared discovery engine and context abstraction for testability.
- `crates/openshell-cli`
  - `openshell provider ...` command handlers,
  - sandbox provider requirement resolution in `sandbox create`.
- `crates/openshell-server` (gateway)
  - provider CRUD gRPC handlers,
  - `GetSandboxProviderEnvironment` handler resolves credentials at runtime,
  - persistence using `object_type = "provider"`.
- `crates/openshell-sandbox`
  - sandbox supervisor fetches provider credentials via gRPC at startup,
  - injects placeholder env vars into entrypoint and SSH child processes,
  - resolves placeholders back to real secrets in the outbound proxy path.

## Provider Plugins

Each provider has its own module under `crates/openshell-providers/src/providers/`.

### Trait Definition

`ProviderPlugin` (`crates/openshell-providers/src/lib.rs`):

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

`openshell provider create --type <type> --name <name> [--from-existing] [--credential k=v]... [--config k=v]...`

- `--credential` supports `KEY=VALUE` and `KEY` forms.
  - `KEY=VALUE` sets an explicit credential value.
  - `KEY` reads from the local environment variable with the same key, and fails when
    the local value is missing or empty.
- `--from-existing` and `--credential` are mutually exclusive.
- `--from-existing` merges discovered laptop data into explicit `--config` args.

Also supported:

- `openshell provider get <name>`
- `openshell provider list`
- `openshell provider list-profiles`
- `openshell provider update <name> ...`
- `openshell provider delete <name> [<name>...]`

### Sandbox Create

`openshell sandbox create --provider gitlab -- claude`

Resolution logic (CLI side, `crates/openshell-cli/src/run.rs`):

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

Gateway-side `create_sandbox()` (`crates/openshell-server/src/grpc.rs`):

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

`resolve_provider_environment()` (`crates/openshell-server/src/grpc.rs`) builds the
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
- Provider profiles do not change credential injection in the first iteration.
  Injection still uses the existing placeholder environment path.

### Sandbox Supervisor: Fetching Credentials

The sandbox pod runs `openshell-sandbox` (`crates/openshell-sandbox/src/main.rs`). On
startup it receives `OPENSHELL_SANDBOX_ID` and `OPENSHELL_ENDPOINT` as environment
variables (injected into the pod spec by the gateway's Kubernetes sandbox creation code).

In `run_sandbox()` (`crates/openshell-sandbox/src/lib.rs`):

1. loads the sandbox policy via gRPC (`GetSandboxSettings`),
2. fetches provider credentials via gRPC (`GetSandboxProviderEnvironment`),
3. if the fetch fails, continues with an empty map (graceful degradation with a warning).

The returned `provider_env` `HashMap<String, String>` is immediately transformed into:

- a child-visible env map with placeholder values such as
  `openshell:resolve:env:ANTHROPIC_API_KEY`, and
- a supervisor-only in-memory registry mapping each placeholder back to its real secret.

The placeholder env map is threaded to the entrypoint process spawner and SSH server.
The registry is threaded to the proxy so it can rewrite outbound headers.

### Child Process Environment Variable Injection

Provider placeholders are injected into child processes in two places, covering all
process spawning paths inside the sandbox:

**1. Entrypoint process** (`crates/openshell-sandbox/src/process.rs`):

```rust
let mut cmd = Command::new(program);
cmd.args(args)
    .env("OPENSHELL_SANDBOX", "1");

// Set provider environment variables (supervisor-managed placeholders).
for (key, value) in provider_env {
    cmd.env(key, value);
}
```

This uses `tokio::process::Command`. The `.env()` call adds each variable to the child's
inherited environment without clearing it. The spawn path also explicitly removes
`OPENSHELL_SSH_HANDSHAKE_SECRET` so the handshake secret does not leak into the agent
entrypoint process.

After provider env vars, proxy env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
`NO_PROXY=127.0.0.1,localhost,::1`, lowercase variants, etc.) are also set when
`NetworkMode` is `Proxy`. The child is then launched with namespace
isolation, privilege dropping, seccomp, and Landlock restrictions via `pre_exec`.

**2. SSH shell sessions** (`crates/openshell-sandbox/src/ssh.rs`):

When a user connects via `openshell sandbox connect`, a PTY shell is spawned:

```rust
let mut cmd = Command::new(shell);
cmd.env("OPENSHELL_SANDBOX", "1")
    .env("HOME", "/sandbox")
    .env("USER", "sandbox")
    .env("TERM", term);

// Set provider environment variables (supervisor-managed placeholders).
for (key, value) in provider_env {
    cmd.env(key, value);
}
```

This uses `std::process::Command`. The `SshHandler` holds the `provider_env` map and
passes it to `spawn_pty_shell()` for each new shell or exec request. SSH child processes
start from `env_clear()`, so the handshake secret is not present there.

### Proxy-Time Secret Resolution

When a sandboxed tool uses one of these placeholder env vars in an outbound HTTP request,
the sandbox proxy rewrites the placeholder to the real secret value immediately before the
request is forwarded upstream. Placeholders are resolved in four locations:

- **HTTP header values** — exact match (`x-api-key: openshell:resolve:env:KEY`), prefixed
  match (`Authorization: Bearer openshell:resolve:env:KEY`), and Base64-decoded Basic auth
  tokens (`Authorization: Basic <base64(user:openshell:resolve:env:PASS)>`)
- **URL query parameters** — for APIs that authenticate via query string
  (e.g., `?key=openshell:resolve:env:YOUTUBE_API_KEY`)
- **URL path segments** — for APIs that embed tokens in the URL path
  (e.g., `/bot<placeholder>/sendMessage` for Telegram Bot API)

This applies to forward-proxy HTTP requests, L7-inspected REST requests inside CONNECT
tunnels, and credential-injection-only passthrough relays on TLS-terminated connections.

All rewriting fails closed: if any `openshell:resolve:env:*` placeholder is detected but
cannot be resolved, the proxy rejects the request with HTTP 500 instead of forwarding the
raw placeholder upstream. Resolved secret values are validated for prohibited control
characters (CR, LF, null byte) to prevent header injection (CWE-113). Path segment
credentials are additionally validated to reject traversal sequences, path separators, and
URI delimiters (CWE-22).

The real secret value remains in supervisor memory only; it is not re-injected into the
child process environment. See [Credential injection](sandbox.md#credential-injection) for
the full implementation details, encoding rules, and security properties.

### End-to-End Flow

```text
CLI: openshell sandbox create -- claude
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
                K8s: pod starts openshell-sandbox binary
                  +-- OPENSHELL_SANDBOX_ID and OPENSHELL_ENDPOINT set in pod env
                  |
                    Sandbox supervisor: run_sandbox()
                      +-- Fetches policy via gRPC
                      +-- Fetches provider env via gRPC
                      |     +-- Gateway resolves: "claude" -> credentials -> {ANTHROPIC_API_KEY: "sk-..."}
                      +-- Builds placeholder registry
                      |     +-- child env: {ANTHROPIC_API_KEY: "openshell:resolve:env:ANTHROPIC_API_KEY"}
                      |     +-- supervisor registry: {"openshell:resolve:env:ANTHROPIC_API_KEY": "sk-..."}
                      +-- Spawns entrypoint with placeholder env
                      +-- SSH server holds placeholder env
                      |     +-- Each SSH shell: cmd.env("ANTHROPIC_API_KEY", "openshell:resolve:env:ANTHROPIC_API_KEY")
                      +-- Proxy rewrites outbound auth header placeholders -> real secrets
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
- Child processes never receive the raw provider secret values; they only receive
  placeholders, and the supervisor resolves those placeholders during outbound proxying.
- `OPENSHELL_SSH_HANDSHAKE_SECRET` is required by the supervisor/SSH server path but is
  explicitly kept out of spawned sandbox child-process environments.

## Test Strategy

- Per-provider unit tests in each provider module.
- Shared normalization/command-detection tests in `crates/openshell-providers/src/lib.rs`.
- Mocked discovery context tests cover env and path-based behavior.
- CLI and gateway integration tests validate end-to-end RPC compatibility.
- `resolve_provider_environment` unit tests in `crates/openshell-server/src/grpc.rs`.
- sandbox unit tests validate placeholder generation and header rewriting.
- E2E sandbox tests verify placeholders are visible in child env, outbound proxy traffic
  is rewritten with the real secret, and the SSH handshake secret is absent from exec env.
