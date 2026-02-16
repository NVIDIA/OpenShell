# Providers

## Overview

Navigator uses a first-class `Provider` entity to represent external tool credentials and
configuration (for example `claude`, `gitlab`, `github`, `outlook`).

Providers exist as an abstraction layer for configuring tools that rely on third-party
access. Rather than each tool managing its own credentials and service configuration,
providers centralize that concern: a user configures a provider once, and any sandbox that
needs that external service can reference it.

At sandbox creation time, providers configure the sandbox environment with the
credentials and settings the tool needs. Access is then enforced through the sandbox
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
  - `nav provider ...` command handlers,
  - sandbox provider requirement resolution in `sandbox create`.
- `crates/navigator-server`
  - provider CRUD gRPC handlers,
  - persistence using `object_type = "provider"`.

## Provider Plugins

Each provider has its own module under `crates/navigator-providers/src/providers/`.

Current modules:

- `claude.rs`
- `codex.rs`
- `opencode.rs`
- `openclaw.rs`
- `gitlab.rs`
- `github.rs`
- `outlook.rs`

Each plugin defines:

- canonical `id()`,
- discovery spec (env vars + config paths),
- `discover_existing()` behavior.

The registry is assembled in `ProviderRegistry::new()` by registering each provider module.

## Discovery Architecture

Discovery behavior is split into three layers:

1. provider module defines static spec (`ProviderDiscoverySpec`),
2. shared engine (`discover_with_spec`) performs env/file scanning,
3. runtime context (`DiscoveryContext`) supplies filesystem/environment reads.

`DiscoveryContext` has:

- `RealDiscoveryContext` for production runtime,
- `MockDiscoveryContext` test helper for deterministic tests.

This keeps provider tests isolated from host environment and filesystem.

## CLI Flows

### Provider CRUD

`nav provider create --type <type> --name <name> [--from-existing] [--credential k=v]... [--config k=v]...`

- `--from-existing` merges discovered laptop data into explicit CLI key-value args.
- Explicit `--credential` / `--config` values take precedence.

Also supported:

- `nav provider get <name>`
- `nav provider list`
- `nav provider update <name> ...`
- `nav provider delete <name> [<name>...]`

### Sandbox Create

`nav sandbox create --provider gitlab -- claude`

Resolution logic:

1. infer provider from command token after `--` (for example `claude`),
2. union with explicit `--provider <type>` flags,
3. ensure each required provider type exists,
4. if interactive and missing, auto-create from existing local state,
5. set `NAVIGATOR_PROVIDER_TYPES` in sandbox spec environment.

Non-interactive mode fails with a clear missing-provider error.

> **Note:** Providers can also be configured from within the sandbox itself. This allows
> sandbox users to set up or update provider credentials and configuration at runtime,
> without requiring them to be fully resolved before sandbox creation.

## Persistence and Validation

Server enforces:

- `provider.type` must be non-empty,
- name uniqueness for providers,
- generated `id` on create,
- id preservation on update.

Providers are stored with `object_type = "provider"` in the shared object store.

## Security Notes

- Provider credentials are stored in `credentials` map and treated as sensitive.
- CLI output intentionally avoids printing credential values.
- CLI displays only non-sensitive summaries (counts/key names where relevant).

## Test Strategy

- Per-provider unit tests in each provider module.
- Shared normalization/command-detection tests in `crates/navigator-providers/src/lib.rs`.
- Mocked discovery context tests cover env and path-based behavior.
- CLI and server integration tests validate end-to-end RPC compatibility.
