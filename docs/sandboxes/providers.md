<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Providers

AI agents typically need credentials to access external services — an API key for the AI model provider, a token for GitHub or GitLab, and so on. NemoClaw manages these credentials as first-class entities called *providers*.

Create and manage providers that supply credentials to sandboxes.

## Create a Provider

### From Local Credentials

The fastest way to create a provider is to let the CLI discover credentials from
your shell environment:

```console
$ nemoclaw provider create --name my-claude --type claude --from-existing
```

This reads `ANTHROPIC_API_KEY` or `CLAUDE_API_KEY` from your current environment
and stores them in the provider.

### With Explicit Credentials

Supply a credential value directly:

```console
$ nemoclaw provider create --name my-api --type generic --credential API_KEY=sk-abc123
```

### Bare Key Form

Pass a key name without a value to read the value from the environment variable
of that name:

```console
$ nemoclaw provider create --name my-api --type generic --credential API_KEY
```

This looks up the current value of `$API_KEY` in your shell and stores it.

## Manage Providers

List all providers:

```console
$ nemoclaw provider list
```

Inspect a provider:

```console
$ nemoclaw provider get my-claude
```

Update a provider's credentials:

```console
$ nemoclaw provider update my-claude --type claude --from-existing
```

Delete a provider:

```console
$ nemoclaw provider delete my-claude
```

## Attach Providers to Sandboxes

Pass one or more `--provider` flags when creating a sandbox:

```console
$ nemoclaw sandbox create --provider my-claude --provider my-github -- claude
```

Each `--provider` flag attaches one provider. The sandbox receives all
credentials from every attached provider at runtime.

:::{warning}
Providers cannot be added to a running sandbox. If you need to attach an
additional provider, delete the sandbox and recreate it with all required
providers specified.
:::

### Auto-Discovery Shortcut

When the trailing command in `nemoclaw sandbox create` is a recognized tool name
--- `claude`, `codex`, or `opencode` --- the CLI auto-creates the required
provider from your local credentials if one does not already exist. You do not
need to create the provider separately:

```console
$ nemoclaw sandbox create -- claude
```

This detects `claude` as a known tool, finds your `ANTHROPIC_API_KEY`, creates
a provider, attaches it to the sandbox, and launches Claude Code.

## How Credentials Flow

Credentials follow a secure path from your machine into the agent process.

```{mermaid}
flowchart LR
    A["You create a provider"] --> B["Attach provider\nto sandbox at creation"]
    B --> C["Sandbox starts"]
    C --> D["Supervisor fetches\ncredentials from gateway"]
    D --> E["Credentials injected into\nagent process + SSH sessions"]
```

1. **You create a provider** with credentials from your environment or
   specified explicitly.
2. **You attach the provider to a sandbox** at creation time using the
   `--provider` flag (one or more providers can be attached).
3. **The sandbox starts.** The supervisor process initializes.
4. **The supervisor fetches credentials** from the NemoClaw gateway at runtime.
   Credentials are not stored in the sandbox specification --- they are
   retrieved on demand.
5. **Credentials are injected** into the agent process as environment variables.
   They are also available in SSH sessions when you connect to the sandbox.

:::{warning}
Credentials are never stored in the sandbox container specification. They are
fetched at runtime by the supervisor and held only in process memory. This
means credentials are not visible in container inspection, image layers, or
environment dumps of the container spec.
:::

## Supported Provider Types

For a list of supported provider types, refer to the [Support Matrix](../about/support-matrix.md#supported-provider-types).

## Next Steps

- {doc}`create-and-manage` --- full sandbox lifecycle management
- {doc}`custom-containers` --- use providers with custom container images
- {doc}`../safety-and-privacy/security-model` --- why credential isolation matters