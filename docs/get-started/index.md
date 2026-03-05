<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# About Getting Started

NemoClaw is designed for minimal setup with safety and privacy built in from the start. Docker is the only prerequisite.

## Quickstart

**Step 1: Install the CLI.**

```console
$ pip install nemoclaw
```

See [Installation](installation.md) for detailed prerequisites and alternative install methods.

**Step 2: Create a sandbox.**

```console
$ nemoclaw sandbox create -- claude
```

If no cluster exists, the CLI automatically bootstraps one. It provisions a local Kubernetes cluster inside a Docker container, discovers your AI provider credentials from local configuration files, uploads them to the gateway, and launches a sandbox — all from a single command.

**Step 3: Connect to a running sandbox.**

```console
$ nemoclaw sandbox connect <sandbox-name>
```

This opens an interactive SSH session into the sandbox, with all provider credentials available as environment variables.

## What Happens Under the Hood

When you run `nemoclaw sandbox create -- claude`, the CLI:

1. Checks for a running cluster. If none exists, it bootstraps one automatically (a k3s cluster inside a Docker container).
2. Scans your local machine for Claude credentials (`ANTHROPIC_API_KEY`, `~/.claude.json`, etc.) and uploads them to the gateway as a provider.
3. Creates a sandbox pod with the default policy and attaches the discovered provider.
4. Waits for the sandbox to reach `Ready` state.
5. Opens an interactive SSH session into the sandbox.

## Next Steps

- [Installation](installation.md) — detailed prerequisites and install methods.
- [Your First Sandbox](first-sandbox.md) — a step-by-step walkthrough.
- [Sandboxes](../sandboxes/index.md) — full sandbox management guide.
