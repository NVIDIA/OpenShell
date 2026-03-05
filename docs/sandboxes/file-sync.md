<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# File Sync

NemoClaw supports syncing files between your local machine and a running sandbox. File sync uses tar-over-SSH through the gateway tunnel — no direct network access to the sandbox pod is needed.

## Sync at Create Time

The `--sync` flag pushes local git-tracked files into the sandbox at `/sandbox` before the agent starts:

```console
$ nemoclaw sandbox create --sync -- claude
```

This is useful when you want the agent to work with your current project files.

## Manual Sync

### Push Files to a Sandbox

```console
$ nemoclaw sandbox sync my-sandbox --up ./src /sandbox/src
```

This copies local `./src` into `/sandbox/src` inside the sandbox.

### Pull Files from a Sandbox

```console
$ nemoclaw sandbox sync my-sandbox --down /sandbox/output ./local-output
```

This copies `/sandbox/output` from the sandbox to `./local-output` on your machine.

### Default Destinations

- `--up` defaults to `/sandbox` if no destination is specified.
- `--down` defaults to the current directory (`.`).
