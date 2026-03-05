<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Installation

## Prerequisites

- **Docker** — must be installed and running. This is the only runtime dependency.
- **Python 3.12+** — required for `pip install`.

## Install the CLI

```console
$ pip install nemoclaw
```

This installs the `nemoclaw` command (also available as `ncl`).

### Verify the Installation

```console
$ nemoclaw --help
```

You should see the top-level help with command groups: `cluster`, `sandbox`, `provider`, `inference`, and `gator`.

## Shell Completions

Generate shell completions for tab-completion support:

```console
$ nemoclaw completions bash >> ~/.bashrc
$ nemoclaw completions zsh >> ~/.zshrc
$ nemoclaw completions fish >> ~/.config/fish/completions/nemoclaw.fish
```

## For Contributors

If you are developing NemoClaw itself, see the [Contributing Guide](https://github.com/NVIDIA/NemoClaw/blob/main/CONTRIBUTING.md) for building from source using `mise`.

The contributor workflow uses a local shortcut script at `scripts/bin/nemoclaw` that automatically builds the CLI from source. With `mise` active, you can run `nemoclaw` directly from the repository.

```console
$ mise trust
$ mise run sandbox
```
