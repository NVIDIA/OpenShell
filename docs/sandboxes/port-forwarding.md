<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Port Forwarding

Port forwarding lets you access services running inside a sandbox from your local machine. It uses SSH tunneling through the gateway — sandbox pods are never directly accessible from outside the cluster.

## Starting a Port Forward

### Foreground (blocks until interrupted)

```console
$ nemoclaw sandbox forward start 8080 my-sandbox
```

### Background (returns immediately)

```console
$ nemoclaw sandbox forward start 8080 my-sandbox -d
```

The service is now reachable at `localhost:8080`.

## Managing Port Forwards

### List Active Forwards

```console
$ nemoclaw sandbox forward list
```

Shows all active port forwards with sandbox name, port, PID, and status.

### Stop a Forward

```console
$ nemoclaw sandbox forward stop 8080 my-sandbox
```

## Port Forward at Create Time

You can start a port forward when creating a sandbox:

```console
$ nemoclaw sandbox create --image my-app:latest --forward 8080 --keep -- ./start-server.sh
```

The `--forward` flag implies `--keep` (the sandbox stays alive after the command exits) and starts the forward before the command runs.

## How It Works

Port forwarding uses OpenSSH's `-L` flag (`-L <port>:127.0.0.1:<port>`) through the same `ProxyCommand`-based tunnel used by `sandbox connect`. Connections to `127.0.0.1:<port>` on your local machine are forwarded to `127.0.0.1:<port>` inside the sandbox.

Background forwards are tracked via PID files in `~/.config/nemoclaw/forwards/`. Deleting a sandbox automatically stops any active forwards for that sandbox.

## Gator TUI

The Gator TUI also supports port forwarding. When creating a sandbox in Gator, specify ports in the **Ports** field (comma-separated, e.g., `8080,3000`). Forwarded ports appear in the sandbox table's **NOTES** column.
