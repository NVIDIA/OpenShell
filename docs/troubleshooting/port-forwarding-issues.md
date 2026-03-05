<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Port Forwarding Issues

Troubleshoot problems with forwarding local ports into sandbox services.

## Port Forward Not Working

**Symptom:** `localhost:<port>` does not connect to the sandbox service.

**Check:**
1. Is the forward running? `nemoclaw sandbox forward list`.
2. Is the service listening on that port inside the sandbox?
3. Is the sandbox still in `Ready` state?
4. Try stopping and restarting: `nemoclaw sandbox forward stop <port> <name> && nemoclaw sandbox forward start <port> <name> -d`.
