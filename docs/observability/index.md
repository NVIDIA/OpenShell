---
title:
  page: Observability
  nav: Observability
description: Understand how OpenShell logs sandbox activity, how to access logs, and how to export structured OCSF records.
topics:
- Generative AI
- Cybersecurity
tags:
- Logging
- OCSF
- Observability
- Monitoring
content:
  type: concept
  difficulty: technical_beginner
  audience:
  - engineer
  - data_scientist
---

<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Observability

OpenShell provides structured logging for every sandbox. Every network connection, process lifecycle event, filesystem policy decision, and configuration change is recorded so you can understand exactly what happened inside a sandbox.

This section covers:

- **[Sandbox Logging](logging.md)** -- How the two log formats work (standard tracing and OCSF structured events), where logs are stored, and how to read them.
- **[Accessing Logs](accessing-logs.md)** -- How to view logs through the CLI, TUI, and directly on the sandbox filesystem.
- **[OCSF JSON Export](ocsf-json-export.md)** -- How to enable full OCSF JSON output for integration with SIEMs, log aggregators, and compliance tools.

```{toctree}
:hidden:

logging
accessing-logs
ocsf-json-export
```
