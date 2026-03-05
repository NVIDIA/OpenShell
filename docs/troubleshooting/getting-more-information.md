<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Getting More Information

Use these techniques to gather additional diagnostic detail when troubleshooting.

- Increase CLI verbosity: `nemoclaw -vvv <command>` for trace-level output.
- View gateway-side logs: `nemoclaw sandbox logs <name> --source gateway`.
- View sandbox-side logs: `nemoclaw sandbox logs <name> --source sandbox --level debug`.
