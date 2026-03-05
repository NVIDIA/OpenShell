<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Provider Issues

Troubleshoot problems with provider credential discovery and injection into sandboxes.

## Provider Discovery Finds No Credentials

**Symptom:** `--from-existing` creates a provider with no credentials.

**Check:**
1. Are the expected environment variables set? (e.g., `ANTHROPIC_API_KEY` for Claude).
2. Do the expected config files exist? (e.g., `~/.claude.json`).
3. Try explicit credentials: `--credential ANTHROPIC_API_KEY=sk-...`.

## Sandbox Missing Credentials

**Symptom:** Environment variables for a provider are not set inside the sandbox.

**Check:**
1. Was the provider attached? `nemoclaw sandbox get <name>` — check the providers list.
2. Does the provider have credentials? `nemoclaw provider get <name>`.
3. Are the credential keys valid env var names? Keys with dots, dashes, or spaces are silently skipped.
