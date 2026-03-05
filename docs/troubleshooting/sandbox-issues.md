<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Sandbox Issues

Troubleshoot problems with creating, connecting to, and configuring sandboxes.

## Sandbox Stuck in Provisioning

**Symptom:** Sandbox shows `Provisioning` status and does not become `Ready`.

**Check:**
1. View sandbox logs: `nemoclaw sandbox logs <name> --source gateway`.
2. Check if the container image can be pulled.
3. For custom images, verify the image was pushed: `nemoclaw sandbox image push`.

## Cannot Connect to Sandbox

**Symptom:** `nemoclaw sandbox connect <name>` fails.

**Check:**
1. Is the sandbox in `Ready` state? `nemoclaw sandbox get <name>`.
2. Is SSH accessible? The tunnel goes through the gateway — verify cluster connectivity first.

## Network Requests Denied

**Symptom:** The agent cannot reach a remote host.

**Check:**
1. Stream sandbox logs: `nemoclaw sandbox logs <name> --tail --source sandbox`.
2. Look for `deny` actions — they include the destination, binary, and reason.
3. Update the policy to allow the blocked endpoint. See [Policy Iteration Loop](../safety-and-privacy/policies.md#the-policy-iteration-loop).

## Policy Update Fails

**Symptom:** `nemoclaw sandbox policy set` returns an error or the status shows `failed`.

**Check:**
1. Are you changing a static field? `filesystem_policy`, `landlock`, and `process` cannot change after creation.
2. Are you adding/removing `network_policies` to change the network mode? This is not allowed — the mode is fixed at creation.
3. Check the error message in `nemoclaw sandbox policy list <name>`.
