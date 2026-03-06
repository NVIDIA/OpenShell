<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Use this guide to troubleshoot problems with NemoClaw.

## Cluster Issues

Troubleshoot problems with deploying, connecting to, and running NemoClaw clusters.

### Cluster Deploy Fails

**Symptom:** `nemoclaw cluster admin deploy` exits with an error.

**Check:**
1. Is Docker running? The cluster requires Docker to be active.
2. Is the port already in use? Try a different port: `--port 8081`.
3. Does a stale container exist? Destroy and redeploy: `nemoclaw cluster admin destroy && nemoclaw cluster admin deploy`.

### Cluster Not Reachable

**Symptom:** `nemoclaw cluster status` fails to connect.

**Check:**
1. Is the cluster container running? `docker ps | grep nemoclaw`.
2. Was the cluster stopped? Redeploy: `nemoclaw cluster admin deploy`.
3. For remote clusters, is the SSH connection working?

### Health Check Fails During Deploy

**Symptom:** Deploy hangs or times out waiting for health checks.

**Check:**
1. View container logs: `docker logs nemoclaw-cluster`.
2. Check if k3s started: the bootstrap process waits up to 180 attempts (six minutes) for cluster readiness.
3. Look for resource constraints. k3s needs sufficient memory and disk.

## Sandbox Issues

Troubleshoot problems with creating, connecting to, and configuring sandboxes.

### Sandbox Stuck in Provisioning

**Symptom:** Sandbox shows `Provisioning` status and does not become `Ready`.

**Check:**
1. View sandbox logs: `nemoclaw sandbox logs <name> --source gateway`.
2. Check if the container image can be pulled.
3. For custom images, verify the image was pushed: `nemoclaw sandbox image push`.

### Cannot Connect to Sandbox

**Symptom:** `nemoclaw sandbox connect <name>` fails.

**Check:**
1. Is the sandbox in `Ready` state? `nemoclaw sandbox get <name>`.
2. Is SSH accessible? The tunnel goes through the gateway. Verify cluster connectivity first.

### Network Requests Denied

**Symptom:** The agent cannot reach a remote host.

**Check:**
1. Stream sandbox logs: `nemoclaw sandbox logs <name> --tail --source sandbox`.
2. Look for `deny` actions. They include the destination, binary, and reason.
3. Update the policy to allow the blocked endpoint. Refer to [Policy Iteration Loop](safety-and-privacy/policies.md#the-policy-iteration-loop).

### Policy Update Fails

**Symptom:** `nemoclaw sandbox policy set` returns an error or the status shows `failed`.

**Check:**
1. Are you changing a static field? `filesystem_policy`, `landlock`, and `process` cannot change after creation.
2. Are you adding/removing `network_policies` to change the network mode? This is not allowed. The mode is fixed at creation.
3. Check the error message in `nemoclaw sandbox policy list <name>`.

## Provider Issues

Troubleshoot problems with provider credential discovery and injection into sandboxes.

### Provider Discovery Finds No Credentials

**Symptom:** `--from-existing` creates a provider with no credentials.

**Check:**
1. Are the expected environment variables set? (for example, `ANTHROPIC_API_KEY` for Claude).
2. Do the expected config files exist? (for example, `~/.claude.json`).
3. Try explicit credentials: `--credential ANTHROPIC_API_KEY=sk-...`.

### Sandbox Missing Credentials

**Symptom:** Environment variables for a provider are not set inside the sandbox.

**Check:**
1. Was the provider attached? `nemoclaw sandbox get <name>`. Check the providers list.
2. Does the provider have credentials? `nemoclaw provider get <name>`.
3. Are the credential keys valid env var names? Keys with dots, dashes, or spaces are silently skipped.

## Custom Container Issues

Troubleshoot problems with building and running custom container images in sandboxes.

### Custom Image Fails to Start

**Symptom:** Sandbox with `--from <image>` goes to `Error` state.

**Check:**
1. Is the image pushed to the cluster? `nemoclaw sandbox image push --dockerfile ./Dockerfile --tag my-image`.
2. Does the image have glibc and `/proc`? Distroless / `FROM scratch` images are not supported.
3. For proxy mode, does the image have `iproute2`? Network namespace setup requires it.

## Port Forwarding Issues

Troubleshoot problems with forwarding local ports into sandbox services.

### Port Forward Not Working

**Symptom:** `localhost:<port>` does not connect to the sandbox service.

**Check:**
1. Is the forward running? `nemoclaw sandbox forward list`.
2. Is the service listening on that port inside the sandbox?
3. Is the sandbox still in `Ready` state?
4. Try stopping and restarting: `nemoclaw sandbox forward stop <port> <name> && nemoclaw sandbox forward start <port> <name> -d`.

## Getting More Information

Use these techniques to gather additional diagnostic detail when troubleshooting.

- Increase CLI verbosity: `nemoclaw -vvv <command>` for trace-level output.
- View gateway-side logs: `nemoclaw sandbox logs <name> --source gateway`.
- View sandbox-side logs: `nemoclaw sandbox logs <name> --source sandbox --level debug`.
