<!--
  SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
  SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Use this guide to troubleshoot problems with OpenShell.

## Cluster Issues

Troubleshoot problems with deploying, connecting to, and running OpenShell clusters.

### Cluster Deploy Fails

**Symptom:** `openshell gateway start` exits with an error.

**Check:**
1. Is Docker running? The cluster requires Docker to be active.
2. Is the port already in use? Try a different port: `--port 8081`.
3. Does a stale container exist? Destroy and redeploy: `openshell gateway destroy && openshell gateway start`.

### Cluster Not Reachable

**Symptom:** `openshell status` fails to connect.

**Check:**
1. Is the cluster container running? `docker ps | grep openshell`.
2. Was the cluster stopped? Redeploy: `openshell gateway start`.
3. For remote clusters, is the SSH connection working?

### Health Check Fails During Deploy

**Symptom:** Deploy hangs or times out waiting for health checks.

**Check:**
1. View container logs: `docker logs openshell-cluster`.
2. Check if k3s started: the bootstrap process waits up to 180 attempts (six minutes) for cluster readiness.
3. Look for resource constraints. k3s needs sufficient memory and disk.

## Sandbox Issues

Troubleshoot problems with creating, connecting to, and configuring sandboxes.

### Sandbox Stuck in Provisioning

**Symptom:** Sandbox shows `Provisioning` status and does not become `Ready`.

**Check:**
1. View sandbox logs: `openshell logs <name> --source gateway`.
2. Check if the container image can be pulled.
3. For custom images, verify the image was pushed: `openshell sandbox image push`.

### Cannot Connect to Sandbox

**Symptom:** `openshell sandbox connect <name>` fails.

**Check:**
1. Is the sandbox in `Ready` state? `openshell sandbox get <name>`.
2. Is SSH accessible? The tunnel goes through the gateway. Verify cluster connectivity first.

### Network Requests Denied

**Symptom:** The agent cannot reach a remote host.

**Check:**
1. Stream sandbox logs: `openshell logs <name> --tail --source sandbox`.
2. Look for `deny` actions. They include the destination, binary, and reason.
3. Update the policy to allow the blocked endpoint. Refer to [](safety-and-privacy/policies.md).

### Policy Update Fails

**Symptom:** `openshell policy set` returns an error or the status shows `failed`.

**Check:**
1. Are you changing a static field? `filesystem_policy`, `landlock`, and `process` cannot change after creation.
2. Are you adding/removing `network_policies` to change the network mode? This is not allowed. The mode is fixed at creation.
3. Check the error message in `openshell policy list <name>`.

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
1. Was the provider attached? `openshell sandbox get <name>`. Check the providers list.
2. Does the provider have credentials? `openshell provider get <name>`.
3. Are the credential keys valid env var names? Keys with dots, dashes, or spaces are silently skipped.

## Custom Container Issues

Troubleshoot problems with building and running custom container images in sandboxes.

### Custom Image Fails to Start

**Symptom:** Sandbox with `--from <image>` goes to `Error` state.

**Check:**
1. Is the image pushed to the cluster? `openshell sandbox image push --dockerfile ./Dockerfile --tag my-image`.
2. Does the image have glibc and `/proc`? Distroless / `FROM scratch` images are not supported.
3. For proxy mode, does the image have `iproute2`? Network namespace setup requires it.

## Port Forwarding Issues

Troubleshoot problems with forwarding local ports into sandbox services.

### Port Forward Not Working

**Symptom:** `localhost:<port>` does not connect to the sandbox service.

**Check:**
1. Is the forward running? `openshell forward list`.
2. Is the service listening on that port inside the sandbox?
3. Is the sandbox still in `Ready` state?
4. Try stopping and restarting: `openshell forward stop <port> <name> && openshell forward start <port> <name> -d`.

## Getting More Information

Use these techniques to gather additional diagnostic detail when troubleshooting.

- Increase CLI verbosity: `openshell -vvv <command>` for trace-level output.
- View gateway-side logs: `openshell logs <name> --source gateway`.
- View sandbox-side logs: `openshell logs <name> --source sandbox --level debug`.
